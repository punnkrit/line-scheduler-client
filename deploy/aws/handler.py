"""Private scheduler backend. Never log requests, message bodies, or credentials."""
import base64
import hmac
import hashlib
import json
import os
import re
import subprocess
import time
import uuid
import unicodedata
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError
from botocore.config import Config

ddb = boto3.resource("dynamodb")
jobs = ddb.Table(os.environ["JOBS_TABLE"])
session_table = ddb.Table(os.environ["SESSION_TABLE"]) if os.environ.get("SESSION_TABLE") else None
scheduler = boto3.client("scheduler")
functions = boto3.client("lambda")
objects = boto3.client("s3", config=Config(signature_version="s3v4", s3={"addressing_style":"virtual"}),
                       endpoint_url="https://s3."+os.environ.get("AWS_REGION","ap-southeast-1")+".amazonaws.com")
MAX_FILE = 20 * 1024 * 1024
ID = re.compile(r"^[a-f0-9]{32}$")
CHAT = re.compile(r"^(?:[uUcCrR][A-Za-z0-9_-]{43}|[ucr][0-9a-f]{32})$")
SAFE_ERROR = "The operation could not be completed. Refresh to check its status."


def conditional(exc):
    return isinstance(exc, ClientError) and exc.response["Error"]["Code"] == "ConditionalCheckFailedException"


def read(table, key):
    return table.get_item(Key={"id": key}, ConsistentRead=True).get("Item")


def all_jobs():
    items = []
    request = {}
    while True:
        result = jobs.scan(**request)
        items.extend(x for x in result["Items"] if ID.fullmatch(x["id"]))
        if not result.get("LastEvaluatedKey"):
            return items
        if len(items) > 5000:
            raise ValueError("History limit reached; archive older jobs before adding more.")
        request["ExclusiveStartKey"] = result["LastEvaluatedKey"]


def response(status, data):
    return {"statusCode": status, "headers": {"Content-Type": "application/json", "Cache-Control": "no-store"},
            "body": json.dumps(data, default=lambda n: int(n))}


def invoke_worker(payload):
    functions.invoke(FunctionName=os.environ["WORKER_NAME"], InvocationType="Event", Payload=json.dumps(payload).encode())


def file_spec(body):
    name, size, digest = body.get("name"), body.get("size"), body.get("sha256")
    if (not isinstance(name, str) or not name or len(name.encode("utf-8")) > 255
            or any(c in "/\\" or unicodedata.category(c) == "Cc" for c in name)
            or type(size) is not int or not 0 <= size <= MAX_FILE
            or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest)):
        raise ValueError("Invalid file")
    return {"name": name, "size": size, "sha256": digest}


def start_upload(body):
    job_id = body.get("id", "")
    if not isinstance(job_id, str) or not ID.fullmatch(job_id):
        raise ValueError("Invalid upload")
    spec = file_spec(body)
    existing = read(jobs, job_id)
    if existing:
        if {k:existing.get("attachment", {}).get(k) for k in spec} != spec:
            return response(409, {"error":"This request ID was already used."})
        return response(200, {"scheduled":True})
    # Metadata is bound to one future job; the browser cannot select arbitrary S3 keys.
    metadata_id = "upload_" + job_id
    previous = read(jobs, metadata_id)
    if previous and any(previous.get(k) != v for k, v in spec.items()):
        return response(409, {"error":"This upload ID was already used."})
    now = int(time.time())
    if not previous:
        jobs.put_item(Item={"id":metadata_id, **spec, "expires_at":now+86400},
                      ConditionExpression="attribute_not_exists(id)")
    elif int(previous["expires_at"]) < now:
        return response(410, {"error":"Upload expired. Remove the file and add it again."})
    tag = "<Tagging><TagSet><Tag><Key>state</Key><Value>staging</Value></Tag></TagSet></Tagging>"
    fields = {"Content-Type":"application/octet-stream", "x-amz-server-side-encryption":"AES256", "tagging":tag}
    upload = objects.generate_presigned_post(
        os.environ["FILES_BUCKET"], "uploads/"+job_id, Fields=fields,
        Conditions=[{k:v} for k,v in fields.items()]+[["content-length-range",spec["size"],spec["size"]]], ExpiresIn=300)
    return response(200, {"upload":upload})


def prepare_attachment(job_id):
    metadata = read(jobs, "upload_"+job_id)
    if not metadata or int(metadata["expires_at"]) < time.time():
        raise ValueError("Upload expired")
    spec = file_spec({**metadata, "size":int(metadata["size"])})
    key = "uploads/"+job_id
    head = objects.head_object(Bucket=os.environ["FILES_BUCKET"],Key=key)
    if head["ContentLength"] != spec["size"] or not head.get("VersionId") or head["VersionId"] == "null":
        raise ValueError("Invalid uploaded file")
    # Pin the immutable version before dispatch. A still-valid upload URL cannot replace it.
    spec.update(key=key, version=head["VersionId"])
    objects.put_object_tagging(Bucket=os.environ["FILES_BUCKET"],Key=key,VersionId=spec["version"],
                               Tagging={"TagSet":[{"Key":"state","Value":"scheduled"}]})
    return spec


def delete_attachment(job):
    attachment = job.get("attachment")
    if attachment:
        try:
            objects.delete_object(Bucket=os.environ["FILES_BUCKET"],Key=attachment["key"],VersionId=attachment["version"])
        except Exception:
            pass  # Lifecycle is the fallback; never alter the delivery result for cleanup.


def load_attachment(attachment):
    spec = file_spec({**attachment, "size":int(attachment["size"])})
    obj = objects.get_object(Bucket=os.environ["FILES_BUCKET"],Key=attachment["key"],VersionId=attachment["version"])
    try:
        content = obj["Body"].read(MAX_FILE+1)
    finally:
        obj["Body"].close()
    if len(content) != spec["size"] or not hmac.compare_digest(hashlib.sha256(content).hexdigest(), spec["sha256"]):
        raise ValueError("File integrity check failed")
    return {"file_name":spec["name"], "file_data":base64.b64encode(content).decode("ascii")}


def controller(event, context):
    headers = {k.lower(): v for k, v in event.get("headers", {}).items()}
    expected = "Bearer " + os.environ["BRIDGE_TOKEN"]
    if not hmac.compare_digest(headers.get("authorization", ""), expected):
        return response(401, {"error": "Unauthorized"})
    try:
        if len(event.get("body") or "") > 100000:
            return response(413, {"error": "Request too large"})
        if event.get("isBase64Encoded"):
            return response(400, {"error": "JSON required"})
        method = event.get("requestContext", {}).get("http", {}).get("method")
        if method == "GET":
            meta = read(jobs, "meta") or {}
            records = sorted(all_jobs(), key=lambda j: j["created_at"], reverse=True)
            for job in records:
                if job["status"] == "sending" and int(job.get("started_at", 0)) < time.time() - 180:
                    job["status"] = "unknown"
                    job["error"] = "Delivery could not be confirmed. Check LINE before sending again."
            return response(200, {"connected": meta.get("connected", False), "chats": meta.get("chats", []),
                                  "refreshed_at": meta.get("refreshed_at"), "connection_error": meta.get("error"),
                                  "jobs": records[:200], "server_time": int(time.time())})
        if method != "POST":
            return response(405, {"error": "Method not allowed"})
        body = json.loads(event.get("body") or "{}")
        action = body.get("action")
        if action == "upload":
            return start_upload(body)
        if action == "refresh":
            # An inexpensive durable cooldown prevents expensive refresh flooding.
            try:
                jobs.update_item(Key={"id": "refresh"}, UpdateExpression="SET next_at = :next",
                                 ConditionExpression="attribute_not_exists(next_at) OR next_at < :now",
                                 ExpressionAttributeValues={":next": int(time.time())+60, ":now": int(time.time())})
            except ClientError as exc:
                if conditional(exc):
                    return response(202, {"accepted": True})
                raise
            invoke_worker({"action": "refresh"})
            return response(202, {"accepted": True})
        if action == "cancel":
            job_id = body.get("id", "")
            if not ID.fullmatch(job_id):
                raise ValueError("Invalid message")
            try:
                jobs.update_item(Key={"id": job_id}, UpdateExpression="SET #s = :c",
                                 ConditionExpression="#s IN (:q,:s)",
                                 ExpressionAttributeNames={"#s": "status"},
                                 ExpressionAttributeValues={":c":"cancelled",":q":"queued",":s":"scheduled"})
            except ClientError as exc:
                if conditional(exc):
                    return response(409, {"error": "This message has already started or finished."})
                raise
            try:
                scheduler.delete_schedule(Name=job_id, GroupName=os.environ["SCHEDULE_GROUP"])
            except ClientError:
                pass  # Cancelled row is authoritative even if schedule cleanup fails.
            delete_attachment(read(jobs, job_id) or {})
            return response(200, {"cancelled": True})
        if action != "schedule":
            raise ValueError("Invalid action")
        job_id, chat, text = body.get("id",""), body.get("chat",""), body.get("text","")
        if not ID.fullmatch(job_id) or not CHAT.fullmatch(chat):
            raise ValueError("Choose a conversation")
        is_file = body.get("file") is True
        if (not isinstance(text,str) or len(text.encode("utf-16-le"))//2 > 10000
                or (not is_file and not text.strip()) or (is_file and text)):
            raise ValueError("Enter a message of at most 10,000 characters")
        immediate = body.get("immediate") is True
        now = int(time.time())
        due = now if immediate else int(datetime.fromisoformat(body["due_at"].replace("Z","+00:00")).timestamp())
        if not immediate and (due < now + 60 or due > now + 366*86400):
            raise ValueError("Choose a time at least one minute ahead and within one year")
        existing = read(jobs,job_id)
        if existing:
            if existing.get("chat") != chat or existing.get("text") != text or bool(existing.get("attachment")) != is_file:
                return response(409, {"error":"This request ID was already used."})
            return response(200, {"job":existing})
        meta = read(jobs,"meta") or {}
        names = {c["id"]:c["name"] for c in meta.get("chats",[])}
        if not meta.get("connected") or chat not in names:
            raise ValueError("Refresh conversations and select a connected chat")
        records = all_jobs()
        if sum(x["status"] in ("queued","scheduled","sending") for x in records) >= 200:
            raise ValueError("You already have 200 pending messages")
        item = {"id":job_id,"chat":chat,"chat_name":names[chat],"text":text,"due_at":due,
                "created_at":now,"status":"queued","timezone":str(body.get("timezone","UTC"))[:80],
                "expires_at":due+90*86400}
        if is_file:
            item["attachment"] = prepare_attachment(job_id)
        jobs.put_item(Item=item,ConditionExpression="attribute_not_exists(id)")
        try:
            if immediate:
                invoke_worker({"id":job_id})
            else:
                scheduler.create_schedule(
                    Name=job_id,GroupName=os.environ["SCHEDULE_GROUP"],ClientToken=job_id,
                    ScheduleExpression="at("+datetime.fromtimestamp(due,timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")+")",
                    ScheduleExpressionTimezone="UTC",FlexibleTimeWindow={"Mode":"OFF"},ActionAfterCompletion="DELETE",
                    Target={"Arn":os.environ["WORKER_ARN"],"RoleArn":os.environ["SCHEDULER_ROLE"],
                            "Input":json.dumps({"id":job_id}),
                            "RetryPolicy":{"MaximumEventAgeInSeconds":900,"MaximumRetryAttempts":10},
                            "DeadLetterConfig":{"Arn":os.environ["FAILURE_ARN"]}})
                jobs.update_item(Key={"id":job_id},UpdateExpression="SET #s = :s",
                                 ConditionExpression="#s = :q",ExpressionAttributeNames={"#s":"status"},
                                 ExpressionAttributeValues={":s":"scheduled",":q":"queued"})
                item["status"]="scheduled"
        except Exception:
            # Conservatively retain the job. If dispatch was accepted it may still run.
            # Never blindly create another message when the API response is lost.
            return response(202,{"job":read(jobs,job_id),"notice":"Refresh to confirm scheduling status."})
        return response(201,{"job":item})
    except (ValueError,KeyError,TypeError):
        return response(400,{"error":"Check the conversation, message, and scheduled time."})
    except Exception:
        return response(503,{"error":SAFE_ERROR})


def acquire(owner, now):
    try:
        session_table.put_item(Item={"id":"lock","owner":owner,"until":now+180},
            ConditionExpression="attribute_not_exists(id) OR #until < :now",
            ExpressionAttributeNames={"#until":"until"},ExpressionAttributeValues={":now":now})
        return True
    except ClientError as exc:
        if conditional(exc): return False
        raise


def save_session(blob, version, owner):
    # One transaction fences an expired/foreign lease and the session version.
    session_table.meta.client.transact_write_items(TransactItems=[
        {"ConditionCheck":{"TableName":session_table.name,"Key":{"id":"lock"},
          "ConditionExpression":"#owner = :owner AND #until > :now",
          "ExpressionAttributeNames":{"#owner":"owner","#until":"until"},
          "ExpressionAttributeValues":{":owner":owner,":now":int(time.time())}}},
        {"Put":{"TableName":session_table.name,
          "Item":{"id":"session","blob":blob,"version":version+1},
          "ConditionExpression":"#v = :v","ExpressionAttributeNames":{"#v":"version"},
          "ExpressionAttributeValues":{":v":version}}}
    ])


def run_client(action, owner, chat="", text="", file_input=None):
    saved = read(session_table,"session")
    if not saved: raise ValueError("No session")
    version = int(saved["version"])
    # Explicit environment excludes AWS role credentials from the child.
    env = {"PATH":"/usr/bin:/bin","HOME":"/tmp","LANG":"C.UTF-8"}
    process = subprocess.Popen(["/var/task/cloudline"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL,text=True,env=env)
    try:
        process.stdin.write(json.dumps({"action":action,"key":os.environ["SESSION_KEY"],"blob":saved["blob"],
                                        "chat":chat,"text":text, **(file_input or {})})+"\n")
        process.stdin.flush()
        result = None
        for line in process.stdout:
            if len(line)>2*1024*1024: raise ValueError("Oversized response")
            message = json.loads(line)
            if message.get("op")=="save":
                save_session(message["blob"],version,owner)
                version+=1
                process.stdin.write('{"ok":true}\n');process.stdin.flush()
            elif message.get("op")=="result":
                result=message;break
            else: raise ValueError("Invalid response")
        process.wait(timeout=5)
        if not result or not result.get("ok"): raise ValueError("LINE unavailable")
        return result["data"]
    finally:
        if process.poll() is None: process.kill()
        process.wait()
        process.stdin.close();process.stdout.close()


def extract_chats(data):
    # The CLI's versioned envelope has an explicit items collection.
    rows = data if isinstance(data,list) else data.get("chats",data.get("items",[]))
    return [{"id":r["id"],"name":r.get("name") or "Unnamed conversation"}
            for r in rows if CHAT.fullmatch(r.get("id",""))]


def worker(event, context):
    owner = context.aws_request_id
    if not acquire(owner,int(time.time())):
        # Safe to retry: no job claim and no LINE mutation has happened.
        raise RuntimeError("sender busy")
    job_id = event.get("id")
    claimed = False
    try:
        if event.get("action")=="probe":
            session_table.put_item(Item={"id":"session","blob":"","version":1},ConditionExpression="attribute_not_exists(id)")
            try:
                result=run_client("probe",owner)
                restored=run_client("probe-read",owner)
                return {"persisted":result["persisted"],"restored":restored["restored"]}
            finally:
                session_table.delete_item(Key={"id":"session"})
        if event.get("action")=="check":
            return run_client("check",owner)
        if event.get("action")=="refresh":
            try:
                run_client("check",owner)
                chats = extract_chats(run_client("chats",owner))
                if not chats: raise ValueError("No conversations")
                jobs.put_item(Item={"id":"meta","connected":True,"chats":chats,"refreshed_at":int(time.time())})
            except Exception:
                jobs.update_item(Key={"id":"meta"},UpdateExpression="SET connected = :c, #e = :e",
                    ExpressionAttributeNames={"#e":"error"},
                    ExpressionAttributeValues={":c":False,":e":"Reconnect LINE or refresh again if the connection was interrupted."})
            return {"ok":True}
        if not isinstance(job_id,str) or not ID.fullmatch(job_id):
            return {"ignored":True}
        job=read(jobs,job_id)
        if not job or job["status"] not in ("queued","scheduled"):
            return {"duplicate_or_cancelled":True}
        now=int(time.time())
        if job["due_at"]>now: raise RuntimeError("not due")
        if job["due_at"]<now-900:
            jobs.update_item(Key={"id":job_id},UpdateExpression="SET #s = :s",
                ExpressionAttributeNames={"#s":"status"},ExpressionAttributeValues={":s":"expired"})
            delete_attachment(job)
            return {"expired":True}
        jobs.update_item(Key={"id":job_id},UpdateExpression="SET #s = :s, started_at = :n",
            ConditionExpression="#s IN (:q,:p)",
            ExpressionAttributeNames={"#s":"status"},
            ExpressionAttributeValues={":s":"sending",":n":now,":q":"queued",":p":"scheduled"})
        claimed=True
        if job.get("attachment"):
            try:
                file_input = load_attachment(job["attachment"])
            except Exception:
                result = {"status":"failed", "error":"File unavailable or integrity check failed. Nothing was sent."}
            else:
                result=run_client("send-file",owner,job["chat"],"",file_input)
        else:
            result=run_client("send",owner,job["chat"],job["text"])
        jobs.update_item(Key={"id":job_id},UpdateExpression="SET #s = :s, result_info = :r, completed_at = :n",
            ConditionExpression="#s = :sending",ExpressionAttributeNames={"#s":"status"},
            ExpressionAttributeValues={":s":result["status"],":r":result,":n":int(time.time()),":sending":"sending"})
        return {"ok":True}
    except Exception:
        if claimed:
            try:
                jobs.update_item(Key={"id":job_id},UpdateExpression="SET #s = :s, #e = :e",
                    ConditionExpression="#s = :sending",ExpressionAttributeNames={"#s":"status","#e":"error"},
                    ExpressionAttributeValues={":s":"unknown",":sending":"sending",
                        ":e":"Delivery could not be confirmed. Check LINE before sending again."})
            except Exception:
                pass # Sending row remains a durable tombstone; never auto-replay.
            return {"unconfirmed":True}
        raise RuntimeError("sender preparation unavailable") from None
    finally:
        if claimed:
            delete_attachment(job)
        try:
            session_table.delete_item(Key={"id":"lock"},ConditionExpression="#o = :o",
                                      ExpressionAttributeNames={"#o":"owner"},ExpressionAttributeValues={":o":owner})
        except Exception: pass
