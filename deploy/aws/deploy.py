"""Deployment and private administration. Secrets stay in process memory/stdin."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import zipfile
from template import template

ROOT=Path(__file__).parent
LOCAL=ROOT/".local"
STACK="line-scheduler"
REGION="ap-southeast-1"
AWS=[str(Path.home()/".local/bin/aws"),"--profile","line-scheduler","--region",REGION,"--no-cli-pager","--output","json"]
def call(*args,payload=None):
    command=AWS+list(args)
    fd=None
    if payload is not None:
        fd=os.memfd_create("aws-request",0)
        os.write(fd,json.dumps(payload).encode());os.lseek(fd,0,0)
        command+=["--cli-input-json","file:///proc/self/fd/"+str(fd)]
    try:
        result=subprocess.run(command,text=True,capture_output=True,pass_fds=(() if fd is None else (fd,)))
    finally:
        if fd is not None:os.close(fd)
    if result.returncode:
        # Never include command/input/environment or response bodies containing secrets.
        raise RuntimeError("AWS operation failed: "+str(args[:2])+" "+result.stderr[:700])
    return json.loads(result.stdout) if result.stdout.strip() else {}
def outputs():
    return {i["OutputKey"]:i["OutputValue"] for i in call("cloudformation","describe-stacks","--stack-name",STACK)["Stacks"][0]["Outputs"]}
def config(name):
    return call("lambda","get-function-configuration","--function-name",name)["Environment"]["Variables"]
def invoke(name,event):
    path=LOCAL/"response.json"
    meta=call("lambda","invoke","--function-name",name,"--cli-binary-format","raw-in-base64-out",
              "--payload",json.dumps(event),str(path))
    data=json.loads(path.read_text());path.unlink()
    if meta.get("FunctionError"):raise RuntimeError("Cloud function failed")
    return data
def deploy(site_origin=None):
    LOCAL.mkdir(exist_ok=True,mode=0o700)
    package=LOCAL/"function.zip"
    with zipfile.ZipFile(package,"w",zipfile.ZIP_DEFLATED) as z:
        z.write(ROOT/"handler.py","handler.py")
        info=zipfile.ZipInfo("cloudline");info.external_attr=0o100755<<16;info.compress_type=zipfile.ZIP_DEFLATED
        z.writestr(info,(LOCAL/"cloudline").read_bytes())
    artifact="builds/"+hashlib.sha256(package.read_bytes()).hexdigest()+".zip"
    account=call("sts","get-caller-identity")["Account"]
    state=LOCAL/("deployment-"+account+"-"+REGION+".json")
    legacy=LOCAL/"deployment.json"
    if not state.exists() and legacy.exists():
        previous=json.loads(legacy.read_text())
        if previous.get("bucket", "").startswith("line-scheduler-artifacts-"+account+"-"):
            state.write_text(json.dumps(previous));state.chmod(0o600)
    if state.exists(): settings=json.loads(state.read_text())
    else:
        bucket="line-scheduler-artifacts-"+account+"-"+secrets.token_hex(4)
        call("s3api","create-bucket",payload={"Bucket":bucket,"CreateBucketConfiguration":{"LocationConstraint":REGION}})
        call("s3api","put-public-access-block",payload={"Bucket":bucket,"PublicAccessBlockConfiguration":{
            "BlockPublicAcls":True,"IgnorePublicAcls":True,"BlockPublicPolicy":True,"RestrictPublicBuckets":True}})
        call("s3api","put-bucket-encryption",payload={"Bucket":bucket,"ServerSideEncryptionConfiguration":{
            "Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":False}]}})
        settings={"bucket":bucket};state.write_text(json.dumps(settings));state.chmod(0o600)
    call("s3api","put-object","--bucket",settings["bucket"],"--key",artifact,"--body",str(package))
    body=json.dumps(template())
    call("cloudformation","validate-template",payload={"TemplateBody":body})
    try:
        existing=call("cloudformation","describe-stacks","--stack-name",STACK)
    except RuntimeError as exc:
        if "does not exist" not in str(exc):raise
        existing=None
    parameters=[{"ParameterKey":"ArtifactBucket","ParameterValue":settings["bucket"]},
                {"ParameterKey":"ArtifactKey","ParameterValue":artifact}]
    if site_origin:
        parameters.append({"ParameterKey":"SiteOrigin","ParameterValue":site_origin.rstrip("/")})
    elif existing and any(p["ParameterKey"] == "SiteOrigin" for p in existing["Stacks"][0].get("Parameters",[])):
        parameters.append({"ParameterKey":"SiteOrigin","UsePreviousValue":True})
    else:
        raise RuntimeError("Provide --site-origin https://your-private-site.example for attachment uploads")
    if existing:
        parameters += [{"ParameterKey":key,"UsePreviousValue":True} for key in ["SessionKey","BridgeToken"]]
    else:
        parameters += [{"ParameterKey":"SessionKey","ParameterValue":base64.b64encode(secrets.token_bytes(32)).decode()},
                       {"ParameterKey":"BridgeToken","ParameterValue":secrets.token_urlsafe(48)}]
    call("cloudformation","update-stack" if existing else "create-stack",payload={
        "StackName":STACK,"TemplateBody":body,"Parameters":parameters,"Capabilities":["CAPABILITY_IAM"]})
    print("Stack update started." if existing else "Stack creation started.")
def migrate():
    out=outputs()
    table=out["SessionTable"]
    current=call("dynamodb","get-item",payload={"TableName":table,"Key":{"id":{"S":"session"}},"ConsistentRead":True})
    if current.get("Item"):raise RuntimeError("Cloud session already exists; refusing to overwrite")
    key=config(out["WorkerName"])["SESSION_KEY"]
    binary=ROOT/".local/cloudline.exe"
    proc=subprocess.Popen([str(binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
    try:
        proc.stdin.write(json.dumps({"action":"export","key":key})+"\n");proc.stdin.flush()
        for line in proc.stdout:
            msg=json.loads(line)
            if msg.get("op")=="save":
                # Ciphertext-only recovery file: never contains key or plaintext.
                recovery=LOCAL/"migration.enc"
                recovery.write_text(msg["blob"]);recovery.chmod(0o600)
                call("dynamodb","put-item",payload={"TableName":table,
                    "Item":{"id":{"S":"session"},"version":{"N":"1"},"blob":{"S":msg["blob"]}},
                    "ConditionExpression":"attribute_not_exists(id)"})
                proc.stdin.write('{"ok":true}\n');proc.stdin.flush()
            elif msg.get("op")=="result":
                if not msg.get("ok"):raise RuntimeError("Migration unavailable; local LINE login may be required")
                print("Encrypted session transferred. Local CLI copy disabled.");break
        if proc.wait(timeout=10)!=0:raise RuntimeError("Migration failed")
    finally:
        if proc.poll() is None:proc.kill()
        proc.wait()
    print(invoke(out["WorkerName"],{"action":"refresh"}))
def main():
    parser=argparse.ArgumentParser();parser.add_argument("action",choices=["deploy","status","migrate","refresh","check","probe","verify"])
    parser.add_argument("--site-origin",help="Exact private Site origin, used for S3 upload CORS")
    args=parser.parse_args()
    if args.action=="deploy":return deploy(args.site_origin)
    if args.action=="status":
        print(call("cloudformation","describe-stacks","--stack-name",STACK)["Stacks"][0]["StackStatus"]);return
    out=outputs()
    if args.action=="migrate":return migrate()
    if args.action=="refresh":print(invoke(out["WorkerName"],{"action":"refresh"}))
    if args.action=="check":
        item=call("dynamodb","get-item",payload={"TableName":out["JobsTable"],"Key":{"id":{"S":"meta"}},"ConsistentRead":True}).get("Item",{})
        print(json.dumps({"connected":item.get("connected",{}).get("BOOL",False),"chat_count":len(item.get("chats",{}).get("L",[]))}))
    if args.action=="probe":print(invoke(out["WorkerName"],{"action":"probe"}))
    if args.action=="verify":print(invoke(out["WorkerName"],{"action":"check"}))
if __name__=="__main__":
    try:main()
    except Exception as exc:
        print(str(exc),file=sys.stderr);sys.exit(1)
