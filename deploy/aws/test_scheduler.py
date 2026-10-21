"""Synthetic-only behavior tests; never load a LINE session."""
import importlib
import json
import os
import sys
import types
import unittest
from unittest.mock import patch

class ClientError(Exception):
    def __init__(self, code="ConditionalCheckFailedException"):
        self.response={"Error":{"Code":code}}
class Table:
    def __init__(self): self.items={};self.writes=[]
    def get_item(self,Key,**kw):return {"Item":self.items[Key["id"]]} if Key["id"] in self.items else {}
    def put_item(self,Item,**kw):
        if kw.get("ConditionExpression")=="attribute_not_exists(id)" and Item["id"] in self.items:raise ClientError()
        self.items[Item["id"]]=dict(Item)
    def scan(self,**kw):return {"Items":list(self.items.values())}
    def update_item(self,Key,ExpressionAttributeValues,**kw):
        item=self.items.setdefault(Key["id"],{"id":Key["id"]})
        values=ExpressionAttributeValues
        cond=kw.get("ConditionExpression","")
        if "#s IN" in cond and item.get("status") not in [values.get(":q"),values.get(":p"),values.get(":s")]:raise ClientError()
        if "#s = :sending" in cond and item.get("status")!="sending":raise ClientError()
        if ":s" in values:item["status"]=values[":s"]
        if ":c" in values:item["status"]=values[":c"]
        if ":r" in values:item["result_info"]=values[":r"]
        if ":n" in values:item["started_at"]=values[":n"]
        if ":e" in values:item["error"]=values[":e"]
        self.writes.append(dict(item))
    def delete_item(self,Key,**kw):self.items.pop(Key["id"],None)
dummy=types.SimpleNamespace(resource=lambda _:types.SimpleNamespace(Table=lambda _:Table()),client=lambda _,**kw:None)
sys.modules.setdefault("boto3",dummy)
sys.modules.setdefault("botocore",types.ModuleType("botocore"))
errors=types.ModuleType("botocore.exceptions");errors.ClientError=ClientError;sys.modules.setdefault("botocore.exceptions",errors)
config=types.ModuleType("botocore.config");config.Config=lambda **kw:kw;sys.modules.setdefault("botocore.config",config)
os.environ.update(JOBS_TABLE="jobs",SESSION_TABLE="sessions",BRIDGE_TOKEN="synthetic",SCHEDULE_GROUP="group")
import handler as h

class SchedulerTests(unittest.TestCase):
    def setUp(self):
        h.jobs=Table();h.session_table=Table();self.context=types.SimpleNamespace(aws_request_id="test")
        self.id="a"*32
        h.jobs.items[self.id]={"id":self.id,"status":"scheduled","due_at":1000,"chat":"c"+"0"*32,"text":"synthetic","created_at":900}
        self.time=patch.object(h.time,"time",return_value=1000);self.time.start()
    def tearDown(self):self.time.stop()
    def run_worker(self,client):
        with patch.object(h,"acquire",return_value=True),patch.object(h,"run_client",client):
            return h.worker({"id":self.id},self.context)
    def test_duplicate_never_sends_twice(self):
        calls=[]
        def client(*args):calls.append(args);return {"status":"sent","encrypted":True}
        self.run_worker(client);self.run_worker(client)
        self.assertEqual(len(calls),1);self.assertEqual(h.jobs.items[self.id]["status"],"sent")
    def test_uncertain_failure_is_never_replayed(self):
        calls=[]
        def client(*args):calls.append(args);raise OSError("private raw response")
        self.run_worker(client);self.run_worker(client)
        self.assertEqual(len(calls),1);self.assertEqual(h.jobs.items[self.id]["status"],"unknown")
        self.assertNotIn("private",json.dumps(h.jobs.items))
    def test_cancelled_never_sends(self):
        h.jobs.items[self.id]["status"]="cancelled"
        self.run_worker(lambda *args:self.fail("sent cancelled job"))
    def test_early_job_stays_pending(self):
        h.jobs.items[self.id]["due_at"]=1001
        with self.assertRaises(RuntimeError):self.run_worker(lambda *args:self.fail("sent early"))
        self.assertEqual(h.jobs.items[self.id]["status"],"scheduled")
    def test_old_job_expires(self):
        h.jobs.items[self.id]["due_at"]=1
        self.run_worker(lambda *args:self.fail("sent stale"))
        self.assertEqual(h.jobs.items[self.id]["status"],"expired")
    def test_durable_claim_precedes_send(self):
        def client(*args):
            self.assertEqual(h.jobs.items[self.id]["status"],"sending")
            return {"status":"sent"}
        self.run_worker(client)
    def test_busy_has_no_claim(self):
        with patch.object(h,"acquire",return_value=False),self.assertRaises(RuntimeError):
            h.worker({"id":self.id},self.context)
        self.assertEqual(h.jobs.items[self.id]["status"],"scheduled")
    def test_unauthorized_does_not_read_jobs(self):
        with patch.object(h,"all_jobs",side_effect=AssertionError):
            r=h.controller({"headers":{}},None)
        self.assertEqual(r["statusCode"],401)
    def test_session_not_in_controller_permissions(self):
        from template import template
        resources=template()["Resources"]
        statement=resources["APIRole"]["Properties"]["Policies"][0]["PolicyDocument"]
        self.assertNotIn("Sessions",json.dumps(statement))
        self.assertNotIn("SESSION_KEY",json.dumps(resources["API"]))
        self.assertEqual(resources["Worker"]["Properties"]["Timeout"],120)
        self.assertEqual(resources["URL"]["Properties"]["AuthType"],"NONE")
    def test_conversation_envelope(self):
        result=h.extract_chats({"schema_version":1,"chats":[{"id":"c"+"0"*32,"name":"Synthetic"}]})
        self.assertEqual(result[0]["name"],"Synthetic")
if __name__=="__main__":unittest.main()
