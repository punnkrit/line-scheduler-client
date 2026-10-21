"""Attachment tests are synthetic and never contact LINE or AWS."""
import hashlib
import io
import json
import os
import types
from decimal import Decimal
import unittest
from unittest.mock import Mock, patch

import test_scheduler as base
from test_scheduler import Table
import handler as h


class AttachmentTests(unittest.TestCase):
    def setUp(self):
        h.jobs=Table()
        self.id="b"*32
        self.content=b"synthetic attachment"
        self.spec={"name":"example.txt","size":len(self.content),"sha256":hashlib.sha256(self.content).hexdigest()}
        self.s3=Mock()
        self.s3.generate_presigned_post.return_value={"url":"https://example.invalid", "fields":{}}
        self.patch=patch.object(h,"objects",self.s3);self.patch.start()
        self.env=patch.dict(os.environ,{"FILES_BUCKET":"synthetic"});self.env.start()
    def tearDown(self):self.patch.stop();self.env.stop()
    def test_names_and_sizes_rejected(self):
        for spec in [{**self.spec,"name":"../private"},{**self.spec,"name":"a\\b"},
                     {**self.spec,"name":"a\n"},{**self.spec,"size":True},
                     {**self.spec,"size":h.MAX_FILE+1},{**self.spec,"sha256":"not a hash"}]:
            with self.subTest(spec=spec),self.assertRaises(ValueError):h.file_spec(spec)
    def test_upload_policy_has_exact_size_and_expiry(self):
        h.start_upload({"id":self.id,**self.spec})
        args,kw=self.s3.generate_presigned_post.call_args
        self.assertEqual(args,("synthetic","uploads/"+self.id))
        self.assertEqual(kw["ExpiresIn"],300)
        self.assertIn(["content-length-range",len(self.content),len(self.content)],kw["Conditions"])
        self.assertEqual(kw["Fields"]["x-amz-server-side-encryption"],"AES256")
    def test_upload_id_cannot_change_content(self):
        h.start_upload({"id":self.id,**self.spec})
        response=h.start_upload({"id":self.id,**self.spec,"name":"different.txt"})
        self.assertEqual(response["statusCode"],409)
        self.assertEqual(self.s3.generate_presigned_post.call_count,1)
    def test_accepted_job_does_not_get_another_upload(self):
        h.jobs.items[self.id]={"id":self.id,"attachment":self.spec}
        result=h.start_upload({"id":self.id,**self.spec})
        self.assertTrue(json.loads(result["body"])["scheduled"])
        self.s3.generate_presigned_post.assert_not_called()
    def test_schedule_pins_version_and_retains_only_that_version(self):
        h.jobs.items["upload_"+self.id]={**self.spec,"size":Decimal(len(self.content)),"expires_at":10**12}
        self.s3.head_object.return_value={"ContentLength":len(self.content),"VersionId":"immutable-version"}
        attachment=h.prepare_attachment(self.id)
        self.assertEqual(attachment["version"],"immutable-version")
        self.assertEqual(self.s3.put_object_tagging.call_args.kwargs["VersionId"],"immutable-version")
    def test_invalid_version_cannot_be_scheduled(self):
        h.jobs.items["upload_"+self.id]={**self.spec,"expires_at":10**12}
        self.s3.head_object.return_value={"ContentLength":len(self.content)}
        with self.assertRaises(ValueError):h.prepare_attachment(self.id)
        self.s3.put_object_tagging.assert_not_called()
    def test_file_read_checks_hash_and_uses_pinned_version(self):
        attachment={**self.spec,"size":Decimal(len(self.content)),"key":"uploads/"+self.id,"version":"v1"}
        self.s3.get_object.return_value={"Body":io.BytesIO(self.content)}
        result=h.load_attachment(attachment)
        self.assertEqual(result["file_name"],"example.txt")
        self.assertEqual(self.s3.get_object.call_args.kwargs["VersionId"],"v1")
        self.s3.get_object.return_value={"Body":io.BytesIO(b"tampered attachment")}
        with self.assertRaises(ValueError):h.load_attachment(attachment)
    def test_cleanup_deletes_only_pinned_version(self):
        h.delete_attachment({"attachment":{**self.spec,"key":"uploads/"+self.id,"version":"v1"}})
        self.s3.delete_object.assert_called_once_with(Bucket="synthetic",Key="uploads/"+self.id,VersionId="v1")
    def test_storage_private_and_scoped(self):
        from template import template
        resources=template()["Resources"]
        self.assertTrue(all(resources["Files"]["Properties"]["PublicAccessBlockConfiguration"].values()))
        self.assertEqual(resources["Files"]["Properties"]["VersioningConfiguration"]["Status"],"Enabled")
        policy=json.dumps(resources["WorkerRole"]["Properties"]["Policies"])
        self.assertNotIn("s3:PutObject",policy)
        self.assertIn("s3:GetObjectVersion",policy)
        abandoned=resources["Files"]["Properties"]["LifecycleConfiguration"]["Rules"][0]
        self.assertEqual(abandoned["NoncurrentVersionExpiration"]["NoncurrentDays"],1)


class AttachmentWorkerTests(unittest.TestCase):
    setUp = base.SchedulerTests.setUp
    tearDown = base.SchedulerTests.tearDown
    run_worker = base.SchedulerTests.run_worker
    def test_invalid_file_never_calls_line_and_is_not_replayed(self):
        h.jobs.items[self.id]["attachment"]={"name":"test.txt"}
        with patch.object(h,"load_attachment",side_effect=ValueError),patch.object(h,"delete_attachment"):
            self.run_worker(lambda *args:self.fail("LINE must not run on invalid bytes"))
            self.run_worker(lambda *args:self.fail("Failed job must not replay"))
        self.assertEqual(h.jobs.items[self.id]["status"],"failed")
    def test_file_claim_precedes_single_attempt(self):
        h.jobs.items[self.id]["attachment"]={"name":"test.txt"}
        def send(*args):
            self.assertEqual(h.jobs.items[self.id]["status"],"sending")
            self.assertEqual(args[0],"send-file")
            return {"status":"sent","encrypted":True}
        with patch.object(h,"load_attachment",return_value={"file_name":"test.txt","file_data":""}),patch.object(h,"delete_attachment"):
            self.run_worker(send)
            self.run_worker(lambda *args:self.fail("Duplicate attachment send"))
    def test_uncertain_file_attempt_cleans_up_without_replay(self):
        h.jobs.items[self.id]["attachment"]={"name":"test.txt"}
        with patch.object(h,"load_attachment",return_value={"file_name":"test.txt","file_data":""}), \
             patch.object(h,"delete_attachment") as cleanup:
            self.run_worker(Mock(side_effect=OSError("synthetic lost response")))
            self.assertEqual(h.jobs.items[self.id]["status"],"unknown")
            self.run_worker(lambda *args:self.fail("Uncertain file must not replay"))
            cleanup.assert_called_once()

if __name__=="__main__":unittest.main()
