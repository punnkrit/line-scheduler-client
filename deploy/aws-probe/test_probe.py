import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import threading
import unittest

from handler import record
from template import template


class Conflict(Exception):
    response = {"Error": {"Code": "ConditionalCheckFailedException"}}


class Table:
    def __init__(self):
        self.items = {}
        self.lock = threading.Lock()

    def put_item(self, Item, ConditionExpression):
        assert ConditionExpression == "attribute_not_exists(job_id)"
        with self.lock:
            if Item["job_id"] in self.items:
                raise Conflict()
            self.items[Item["job_id"]] = copy.deepcopy(Item)

    def get_item(self, Key, ConsistentRead):
        assert ConsistentRead
        return {"Item": copy.deepcopy(self.items.get(Key["job_id"]))}


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 21, 12, tzinfo=timezone.utc)
        self.event = {"job_id": "probe-synthetic-test", "due_at": self.now.isoformat()}
        self.table = Table()

    def test_early_invocation_writes_nothing(self):
        with self.assertRaisesRegex(ValueError, "not due"):
            record(self.event, self.table, self.now - timedelta(seconds=1))
        self.assertEqual(self.table.items, {})

    def test_simultaneous_invocations_have_one_receipt(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: record(self.event, self.table, self.now), range(24)))
        self.assertEqual(sum(r["status"] == "recorded" for r in results), 1)
        self.assertEqual(len(self.table.items), 1)

    def test_later_retry_preserves_timestamp(self):
        first = record(self.event, self.table, self.now)
        later = record(self.event, self.table, self.now + timedelta(minutes=5))
        self.assertEqual(later["status"], "duplicate")
        self.assertEqual(first["receipt"], later["receipt"])

    def test_same_id_different_due_time_rejected(self):
        record(self.event, self.table, self.now)
        event = dict(self.event, due_at=(self.now - timedelta(minutes=1)).isoformat())
        with self.assertRaisesRegex(ValueError, "different content"):
            record(event, self.table, self.now)

    def test_private_or_malformed_inputs_rejected(self):
        for event in [None, {}, dict(self.event, message="not allowed"),
                      dict(self.event, job_id="real-chat"),
                      dict(self.event, due_at="2026-10-21T12:00:00")]:
            with self.subTest(event=event), self.assertRaises(ValueError):
                record(event, self.table, self.now)
        self.assertEqual(self.table.items, {})

    def test_storage_error_is_not_success(self):
        class Broken(Table):
            def put_item(self, **kwargs):
                raise RuntimeError("unavailable")
        with self.assertRaises(RuntimeError):
            record(self.event, Broken(), self.now)

    def test_deployment_is_private_and_roles_scoped(self):
        resources = template()["Resources"]
        types = {r["Type"] for r in resources.values()}
        self.assertNotIn("AWS::Lambda::Url", types)
        self.assertNotIn("AWS::Lambda::Permission", types)
        self.assertNotIn("AWS::Scheduler::Schedule", types)
        for name in ["FunctionRole", "SchedulerRole"]:
            for p in resources[name]["Properties"]["Policies"]:
                for statement in p["PolicyDocument"]["Statement"]:
                    self.assertNotEqual(statement["Resource"], "*")


if __name__ == "__main__":
    unittest.main()
