"""Account switching must not reuse another account's artifact bucket."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import deploy


class DeploymentAccountTests(unittest.TestCase):
    def test_artifact_state_is_scoped_to_authenticated_account(self):
        account = "111111111111"
        for previous_account in (account, "222222222222"):
            with self.subTest(previous_account=previous_account), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                local = root / ".local"
                local.mkdir()
                (root / "handler.py").write_text("# synthetic handler\n")
                (local / "cloudline").write_bytes(b"synthetic binary")
                old_bucket = "line-scheduler-artifacts-" + previous_account + "-synthetic"
                old_state = {"bucket": old_bucket}
                (local / "deployment.json").write_text(json.dumps(old_state))
                requests = []

                def fake_call(*args, payload=None):
                    requests.append((args, payload))
                    if args[:2] == ("sts", "get-caller-identity"):
                        return {"Account": account}
                    if args[:2] == ("cloudformation", "describe-stacks"):
                        raise RuntimeError("Stack does not exist")
                    return {}

                with patch.object(deploy, "ROOT", root), patch.object(deploy, "LOCAL", local), \
                     patch.object(deploy, "call", fake_call), patch("builtins.print"):
                    deploy.deploy("https://private.example")

                scoped = json.loads((local / ("deployment-" + account + "-" + deploy.REGION + ".json")).read_text())
                bucket = scoped["bucket"]
                self.assertTrue(bucket.startswith("line-scheduler-artifacts-" + account + "-"))
                self.assertEqual(json.loads((local / "deployment.json").read_text()), old_state)
                uploads = [args for args, _ in requests if args[:2] == ("s3api", "put-object")]
                self.assertEqual(uploads[0][uploads[0].index("--bucket") + 1], bucket)
                creates = [payload for args, payload in requests if args[:2] == ("s3api", "create-bucket")]
                self.assertEqual(len(creates), int(previous_account != account))


if __name__ == "__main__":
    unittest.main()
