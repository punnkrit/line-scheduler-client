"""AWS CLI wrapper for the synthetic probe; never loads the LINE session."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from template import template


class AWS:
    def __init__(self, profile, region):
        executable = shutil.which("aws") or str(Path.home() / ".local/bin/aws")
        self.command = [executable, "--profile", profile, "--region", region,
                        "--no-cli-pager", "--output", "json"]

    def call(self, *args):
        env = dict(os.environ, AWS_PAGER="", AWS_CLI_AUTO_PROMPT="off")
        result = subprocess.run(self.command + list(args), capture_output=True,
                                text=True, check=True, env=env)
        return json.loads(result.stdout) if result.stdout.strip() else {}

    def payload(self, service, operation, value):
        with tempfile.TemporaryDirectory(prefix="line-dummy-probe-") as directory:
            path = Path(directory) / "request.json"
            path.write_text(json.dumps(value))
            path.chmod(0o600)
            return self.call(service, operation, "--cli-input-json", "file://" + str(path))


def outputs(aws, stack):
    result = aws.call("cloudformation", "describe-stacks", "--stack-name", stack)
    return {v["OutputKey"]: v["OutputValue"] for v in result["Stacks"][0]["Outputs"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="line-scheduler")
    parser.add_argument("--region", default="ap-southeast-1")
    parser.add_argument("--stack", default="line-scheduler-dummy-probe")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("deploy")
    schedule = sub.add_parser("schedule")
    schedule.add_argument("--minutes", type=int, default=2)
    status = sub.add_parser("status")
    status.add_argument("job_id")
    duplicate = sub.add_parser("duplicate")
    duplicate.add_argument("job_id")
    sub.add_parser("failures")
    args = parser.parse_args()
    if not args.stack.startswith("line-scheduler-dummy-") or len(args.stack) > 48:
        parser.error("Use a line-scheduler-dummy- stack name of at most 48 characters")
    aws = AWS(args.profile, args.region)

    if args.action == "deploy":
        # Only create a missing, isolated probe. Never overwrite an existing stack.
        try:
            aws.call("cloudformation", "describe-stacks", "--stack-name", args.stack)
        except subprocess.CalledProcessError as exc:
            if "does not exist" not in exc.stderr:
                raise
        else:
            raise SystemExit("Stack already exists; inspect it instead of redeploying")
        body = json.dumps(template())
        aws.payload("cloudformation", "validate-template", {"TemplateBody": body})
        result = aws.payload("cloudformation", "create-stack", {
            "StackName": args.stack, "TemplateBody": body,
            "Capabilities": ["CAPABILITY_IAM"],
            "Tags": [{"Key": "Purpose", "Value": "synthetic-line-scheduler-probe"}],
        })
        print(json.dumps(result))
        print("Creation started. Inspect CloudFormation completion before scheduling.")
        return

    out = outputs(aws, args.stack)
    if args.action == "schedule":
        if not 1 <= args.minutes <= 60:
            parser.error("Probe delay must be between 1 and 60 minutes")
        due = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=args.minutes)
        job = {"job_id": "probe-" + uuid4().hex, "due_at": due.isoformat()}
        # Persist a non-secret request before calling AWS for uncertain-outcome recovery.
        folder = Path(__file__).with_name(".local")
        folder.mkdir(mode=0o700, exist_ok=True)
        request = {
            "Name": job["job_id"], "GroupName": out["GroupName"],
            "ScheduleExpression": "at(" + due.strftime("%Y-%m-%dT%H:%M:%S") + ")",
            "ScheduleExpressionTimezone": "UTC", "FlexibleTimeWindow": {"Mode": "OFF"},
            "ActionAfterCompletion": "DELETE", "ClientToken": job["job_id"],
            "Target": {
                "Arn": out["FunctionArn"], "RoleArn": out["RoleArn"],
                "Input": json.dumps(job),
                "RetryPolicy": {"MaximumEventAgeInSeconds": 900, "MaximumRetryAttempts": 2},
                "DeadLetterConfig": {"Arn": out["FailureArn"]},
            },
        }
        local = folder / (job["job_id"] + ".json")
        local.write_text(json.dumps(request, indent=2))
        local.chmod(0o600)
        aws.payload("scheduler", "create-schedule", request)
        print(json.dumps(job))
        print("Scheduled once. After the due minute, use status with this job_id.")
        return

    if args.action == "failures":
        result = aws.call("sqs", "get-queue-attributes", "--queue-url", out["FailureQueueUrl"],
                          "--attribute-names", "ApproximateNumberOfMessages")
        print(json.dumps(result))
        return

    result = aws.call("dynamodb", "get-item", "--table-name", out["TableName"],
                      "--consistent-read", "--key", json.dumps({"job_id": {"S": args.job_id}}))
    if args.action == "status":
        print(json.dumps(result.get("Item", {"status": "pending-or-failed"}), indent=2))
        return
    receipt = result.get("Item")
    if not receipt:
        raise SystemExit("No original receipt; cannot test duplicate handling yet")
    event = {"job_id": args.job_id, "due_at": receipt["due_at"]["S"]}
    with tempfile.TemporaryDirectory(prefix="line-dummy-result-") as directory:
        response = Path(directory) / "result.json"
        metadata = aws.call("lambda", "invoke", "--function-name", out["FunctionArn"],
                            "--cli-binary-format", "raw-in-base64-out", "--payload",
                            json.dumps(event), str(response))
        content = json.loads(response.read_text())
        if metadata.get("FunctionError") or content.get("status") != "duplicate":
            raise SystemExit("Duplicate probe failed: " + json.dumps(content))
        if content["receipt"]["completed_at"] != receipt["completed_at"]["S"]:
            raise SystemExit("Duplicate invocation changed the original receipt")
        print("Duplicate invocation preserved the original receipt.")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.stderr.strip()) from None
