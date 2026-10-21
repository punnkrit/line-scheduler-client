"""Synthetic receipt writer. Deliberately contains no LINE integration."""

import os
import re
from datetime import datetime, timezone


def record(event, table, now):
    if not isinstance(event, dict) or set(event) != {"job_id", "due_at"}:
        raise ValueError("Expected only a synthetic job_id and due_at")
    job_id, due_at = event["job_id"], event["due_at"]
    if not isinstance(job_id, str) or not re.fullmatch(r"probe-[a-z0-9-]{8,60}", job_id):
        raise ValueError("Invalid synthetic job ID")
    if not isinstance(due_at, str):
        raise ValueError("Invalid due time")
    due = datetime.fromisoformat(due_at.replace("Z", "+00:00"))
    if due.tzinfo is None:
        raise ValueError("Due time must include a timezone")
    if now < due:
        # Never record a successful execution before its due time.
        raise ValueError("Job is not due yet")
    item = {
        "job_id": job_id,
        "due_at": due_at,
        "completed_at": now.isoformat(),
        "delay_ms": int((now - due).total_seconds() * 1000),
        "scope": "synthetic-receipt-only",
    }
    try:
        table.put_item(Item=item, ConditionExpression="attribute_not_exists(job_id)")
    except Exception as exc:
        if getattr(exc, "response", {}).get("Error", {}).get("Code") != "ConditionalCheckFailedException":
            raise
        existing = table.get_item(Key={"job_id": job_id}, ConsistentRead=True).get("Item")
        if not existing or existing["due_at"] != due_at:
            raise ValueError("Job ID reused with different content") from None
        return {"status": "duplicate", "receipt": existing}
    return {"status": "recorded", "receipt": item}


def handler(event, context):
    import boto3  # Included in the Lambda runtime for this inline dummy probe.

    table = boto3.resource("dynamodb").Table(os.environ["RECEIPTS_TABLE"])
    result = record(event, table, datetime.now(timezone.utc))
    # Do not log the incoming event or any future credential material.
    print(result["status"])
    return result
