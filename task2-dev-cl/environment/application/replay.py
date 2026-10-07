"""Move poison events from one consumer's DLQ back to its own main queue."""

import json
import os

from common import client


def handler(event, _context):
    if not isinstance(event, dict) or event.get("operation") != "replay":
        raise ValueError("operation must be replay")
    consumer = event.get("consumer")
    if consumer not in ("fulfillment", "analytics"):
        raise ValueError("consumer must be fulfillment or analytics")
    limit = event.get("limit", 10)
    if type(limit) is not int or not 1 <= limit <= 10:
        raise ValueError("limit must be 1-10")
    sqs = client("sqs")
    source = os.environ[f"{consumer.upper()}_DLQ"]
    target = os.environ[f"{consumer.upper()}_QUEUE"]
    response = sqs.receive_message(QueueUrl=source, MaxNumberOfMessages=limit,
                                   WaitTimeSeconds=1)
    count = 0
    for message in response.get("Messages", []):
        envelope = json.loads(message["Body"])
        envelope["detail"]["replayed"] = True
        sqs.send_message(QueueUrl=target, MessageBody=json.dumps(envelope))
        sqs.delete_message(QueueUrl=source, ReceiptHandle=message["ReceiptHandle"])
        count += 1
    return {"status": "replayed", "consumer": consumer, "count": count}
