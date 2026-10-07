"""SQS consumer with a conditional, durable completed-delivery ledger."""

import json
import os
import time

from botocore.exceptions import ClientError
from common import client


def handler(event, _context):
    consumer = os.environ["CONSUMER"]
    table = os.environ["DELIVERIES_TABLE"]
    db = client("dynamodb")
    failures = []
    for record in event.get("Records", []):
        try:
            envelope = json.loads(record["body"])
            detail = envelope["detail"]
            event_id = detail["event_id"]
            delivery_id = f"{consumer}:{detail['tenant']}:{event_id}"
            if detail.get("fail_consumer") == consumer and not detail.get("replayed"):
                raise RuntimeError(f"simulated {consumer} outage for {event_id}")
            try:
                db.put_item(
                    TableName=table,
                    Item={
                        "delivery_id": {"S": delivery_id},
                        "event_id": {"S": event_id},
                        "consumer": {"S": consumer},
                        "tenant": {"S": detail["tenant"]},
                        "kind": {"S": detail["kind"]},
                        "amount": {"N": str(detail["amount"])},
                        "processed_at": {"N": str(int(time.time_ns()))},
                        "replayed": {"BOOL": bool(detail.get("replayed"))},
                    },
                    ConditionExpression="attribute_not_exists(delivery_id)",
                )
            except ClientError as error:
                if error.response["Error"]["Code"] != "ConditionalCheckFailedException":
                    raise
        except Exception as error:
            print(f"record {record['messageId']} failed: {type(error).__name__}")
            failures.append({"itemIdentifier": record["messageId"]})
    return {"batchItemFailures": failures}
