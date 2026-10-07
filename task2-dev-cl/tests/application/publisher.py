"""Validate and publish an order event to the dedicated SNS topic."""

import json
import os
import re
import uuid

from common import client


TENANT = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
KINDS = {"order.created", "order.cancelled"}
CONSUMERS = {"fulfillment", "analytics"}


def handler(event, _context):
    if not isinstance(event, dict) or event.get("operation") != "publish":
        raise ValueError("operation must be publish")
    try:
        event_id = str(uuid.UUID(event["event_id"]))
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise ValueError("event_id must be a UUID") from error
    if event_id != event["event_id"]:
        raise ValueError("event_id must be a canonical UUID")
    tenant = event.get("tenant")
    if not isinstance(tenant, str) or not TENANT.fullmatch(tenant):
        raise ValueError("tenant must be 1-32 lowercase letters, digits or hyphens")
    kind = event.get("kind")
    if kind not in KINDS:
        raise ValueError("kind must be order.created or order.cancelled")
    amount = event.get("amount")
    if type(amount) is not int or not 0 <= amount <= 1000000:
        raise ValueError("amount must be an integer from 0 to 1000000")
    fail_consumer = event.get("fail_consumer")
    if fail_consumer is not None and fail_consumer not in CONSUMERS:
        raise ValueError("fail_consumer is invalid")
    detail = {"event_id": event_id, "tenant": tenant, "kind": kind, "amount": amount}
    if fail_consumer:
        detail["fail_consumer"] = fail_consumer
    message = {"source": "pulseroute.orders", "detail-type": kind, "detail": detail}
    client("sns").publish(
        TopicArn=os.environ["TOPIC_ARN"],
        Message=json.dumps(message, separators=(",", ":")),
    )
    return {"status": "published", "event_id": event_id}
