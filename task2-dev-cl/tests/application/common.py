"""Shared helpers for the fixed PulseRoute Lambda images."""

import os


def client(service):
    import boto3

    options = {"region_name": os.environ.get("AWS_REGION", "us-east-1")}
    if os.environ.get("AWS_ENDPOINT_URL"):
        options["endpoint_url"] = os.environ["AWS_ENDPOINT_URL"]
    return boto3.client(service, **options)
