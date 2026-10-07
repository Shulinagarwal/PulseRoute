#!/usr/bin/env python3
"""Adoption and convergence helpers for one PulseRoute deployment.

Terraform declares every scored resource. This script covers what plain
Terraform cannot: adopting an existing deployment when local state is gone,
and removing out-of-band additions that no declared resource tracks. Every
lookup uses an exact name or an identifier from Terraform state; nothing is
ever selected by name prefix.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid

import boto3
from botocore.exceptions import ClientError


REGION = "us-east-1"
ACCOUNT = "111111111111"
CONSUMERS = ("fulfillment", "analytics")
SERVICES = ("publisher", "fulfillment", "analytics", "replay")
CALLERS = ("publisher", "operator", "outsider")
INVOKERS = ("publisher", "operator")
ABSENT = {
    "NotFound", "NotFoundException", "ResourceNotFoundException", "NoSuchEntity",
    "AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist",
}


def client(service):
    credentials = json.loads(Path(os.environ["PULSEROUTE_TFVARS"]).read_text())
    return boto3.client(
        service,
        endpoint_url=os.environ.get("PULSEROUTE_ENDPOINT", "http://aws:4566"),
        region_name=REGION,
        aws_access_key_id=credentials["admin_access_key"],
        aws_secret_access_key=credentials["admin_secret_key"],
    )


def absent(error):
    return (error.response["Error"]["Code"] in ABSENT
            or error.response["ResponseMetadata"].get("HTTPStatusCode") == 404)


def lookup(call, **kwargs):
    """Return the API response, or None when the resource does not exist."""
    try:
        return call(**kwargs)
    except ClientError as error:
        if absent(error):
            return None
        raise


def pages(api, operation, key, **kwargs):
    for page in api.get_paginator(operation).paginate(**kwargs):
        yield from page.get(key, [])


def function_name(arn):
    # arn:aws:lambda:<region>:<account>:function:<name>[:<qualifier>]
    parts = (arn or "").split(":")
    return parts[6] if len(parts) > 6 else arn


def seed_queues(engine, chdir, queues):
    """Record existing queues in state under their exact URLs.

    The AWS provider's import parser only accepts amazonaws.com queue URLs, so
    Floci queues cannot be imported. A state entry holding just the URL is
    enough: the next plan refreshes every other attribute from the queue.
    """
    terraform = [engine, f"-chdir={chdir}"]
    pulled = subprocess.run([*terraform, "state", "pull"], check=True, capture_output=True, text=True).stdout.strip()
    if pulled:
        state = json.loads(pulled)
    else:
        version = json.loads(subprocess.run([*terraform, "version", "-json"], check=True,
                                            capture_output=True, text=True).stdout)["terraform_version"]
        state = {"version": 4, "terraform_version": version, "serial": 0, "lineage": str(uuid.uuid4()),
                 "outputs": {}, "resources": [], "check_results": None}
    for kind, consumer, url, name in queues:
        entry = next((r for r in state["resources"] if r.get("mode") == "managed"
                      and r.get("type") == "aws_sqs_queue" and r.get("name") == kind), None)
        if entry is None:
            entry = {"mode": "managed", "type": "aws_sqs_queue", "name": kind,
                     "provider": 'provider["registry.terraform.io/hashicorp/aws"]', "instances": []}
            state["resources"].append(entry)
        entry["instances"] = [i for i in entry["instances"] if i.get("index_key") != consumer]
        entry["instances"].append({
            "index_key": consumer, "schema_version": 0, "sensitive_attributes": [],
            "attributes": {"id": url, "url": url, "name": name},
            "identity_schema_version": 1, "identity": {"url": url},
        })
    state["serial"] = int(state.get("serial", 0)) + 1
    with tempfile.NamedTemporaryFile("w", suffix=".tfstate", delete=False) as handle:
        json.dump(state, handle)
    try:
        subprocess.run([*terraform, "state", "push", handle.name], check=True)
    finally:
        os.unlink(handle.name)


def state_resources(state_json):
    state = json.loads(Path(state_json).read_text() or "{}")
    return state.get("values", {}).get("root_module", {}).get("resources", [])


def rescue(prefix, state_json):
    """Keep the deployment's own KMS key alive before Terraform reads it.

    The provider treats a key pending deletion as gone and would plan a new key,
    which would orphan everything encrypted under the old one.
    """
    kms = client("kms")
    recorded = next((r["values"].get("key_id") or r["values"].get("id") for r in state_resources(state_json)
                     if r.get("type") == "aws_kms_key"), None)
    found = lookup(kms.describe_key, KeyId=recorded) if recorded else None
    found = found or lookup(kms.describe_key, KeyId=f"alias/{prefix}-pulseroute")
    if not found:
        return
    key = found["KeyMetadata"]
    if key["KeyState"] == "PendingDeletion":
        kms.cancel_key_deletion(KeyId=key["KeyId"])
        print(f"rescue: cancelled deletion of {key['KeyId']}")
        key = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
    if key["KeyState"] == "Disabled":
        kms.enable_key(KeyId=key["KeyId"])
        print(f"rescue: re-enabled {key['KeyId']}")


def adopt(prefix, state_list, out, engine, chdir, mode):
    """Bring this deployment's existing resources that state lacks under management."""
    managed = set(Path(state_list).read_text().split()) if Path(state_list).is_file() else set()
    sns, sqs, ddb, iam, lam, kms = (client(name) for name in ("sns", "sqs", "dynamodb", "iam", "lambda", "kms"))
    imports, queues = [], []

    def add(address, identifier):
        if address not in managed:
            imports.append((address, identifier))

    alias = f"alias/{prefix}-pulseroute"
    key = lookup(kms.describe_key, KeyId=alias)
    # A key pending deletion is already destroyed as far as destroy.sh is concerned;
    # deploy.sh rescues it before adopting.
    if key and key["KeyMetadata"]["KeyState"] != "PendingDeletion":
        add("aws_kms_key.orders", key["KeyMetadata"]["KeyId"])
        add("aws_kms_alias.orders", alias)
    elif key and mode == "deploy":
        raise SystemExit(f"{alias} is pending deletion; run rescue first")

    topic = f"arn:aws:sns:{REGION}:{ACCOUNT}:{prefix}-orders"
    topic_exists = lookup(sns.get_topic_attributes, TopicArn=topic) is not None
    if topic_exists:
        add("aws_sns_topic.orders", topic)
        add("aws_sns_topic_policy.orders", topic)

    queue_arns = {}
    for consumer in CONSUMERS:
        for kind, name in (("main", f"{prefix}-{consumer}"), ("dlq", f"{prefix}-{consumer}-dlq")):
            found = lookup(sqs.get_queue_url, QueueName=name)
            if not found:
                continue
            url = found["QueueUrl"]
            attributes = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]
            queue_arns[(kind, consumer)] = attributes["QueueArn"]
            if f'aws_sqs_queue.{kind}["{consumer}"]' not in managed:
                queues.append((kind, consumer, url, name))
            # Queue, redrive and redrive allow policies are not imported: their
            # import IDs are queue URLs too, and creating them only overwrites a
            # queue attribute, which is idempotent.
        table = f"{prefix}-{consumer}-deliveries"
        if lookup(ddb.describe_table, TableName=table):
            add(f'aws_dynamodb_table.deliveries["{consumer}"]', table)

    if topic_exists:
        subscriptions = list(pages(sns, "list_subscriptions_by_topic", "Subscriptions", TopicArn=topic))
        for consumer in CONSUMERS:
            endpoint = queue_arns.get(("main", consumer))
            match = next((s["SubscriptionArn"] for s in subscriptions
                          if endpoint and s.get("Protocol") == "sqs" and s.get("Endpoint") == endpoint
                          and s["SubscriptionArn"].startswith("arn:")), None)
            if match:
                add(f'aws_sns_topic_subscription.queue["{consumer}"]', match)

    for service in SERVICES:
        role = f"{prefix}-{service}-lambda"
        if not lookup(iam.get_role, RoleName=role):
            continue
        add(f'aws_iam_role.lambda["{service}"]', role)
        add(f'aws_iam_role_policies_exclusive.service["{service}"]', role)
        add(f'aws_iam_role_policy_attachments_exclusive.service["{service}"]', role)
        if lookup(iam.get_role_policy, RoleName=role, PolicyName=f"{prefix}-{service}"):
            add(f'aws_iam_role_policy.service["{service}"]', f"{role}:{prefix}-{service}")

    functions = set()
    for service in SERVICES:
        name = f"{prefix}-{service}"
        if lookup(lam.get_function_configuration, FunctionName=name):
            functions.add(service)
            add(f'aws_lambda_function.service["{service}"]', name)

    for consumer in CONSUMERS:
        source = queue_arns.get(("main", consumer))
        if not source or consumer not in functions:
            continue
        match = next((m["UUID"] for m in pages(lam, "list_event_source_mappings", "EventSourceMappings",
                                                EventSourceArn=source)
                      if function_name(m.get("FunctionArn")) == f"{prefix}-{consumer}"), None)
        if match:
            add(f'aws_lambda_event_source_mapping.worker["{consumer}"]', match)

    for caller in CALLERS:
        user = f"{prefix}-{caller}-caller"
        if not lookup(iam.get_user, UserName=user):
            continue
        add(f'aws_iam_user.caller["{caller}"]', user)
        add(f'aws_iam_user_policies_exclusive.caller["{caller}"]', user)
        add(f'aws_iam_user_policy_attachments_exclusive.caller["{caller}"]', user)
        policy = f"{prefix}-{caller}-invoke"
        if caller in INVOKERS and lookup(iam.get_user_policy, UserName=user, PolicyName=policy):
            add(f'aws_iam_user_policy.caller["{caller}"]', f"{user}:{policy}")

    # Access keys are never imported: their secrets cannot be read back, so
    # Terraform issues fresh keys and prune-keys/reconcile retire the old ones.
    if queues:
        seed_queues(engine, chdir, queues)
    blocks = [f'import {{\n  to = {address}\n  id = {json.dumps(identifier)}\n}}\n' for address, identifier in imports]
    if blocks:
        Path(out).write_text("\n".join(blocks))
    elif Path(out).exists():
        Path(out).unlink()
    print(f"adopt: {len(queues)} queue(s) recorded, {len(blocks)} resource(s) to import for {prefix}")


def prune_keys(prefix, state_json):
    """Before apply, make room for Terraform without stranding the callers.

    A key that state holds is kept and every other key on that user is an
    out-of-band addition. When state holds no key for a user (state was lost),
    Terraform will issue a new one; IAM allows two keys per user, so keep only
    the newest existing key until reconcile retires it after a successful apply.
    """
    known = {r["values"]["id"] for r in state_resources(state_json) if r.get("type") == "aws_iam_access_key"}
    iam = client("iam")
    for caller in CALLERS:
        user = f"{prefix}-{caller}-caller"
        if not lookup(iam.get_user, UserName=user):
            continue
        keys = sorted(pages(iam, "list_access_keys", "AccessKeyMetadata", UserName=user),
                      key=lambda key: key["CreateDate"])
        unknown = [key for key in keys if key["AccessKeyId"] not in known]
        if len(unknown) == len(keys):
            unknown = unknown[:-1]
        for key in unknown:
            iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"])
            print(f"prune-keys: removed unmanaged key from {user}")


def reconcile(owned_path):
    """After apply, remove out-of-band additions attached to owned resources."""
    owned = json.loads(Path(owned_path).read_text())
    sns, iam, lam, kms = client("sns"), client("iam"), client("lambda"), client("kms")

    # The configuration declares no grants on the deployment key.
    for grant in list(pages(kms, "list_grants", "Grants", KeyId=owned["key"])):
        kms.revoke_grant(KeyId=owned["key"], GrantId=grant["GrantId"])
        print(f"reconcile: revoked grant for {grant.get('GranteePrincipal')}")

    for user, keep in owned["caller_keys"].items():
        for key in pages(iam, "list_access_keys", "AccessKeyMetadata", UserName=user):
            if key["AccessKeyId"] != keep:
                iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"])
                print(f"reconcile: removed extra access key from {user}")
        for group in pages(iam, "list_groups_for_user", "Groups", UserName=user):
            iam.remove_user_from_group(GroupName=group["GroupName"], UserName=user)
            print(f"reconcile: removed {user} from group {group['GroupName']}")

    keep = set(owned["subscriptions"])
    for subscription in pages(sns, "list_subscriptions_by_topic", "Subscriptions", TopicArn=owned["topic"]):
        arn = subscription["SubscriptionArn"]
        if arn.startswith("arn:") and arn not in keep:
            sns.unsubscribe(SubscriptionArn=arn)
            print(f"reconcile: removed subscription to {subscription.get('Endpoint')}")

    queues, functions, mappings = set(owned["queues"]), set(owned["functions"]), set(owned["mappings"])
    for mapping in list(pages(lam, "list_event_source_mappings", "EventSourceMappings")):
        if mapping["UUID"] in mappings:
            continue
        if mapping.get("EventSourceArn") in queues or function_name(mapping.get("FunctionArn")) in functions:
            lookup(lam.delete_event_source_mapping, UUID=mapping["UUID"])
            print(f"reconcile: removed event source mapping {mapping['UUID']}")

    for function in functions:
        # Every version and alias carries its own resource-based policy.
        qualifiers = [None]
        qualifiers += [alias["Name"] for alias in pages(lam, "list_aliases", "Aliases", FunctionName=function)]
        qualifiers += [version["Version"] for version in pages(lam, "list_versions_by_function", "Versions",
                                                               FunctionName=function)
                       if version["Version"] != "$LATEST"]
        for qualifier in qualifiers:
            target = {"FunctionName": function, **({"Qualifier": qualifier} if qualifier else {})}
            found = lookup(lam.get_policy, **target)
            if not found:
                continue
            for statement in json.loads(found["Policy"]).get("Statement", []):
                lam.remove_permission(StatementId=statement["Sid"], **target)
                print(f"reconcile: removed permission {statement['Sid']} from {function}"
                      + (f":{qualifier}" if qualifier else ""))

    # Settings a plan reads but never resets, because the configuration cannot
    # declare their absence: DLQ policies and redrive, and table resource policies.
    sqs, ddb = client("sqs"), client("dynamodb")
    for url in owned["dlq_urls"]:
        attributes = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy", "RedrivePolicy"])["Attributes"]
        stray = {name: "" for name in ("Policy", "RedrivePolicy") if attributes.get(name)}
        if stray:
            sqs.set_queue_attributes(QueueUrl=url, Attributes=stray)
            print(f"reconcile: cleared {', '.join(sorted(stray))} on {url}")
    for table in owned["tables"]:
        arn = ddb.describe_table(TableName=table)["Table"]["TableArn"]
        try:
            ddb.delete_resource_policy(ResourceArn=arn)
            print(f"reconcile: removed the resource policy of {table}")
        except ClientError as error:
            if error.response["Error"]["Code"] not in ("PolicyNotFoundException", "ResourceNotFoundException"):
                raise


def check_state(path):
    """Remove a state file Terraform could not load, so the run adopts instead.

    A run killed while writing state leaves a truncated file, and Terraform then
    refuses every command. The file holds nothing the live deployment does not.
    """
    state = Path(path)
    if not state.is_file():
        return
    try:
        document = json.loads(state.read_text())
        readable = isinstance(document, dict) and "version" in document
    except ValueError:
        readable = False
    if not readable:
        state.unlink()
        print(f"check-state: removed unreadable state {path}")


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("check-state")
    command.add_argument("--path", required=True)
    command = commands.add_parser("rescue")
    command.add_argument("--prefix", required=True)
    command.add_argument("--state-json", required=True)
    command = commands.add_parser("adopt")
    command.add_argument("--prefix", required=True)
    command.add_argument("--state-list", required=True)
    command.add_argument("--out", required=True)
    command.add_argument("--terraform", required=True)
    command.add_argument("--chdir", required=True)
    command.add_argument("--mode", choices=("deploy", "destroy"), required=True)
    command = commands.add_parser("prune-keys")
    command.add_argument("--prefix", required=True)
    command.add_argument("--state-json", required=True)
    command = commands.add_parser("reconcile")
    command.add_argument("--owned", required=True)
    args = parser.parse_args()
    if args.command == "check-state":
        check_state(args.path)
    elif args.command == "rescue":
        rescue(args.prefix, args.state_json)
    elif args.command == "adopt":
        adopt(args.prefix, args.state_list, args.out, args.terraform, args.chdir, args.mode)
    elif args.command == "prune-keys":
        prune_keys(args.prefix, args.state_json)
    else:
        reconcile(args.owned)


if __name__ == "__main__":
    main()
