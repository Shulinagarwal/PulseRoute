"""Black-box PulseRoute verifier (revision 6); no reference Terraform labels are assumed."""

import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import random
import re
import string
import time
import traceback
from urllib.parse import unquote, urlparse
import urllib.request
import uuid

import boto3
from botocore.exceptions import ClientError
from jsonschema import Draft202012Validator

from policy_eval import REQUIRED as KMS_REQUIRED, kms_findings


RUNNER = os.environ.get("PULSEROUTE_RUNNER", "http://runner:8088")
REPORT_DIR = Path("/logs/verifier")
SCHEMA = Path("/contracts/manifest.schema.json")
CONFIG = Path("/workspace/config/bootstrap.json")
SOURCE = Path("/runner/source/submission")
ACCOUNT = "111111111111"
CONSUMERS = ("fulfillment", "analytics")
FUNCTIONS = ("publisher", "fulfillment", "analytics", "replay")
CALLERS = ("publisher", "operator", "outsider")
REGISTRY = "111111111111.dkr.ecr.us-east-1.amazonaws.com"
IMAGES = {
    "publisher": "pulseroute-publisher:2", "fulfillment": "pulseroute-worker:2",
    "analytics": "pulseroute-worker:2", "replay": "pulseroute-replay:2",
}
QUEUE_READ = ("sqs:receivemessage", "sqs:deletemessage", "sqs:getqueueattributes", "sqs:changemessagevisibility")
WORKER_TIMEOUT = 15
# AWS: a queue that triggers Lambda needs a visibility timeout of at least six
# times the function timeout (plus the batching window, if one is set).
VISIBILITY_FACTOR = 6
DATA_KEY_REUSE = 86400
# AWS name length limits for the resources the manifest names.
NAME_LIMITS = {"function": 64, "role": 64, "user": 64, "queue": 80, "table": 255}
WIDE = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": [
    "lambda:InvokeFunction", "sns:Publish", "sqs:*", "dynamodb:*"], "Resource": "*"}]}
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def runner(method, path, payload=None, timeout=30):
    data = json.dumps(payload).encode() if payload is not None else (b"" if method == "POST" else None)
    request = urllib.request.Request(RUNNER + path, method=method, data=data,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def token(length):
    rng = random.SystemRandom()
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(length))


def array(value):
    return value if isinstance(value, list) else [value]


def lowered(values):
    return {str(value).lower() for value in array(values)}


def document(value):
    return json.loads(unquote(value)) if isinstance(value, str) else value


def principals(statement):
    principal = statement.get("Principal")
    if isinstance(principal, dict):
        return {(kind, value) for kind, values in principal.items() for value in array(values)}
    return {("*", str(principal))}


def queue_key(url):
    """Identify a queue independently of the URL host form."""
    parts = [part for part in urlparse(url).path.split("/") if part]
    return tuple(parts[-2:])


def function_name(arn):
    parts = (arn or "").split(":")
    return parts[6] if len(parts) > 6 else arn


def canonical(value):
    """Order-insensitive normal form for JSON documents stored as strings."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return value
    if isinstance(value, dict):
        return tuple(sorted((key, canonical(item)) for key, item in value.items()))
    if isinstance(value, list):
        return tuple(sorted((canonical(item) for item in value), key=repr))
    return value


class Verification:
    def __init__(self):
        self.admin_key = json.loads(CONFIG.read_text())["admin"]
        self.prefix = "pr" + token(5)
        # The longest allowed prefix, nested so that it begins with the name of
        # one of the first deployment's resources.
        self.peer_prefix = f"{self.prefix}-fulfillment-{token(5)}"
        self.results = []
        self.manifest = None
        self.peer = None
        self.peer_snapshot = None
        self.initial_inventory = None
        self.sentinels = None
        self.repair_deployed = False
        self.injected = {}
        self.owners_cache = None
        self.secrets = set()
        self.exposed_secret_files = set()
        self.cleaned = False
        self.peer_attempted = False

    # ----- plumbing -----------------------------------------------------------

    def client(self, service, key=None):
        key = key or self.admin_key
        return boto3.client(service, endpoint_url="http://aws:4566", region_name="us-east-1",
                            aws_access_key_id=key["access_key_id"],
                            aws_secret_access_key=key["secret_access_key"])

    def caller(self, service, m, actor):
        return self.client(service, m["callers"][actor])

    def invoke(self, m, actor, name, event):
        response = self.caller("lambda", m, actor).invoke(
            FunctionName=m["functions"][name], InvocationType="RequestResponse",
            Payload=json.dumps(event).encode())
        result = json.loads(response["Payload"].read())
        assert "FunctionError" not in response, f"{name} Lambda error: {result}"
        return result

    @staticmethod
    def denied(action):
        try:
            action()
        except ClientError as error:
            assert error.response["ResponseMetadata"]["HTTPStatusCode"] == 403
            return
        raise AssertionError("cloud request unexpectedly allowed")

    @staticmethod
    def missing(action):
        try:
            action()
        except ClientError as error:
            code = error.response["Error"]["Code"]
            if code in ("NotFound", "NotFoundException", "ResourceNotFoundException", "NoSuchEntity",
                        "AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"):
                return True
            raise
        return False

    def score(self, name, points, check):
        try:
            check()
            self.results.append({"name": name, "points": points, "earned": points})
            print(f"PASS {name}: {points}/{points}")
        except Exception as error:
            frames = traceback.extract_tb(error.__traceback__)
            source = next((frame for frame in reversed(frames)
                           if Path(frame.filename).name == "verify.py"), None)
            self.results.append({"name": name, "points": points, "earned": 0,
                                 "error": f"{type(error).__name__}: {str(error)[:500]}",
                                 "location": f"verify.py:{source.lineno}" if source else "unknown"})
            print(f"FAIL {name}: {type(error).__name__}: {str(error)[:160]}")

    def run_script(self, action, prefix):
        result = runner("POST", f"/{action}", {"prefix": prefix}, timeout=920)
        if result["exit_code"] != 0:
            output = ANSI.sub("", result["output_tail"])
            REPORT_DIR.mkdir(parents=True, exist_ok=True)
            with open(REPORT_DIR / "script-failures.log", "a") as log:
                log.write(f"=== {action}.sh {prefix} exited {result['exit_code']}\n{output}\n")
            raise AssertionError(f"{action}.sh {prefix} exited {result['exit_code']}: ...{output[-400:]}")

    def deploy(self, prefix):
        self.run_script("deploy", prefix)

    def destroy(self, prefix):
        self.run_script("destroy", prefix)

    def read_manifest(self, prefix):
        manifest = runner("GET", "/manifest")
        Draft202012Validator(json.loads(SCHEMA.read_text())).validate(manifest)
        assert manifest["prefix"] == prefix, "manifest describes another deployment"
        self.secrets.update(caller["secret_access_key"] for caller in manifest["callers"].values())
        return manifest

    def declared_ids(self):
        states = runner("GET", "/state-summary")["states"]
        return {str(entry["id"]) for state in states for entry in state["resources"]}

    def owners(self, refresh=False):
        if refresh or self.owners_cache is None:
            iam, owners = self.client("iam"), {}
            for page in iam.get_paginator("list_users").paginate():
                for user in page["Users"]:
                    for keys in iam.get_paginator("list_access_keys").paginate(UserName=user["UserName"]):
                        for key in keys["AccessKeyMetadata"]:
                            owners[key["AccessKeyId"]] = user["UserName"]
            self.owners_cache = owners
        return self.owners_cache

    def caller_users(self, m):
        owners = self.owners(refresh=True)
        users = {}
        for actor in CALLERS:
            key = m["callers"][actor]["access_key_id"]
            assert key in owners, f"{actor} access key is not an IAM user key"
            users[actor] = owners[key]
        return users

    def role_name(self, m, name):
        conf = self.client("lambda").get_function_configuration(FunctionName=m["functions"][name])
        return conf["Role"].rsplit("/", 1)[-1]

    def queue_attributes(self, url):
        return self.client("sqs").get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]

    def ttl_status(self, table):
        return self.client("dynamodb").describe_time_to_live(TableName=table)["TimeToLiveDescription"]["TimeToLiveStatus"]

    def table_policy(self, table_arn):
        try:
            return self.client("dynamodb").get_resource_policy(ResourceArn=table_arn).get("Policy")
        except ClientError as error:
            if error.response["Error"]["Code"] in ("PolicyNotFoundException", "ResourceNotFoundException"):
                return None
            raise

    def worker_timeout(self, m, consumer):
        return self.client("lambda").get_function_configuration(FunctionName=m["functions"][consumer])["Timeout"]

    def mappings_for_queue(self, arn):
        return [x for page in self.client("lambda").get_paginator("list_event_source_mappings").paginate()
                for x in page["EventSourceMappings"] if x.get("EventSourceArn") == arn]

    def mapping(self, m, consumer, exclusive=True):
        arn = self.queue_attributes(m["queues"][consumer])["QueueArn"]
        matches = self.mappings_for_queue(arn)
        if not exclusive:
            matches = [x for x in matches if function_name(x["FunctionArn"]) == m["functions"][consumer]]
        assert len(matches) == 1, f"expected exactly one mapping for {consumer}, found {len(matches)}"
        return matches[0]

    def topic_subscriptions(self, m):
        return [x for page in self.client("sns").get_paginator("list_subscriptions_by_topic").paginate(
            TopicArn=m["topic"]) for x in page["Subscriptions"]]

    def subscription(self, m, consumer):
        arn = self.queue_attributes(m["queues"][consumer])["QueueArn"]
        matches = [x for x in self.topic_subscriptions(m) if x["Endpoint"] == arn]
        assert len(matches) == 1, f"expected exactly one subscription for {consumer}"
        return matches[0]

    def wait_enabled(self, m, consumer, exclusive=True):
        deadline = time.monotonic() + 30
        while True:
            mapping = self.mapping(m, consumer, exclusive)
            if mapping["State"] == "Enabled" or time.monotonic() > deadline:
                return mapping
            time.sleep(2)

    # ----- inventories and fingerprints ---------------------------------------

    def inventory(self):
        iam, lam, sqs, sns, ddb = (self.client(x) for x in ("iam", "lambda", "sqs", "sns", "dynamodb"))
        users = {x["UserName"] for page in iam.get_paginator("list_users").paginate() for x in page["Users"]}
        return {
            "functions": {f["FunctionName"] for page in lam.get_paginator("list_functions").paginate() for f in page["Functions"]},
            "mappings": {x["UUID"] for page in lam.get_paginator("list_event_source_mappings").paginate() for x in page["EventSourceMappings"]},
            "queues": {q for page in sqs.get_paginator("list_queues").paginate() for q in page.get("QueueUrls", [])},
            "topics": {x["TopicArn"] for page in sns.get_paginator("list_topics").paginate() for x in page["Topics"]},
            "subscriptions": {x["SubscriptionArn"] for page in sns.get_paginator("list_subscriptions").paginate() for x in page["Subscriptions"]},
            "tables": {x for page in ddb.get_paginator("list_tables").paginate() for x in page["TableNames"]},
            "roles": {x["RoleName"] for page in iam.get_paginator("list_roles").paginate() for x in page["Roles"]},
            "users": users,
            "groups": {x["GroupName"] for page in iam.get_paginator("list_groups").paginate() for x in page["Groups"]},
            "policies": {x["Arn"] for page in iam.get_paginator("list_policies").paginate(Scope="Local") for x in page["Policies"]},
            "buckets": {x["Name"] for x in self.client("s3").list_buckets().get("Buckets", [])},
            "access_keys": {k["AccessKeyId"] for user in users
                            for page in iam.get_paginator("list_access_keys").paginate(UserName=user)
                            for k in page["AccessKeyMetadata"]},
            "keys": self.live_keys(),
            "aliases": {a["AliasName"] for page in self.client("kms").get_paginator("list_aliases").paginate()
                        for a in page["Aliases"] if not a["AliasName"].startswith("alias/aws/")},
        }

    def live_keys(self):
        """Customer managed keys that are not scheduled for deletion."""
        kms, keys = self.client("kms"), set()
        for page in kms.get_paginator("list_keys").paginate():
            for key in page["Keys"]:
                meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                if meta.get("KeyManager") == "CUSTOMER" and meta.get("KeyState") != "PendingDeletion":
                    keys.add(key["KeyId"])
        return keys

    def principal_policies(self, kind, name):
        """Identity policy documents of a role or user, including a user's groups."""
        iam = self.client("iam")
        if kind == "role":
            inline = [iam.get_role_policy(RoleName=name, PolicyName=n)["PolicyDocument"]
                      for page in iam.get_paginator("list_role_policies").paginate(RoleName=name) for n in page["PolicyNames"]]
            attached = [x["PolicyArn"] for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=name)
                        for x in page["AttachedPolicies"]]
        else:
            inline = [iam.get_user_policy(UserName=name, PolicyName=n)["PolicyDocument"]
                      for page in iam.get_paginator("list_user_policies").paginate(UserName=name) for n in page["PolicyNames"]]
            attached = [x["PolicyArn"] for page in iam.get_paginator("list_attached_user_policies").paginate(UserName=name)
                        for x in page["AttachedPolicies"]]
            for group in iam.list_groups_for_user(UserName=name)["Groups"]:
                inline += [iam.get_group_policy(GroupName=group["GroupName"], PolicyName=n)["PolicyDocument"]
                           for n in iam.list_group_policies(GroupName=group["GroupName"])["PolicyNames"]]
                attached += [x["PolicyArn"] for x in iam.list_attached_group_policies(GroupName=group["GroupName"])["AttachedPolicies"]]
        documents = [document(x) for x in inline]
        for arn in attached:
            version = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
            documents.append(document(iam.get_policy_version(PolicyArn=arn, VersionId=version)["PolicyVersion"]["Document"]))
        return documents

    def principal_tags(self, kind, name):
        iam = self.client("iam")
        try:
            tags = (iam.list_role_tags(RoleName=name) if kind == "role" else iam.list_user_tags(UserName=name))["Tags"]
        except ClientError:
            return {}
        return {tag["Key"]: tag["Value"] for tag in tags}

    def function_qualifiers(self, function):
        """Versions and aliases of a function; each can carry its own resource-based policy."""
        lamb = self.client("lambda")
        qualifiers = [alias["Name"] for page in lamb.get_paginator("list_aliases").paginate(FunctionName=function)
                      for alias in page["Aliases"]]
        qualifiers += [version["Version"] for page in lamb.get_paginator("list_versions_by_function").paginate(
            FunctionName=function) for version in page["Versions"] if version["Version"] != "$LATEST"]
        return qualifiers

    def function_statements(self, function, qualifier=None):
        options = {"FunctionName": function, **({"Qualifier": qualifier} if qualifier else {})}
        try:
            return json.loads(self.client("lambda").get_policy(**options)["Policy"]).get("Statement", [])
        except ClientError as error:
            assert error.response["Error"]["Code"] == "ResourceNotFoundException"
            return []

    def identities(self, m):
        """Identifiers that adoption and repair must never replace."""
        iam, lam, ddb = self.client("iam"), self.client("lambda"), self.client("dynamodb")
        key = self.client("kms").describe_key(KeyId=m["key"])["KeyMetadata"]
        result = {"topic": m["topic"], "key": (key["Arn"], str(key.get("CreationDate")))}
        for name, function in m["functions"].items():
            conf = lam.get_function_configuration(FunctionName=function)
            role = conf["Role"].rsplit("/", 1)[-1]
            result[f"function:{name}"] = conf["FunctionArn"]
            result[f"role:{name}"] = (role, iam.get_role(RoleName=role)["Role"]["RoleId"])
        for consumer in CONSUMERS:
            result[f"mapping:{consumer}"] = self.mapping(m, consumer, exclusive=False)["UUID"]
            result[f"subscription:{consumer}"] = self.subscription(m, consumer)["SubscriptionArn"]
            table = ddb.describe_table(TableName=m["tables"][consumer])["Table"]
            result[f"table:{consumer}"] = (table["TableArn"], str(table["CreationDateTime"]))
            for kind in ("queues", "dlqs"):
                attributes = self.queue_attributes(m[kind][consumer])
                result[f"{kind}:{consumer}"] = (attributes["QueueArn"], attributes.get("CreatedTimestamp"))
        for actor, user in self.caller_users(m).items():
            result[f"user:{actor}"] = (user, iam.get_user(UserName=user)["User"]["UserId"])
        return result

    def fingerprint(self, m):
        """Identity plus configuration of one deployment; another prefix must leave it untouched."""
        iam, lam, sns, ddb = (self.client(x) for x in ("iam", "lambda", "sns", "dynamodb"))
        result = self.identities(m)
        for name, function in m["functions"].items():
            conf = lam.get_function_configuration(FunctionName=function)
            result[f"environment:{name}"] = canonical(conf.get("Environment", {}).get("Variables", {}))
            result[f"triggers:{name}"] = sorted(
                (x["UUID"], x["EventSourceArn"], x["State"], x.get("BatchSize"))
                for page in lam.get_paginator("list_event_source_mappings").paginate(FunctionName=function)
                for x in page["EventSourceMappings"])
            try:
                result[f"permissions:{name}"] = canonical(lam.get_policy(FunctionName=function)["Policy"])
            except ClientError:
                result[f"permissions:{name}"] = None
            role = conf["Role"].rsplit("/", 1)[-1]
            result[f"role-policies:{name}"] = (
                canonical(iam.get_role(RoleName=role)["Role"]["AssumeRolePolicyDocument"]),
                sorted(n for page in iam.get_paginator("list_role_policies").paginate(RoleName=role) for n in page["PolicyNames"]),
                sorted(x["PolicyArn"] for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role)
                       for x in page["AttachedPolicies"]))
        kms = self.client("kms")
        key = kms.describe_key(KeyId=m["key"])["KeyMetadata"]
        result["key-config"] = (
            key["KeyState"], kms.get_key_rotation_status(KeyId=m["key"])["KeyRotationEnabled"],
            canonical(kms.get_key_policy(KeyId=m["key"], PolicyName="default")["Policy"]),
            sorted(a["AliasName"] for a in kms.list_aliases(KeyId=key["KeyId"])["Aliases"]),
            sorted(g["GrantId"] for g in kms.list_grants(KeyId=m["key"])["Grants"]))
        result["topic-policy"] = canonical(sns.get_topic_attributes(TopicArn=m["topic"])["Attributes"].get("Policy"))
        result["subscriptions"] = sorted(
            (x["SubscriptionArn"], x["Endpoint"],
             canonical(sns.get_subscription_attributes(SubscriptionArn=x["SubscriptionArn"])["Attributes"].get("FilterPolicy")))
            for x in self.topic_subscriptions(m))
        for consumer in CONSUMERS:
            for kind in ("queues", "dlqs"):
                attributes = self.queue_attributes(m[kind][consumer])
                result[f"queue-config:{kind}:{consumer}"] = tuple(canonical(attributes.get(key)) for key in (
                    "VisibilityTimeout", "MessageRetentionPeriod", "RedrivePolicy", "RedriveAllowPolicy", "Policy",
                    "KmsMasterKeyId", "KmsDataKeyReusePeriodSeconds"))
            table = ddb.describe_table(TableName=m["tables"][consumer])["Table"]
            result[f"table-protection:{consumer}"] = (
                table.get("DeletionProtectionEnabled"), self.ttl_status(m["tables"][consumer]),
                canonical(self.table_policy(table["TableArn"])))
        for actor, user in self.caller_users(m).items():
            result[f"caller:{actor}"] = (
                sorted(x["AccessKeyId"] for x in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]),
                sorted(x["GroupName"] for x in iam.list_groups_for_user(UserName=user)["Groups"]),
                sorted(n for page in iam.get_paginator("list_user_policies").paginate(UserName=user) for n in page["PolicyNames"]),
                sorted(x["PolicyArn"] for page in iam.get_paginator("list_attached_user_policies").paginate(UserName=user)
                       for x in page["AttachedPolicies"]))
        return result

    def assert_declared(self, m, ids):
        """Every scored resource is recorded in local state under one of its identifiers.

        An import records whatever identifier it was given: a name or an ARN, a key ID
        or a key ARN, and for queues either URL form (the provider only imports
        https://sqs.<region>.amazonaws.com URLs), so each form counts.
        """
        iam, lamb, ddb = self.client("iam"), self.client("lambda"), self.client("dynamodb")
        declared_queues = {queue_key(value) for value in ids if value.startswith(("http://", "https://"))}

        def recorded(*forms):
            return any(form in ids for form in forms if form)

        key = self.client("kms").describe_key(KeyId=m["key"])["KeyMetadata"]
        missing = [] if recorded(key["KeyId"], key["Arn"]) else [key["KeyId"]]
        if not recorded(m["topic"]):
            missing.append(m["topic"])
        for function in m["functions"].values():
            if not recorded(function, lamb.get_function_configuration(FunctionName=function)["FunctionArn"]):
                missing.append(function)
        for table in m["tables"].values():
            if not recorded(table, ddb.describe_table(TableName=table)["Table"]["TableArn"]):
                missing.append(table)
        for url in [*m["queues"].values(), *m["dlqs"].values()]:
            if not (recorded(url) or queue_key(url) in declared_queues):
                missing.append(url)
        missing += [caller["access_key_id"] for caller in m["callers"].values() if not recorded(caller["access_key_id"])]
        assert not missing, f"live resources missing from declared state: {missing[:4]}"
        for consumer in CONSUMERS:
            assert recorded(self.mapping(m, consumer)["UUID"]), f"{consumer} mapping is not in state"
            assert recorded(self.subscription(m, consumer)["SubscriptionArn"]), f"{consumer} subscription is not in state"
        for name in FUNCTIONS:
            role = self.role_name(m, name)
            assert recorded(role, iam.get_role(RoleName=role)["Role"]["Arn"]), f"{name} execution role is not in state"
        for actor, user in self.caller_users(m).items():
            assert recorded(user, iam.get_user(UserName=user)["User"]["Arn"]), f"{actor} caller user is not in state"

    # ----- events and receipts -----------------------------------------------

    def receipt(self, m, consumer, event):
        return self.client("dynamodb").get_item(
            TableName=m["tables"][consumer],
            Key={"delivery_id": {"S": f"{consumer}:{event['tenant']}:{event['event_id']}"}},
            ConsistentRead=True).get("Item")

    def wait_delivery(self, m, consumer, event, timeout=100):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            item = self.receipt(m, consumer, event)
            if item:
                return item
            time.sleep(1)
        raise AssertionError(f"{consumer} delivery did not complete: {event['tenant']} {event['event_id']}")

    def publish(self, m, **changes):
        event = {"operation": "publish", "event_id": str(uuid.uuid4()),
                 "tenant": "shop-7", "kind": "order.created", "amount": 42}
        event.update(changes)
        response = self.invoke(m, "publisher", "publisher", event)
        assert response == {"status": "published", "event_id": event["event_id"]}
        return event

    def assert_receipt(self, m, consumer, event, replayed=False):
        item = self.wait_delivery(m, consumer, event)
        for field in ("event_id", "tenant", "kind"):
            assert item[field]["S"] == event[field]
        assert item["consumer"]["S"] == consumer
        assert item["amount"]["N"] == str(event["amount"])
        assert item["replayed"]["BOOL"] is replayed
        return item

    # ----- sentinels ----------------------------------------------------------

    def create_sentinels(self):
        """Unrelated resources sharing the first prefix; they must survive every run."""
        p, tag = self.prefix, uuid.uuid4().hex[:6]
        sqs, sns, ddb, iam, lam, s3 = (self.client(x) for x in ("sqs", "sns", "dynamodb", "iam", "lambda", "s3"))
        name = f"{p}-unrelated-{tag}"
        queue = sqs.create_queue(QueueName=name)["QueueUrl"]
        sqs.send_message(QueueUrl=queue, MessageBody=name)
        topic = sns.create_topic(Name=name)["TopicArn"]
        ddb.create_table(TableName=name, BillingMode="PAY_PER_REQUEST",
                         KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                         AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}])
        ddb.get_waiter("table_exists").wait(TableName=name)
        ddb.put_item(TableName=name, Item={"id": {"S": name}})
        s3.create_bucket(Bucket=name)
        s3.put_object(Bucket=name, Key="token", Body=name.encode())
        tap = sqs.create_queue(QueueName=f"{p}-orders-tap-{tag}")["QueueUrl"]
        lookalike = sqs.create_queue(QueueName=f"{p}-fulfillment-{tag}")["QueueUrl"]
        lookalike_arn = self.queue_attributes(lookalike)["QueueArn"]
        role = iam.create_role(RoleName=f"{p}-replay-lambda-{tag}", AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                                                   "Action": "sts:AssumeRole"}]}))["Role"]["Arn"]
        function = f"{p}-replay-{tag}"
        lam.create_function(FunctionName=function, PackageType="Image", Role=role, Timeout=15, MemorySize=256,
                            Code={"ImageUri": f"{REGISTRY}/{IMAGES['replay']}"},
                            Environment={"Variables": {key: lookalike for key in (
                                "FULFILLMENT_QUEUE", "FULFILLMENT_DLQ", "ANALYTICS_QUEUE", "ANALYTICS_DLQ")}})
        deadline = time.monotonic() + 60
        while lam.get_function_configuration(FunctionName=function).get("State") not in ("Active", None):
            assert time.monotonic() < deadline, "sentinel function did not become active"
            time.sleep(1)
        lam.create_event_source_mapping(EventSourceArn=lookalike_arn, FunctionName=function,
                                        BatchSize=5, Enabled=False)
        group = f"{p}-break-glass-{tag}"
        iam.create_group(GroupName=group)
        iam.put_group_policy(GroupName=group, PolicyName="break-glass", PolicyDocument=json.dumps(WIDE))
        policy = iam.create_policy(PolicyName=f"{p}-ops-audit-{tag}", PolicyDocument=json.dumps(WIDE))["Policy"]["Arn"]
        user = f"{p}-operator-{tag}"
        iam.create_user(UserName=user)
        key = iam.create_access_key(UserName=user)["AccessKey"]["AccessKeyId"]
        kms = self.client("kms")
        kms_key = kms.create_key(Description=name)["KeyMetadata"]["KeyId"]
        kms_alias = f"alias/{p}-orders-{tag}"
        kms.create_alias(AliasName=kms_alias, TargetKeyId=kms_key)
        self.sentinels = {"queue": queue, "topic": topic, "table": name, "bucket": name, "token": name,
                          "tap": tap, "tap_arn": self.queue_attributes(tap)["QueueArn"],
                          "group": group, "policy": policy, "user": user, "key": key, "function": function,
                          "kms_key": kms_key, "kms_alias": kms_alias, "kms_config": self.key_config(kms_key)}

    def key_config(self, key):
        kms = self.client("kms")
        return (canonical(kms.get_key_policy(KeyId=key, PolicyName="default")["Policy"]),
                kms.get_key_rotation_status(KeyId=key)["KeyRotationEnabled"],
                sorted(g["GrantId"] for g in kms.list_grants(KeyId=key)["Grants"]),
                kms.describe_key(KeyId=key)["KeyMetadata"].get("Description"))

    def sentinels_intact(self):
        s = self.sentinels
        sqs, iam = self.client("sqs"), self.client("iam")
        self.queue_attributes(s["tap"])
        self.client("sns").get_topic_attributes(TopicArn=s["topic"])
        assert iam.get_group(GroupName=s["group"])["Group"]["GroupName"] == s["group"]
        assert "break-glass" in iam.list_group_policies(GroupName=s["group"])["PolicyNames"]
        iam.get_policy(PolicyArn=s["policy"])
        assert [k["AccessKeyId"] for k in iam.list_access_keys(UserName=s["user"])["AccessKeyMetadata"]] == [s["key"]]
        self.client("lambda").get_function_configuration(FunctionName=s["function"])
        kms = self.client("kms")
        assert kms.describe_key(KeyId=s["kms_key"])["KeyMetadata"]["KeyState"] == "Enabled", "unrelated KMS key was disturbed"
        assert [a["AliasName"] for a in kms.list_aliases(KeyId=s["kms_key"])["Aliases"]] == [s["kms_alias"]], \
            "unrelated KMS alias was disturbed"
        assert self.key_config(s["kms_key"]) == s["kms_config"], "unrelated KMS key was modified"
        assert self.client("dynamodb").get_item(TableName=s["table"], Key={"id": {"S": s["token"]}}).get("Item") \
            == {"id": {"S": s["token"]}}, "unrelated table data lost"
        assert self.client("s3").get_object(Bucket=s["bucket"], Key="token")["Body"].read() == s["token"].encode()
        bodies = [x["Body"] for x in sqs.receive_message(QueueUrl=s["queue"], MaxNumberOfMessages=10,
                                                       VisibilityTimeout=0, WaitTimeSeconds=1).get("Messages", [])]
        assert s["token"] in bodies, "unrelated queue data lost"

    # ----- scored checks: deployment A ----------------------------------------

    def contract_and_state(self):
        self.manifest = self.read_manifest(self.prefix)
        assert (SOURCE / "deploy.sh").is_file() and (SOURCE / "destroy.sh").is_file()
        assert list(SOURCE.rglob("*.tf")) or list(SOURCE.rglob("*.tofu"))
        self.assert_declared(self.manifest, self.declared_ids())

    def topology(self, m):
        topic = self.client("sns").get_topic_attributes(TopicArn=m["topic"])["Attributes"]
        assert topic["TopicArn"] == m["topic"]
        assert len(set(m["tables"].values())) == 2 and len(set(m["functions"].values())) == 4
        kms = self.client("kms")
        key = kms.describe_key(KeyId=m["key"])["KeyMetadata"]
        assert key["Arn"] == m["key"] and key.get("KeyManager") == "CUSTOMER", "the key is not a customer managed key"
        assert key.get("KeySpec", "SYMMETRIC_DEFAULT") == "SYMMETRIC_DEFAULT", "the key is not symmetric"
        assert key["KeyState"] == "Enabled", f"the deployment key is {key['KeyState']}"
        assert kms.get_key_rotation_status(KeyId=m["key"])["KeyRotationEnabled"] is True, "key rotation is off"
        aliases = [a["AliasName"] for a in kms.list_aliases(KeyId=key["KeyId"])["Aliases"]]
        # Any alias that contains the prefix as a whole token, such as alias/<prefix>-key,
        # alias/<prefix>_key or alias/team/<prefix>, is derived from it.
        derived = re.compile(rf"(?<![a-z0-9]){re.escape(m['prefix'])}(?![a-z0-9])")
        assert any(derived.search(a[len("alias/"):]) for a in aliases), \
            f"the key has no alias derived from the prefix: {aliases}"

        def encrypted(value):
            try:
                return bool(value) and kms.describe_key(KeyId=value)["KeyMetadata"]["Arn"] == m["key"]
            except ClientError:
                return False

        assert encrypted(topic.get("KmsMasterKeyId")), "the topic is not encrypted with the deployment key"
        for kind in ("queues", "dlqs"):
            for consumer, url in m[kind].items():
                assert encrypted(self.queue_attributes(url).get("KmsMasterKeyId")), \
                    f"{consumer} {kind[:-1]} is not encrypted with the deployment key"
        ddb = self.client("dynamodb")
        for table in m["tables"].values():
            metadata = ddb.describe_table(TableName=table)["Table"]
            assert metadata["KeySchema"] == [{"AttributeName": "delivery_id", "KeyType": "HASH"}]
            assert {"AttributeName": "delivery_id", "AttributeType": "S"} in metadata["AttributeDefinitions"]
            assert metadata.get("DeletionProtectionEnabled") is True, f"{table} lacks deletion protection"
            recovery = ddb.describe_continuous_backups(TableName=table)["ContinuousBackupsDescription"]
            assert recovery["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"] == "ENABLED", \
                f"{table} lacks point-in-time recovery"
            assert self.ttl_status(table) in ("DISABLED", "DISABLING"), f"{table} lets receipts expire (TTL is on)"
            assert 3 <= len(table) <= NAME_LIMITS["table"], f"table name {table} is not valid in AWS"
        for kind in ("queues", "dlqs"):
            for url in m[kind].values():
                assert len(queue_key(url)[-1]) <= NAME_LIMITS["queue"], f"queue name {queue_key(url)[-1]} is too long for AWS"
        for actor, user in self.caller_users(m).items():
            assert len(user) <= NAME_LIMITS["user"], f"{actor} user name {user} is too long for AWS"
        roles = set()
        for name, image in IMAGES.items():
            function = self.client("lambda").get_function(FunctionName=m["functions"][name])
            conf = function["Configuration"]
            assert conf["PackageType"] == "Image"
            assert function["Code"]["ImageUri"].endswith(image)
            assert conf["MemorySize"] >= 256, f"{name} has less than 256 MiB of memory"
            if name in CONSUMERS:
                assert conf["Timeout"] == WORKER_TIMEOUT, f"{name} times out after {conf['Timeout']}s, not {WORKER_TIMEOUT}s"
            else:
                assert conf["Timeout"] >= 15, f"{name} times out after less than 15s"
            assert len(conf["FunctionName"]) <= NAME_LIMITS["function"], f"function name {conf['FunctionName']} is too long"
            assert len(conf["Role"].rsplit("/", 1)[-1]) <= NAME_LIMITS["role"], f"{name} role name is too long for AWS"
            roles.add(conf["Role"])
            variables = conf["Environment"]["Variables"]
            if name == "publisher":
                assert variables["TOPIC_ARN"] == m["topic"]
            elif name in CONSUMERS:
                assert variables["CONSUMER"] == name and variables["DELIVERIES_TABLE"] == m["tables"][name]
            else:
                for consumer in CONSUMERS:
                    upper = consumer.upper()
                    assert queue_key(variables[f"{upper}_QUEUE"]) == queue_key(m["queues"][consumer])
                    assert queue_key(variables[f"{upper}_DLQ"]) == queue_key(m["dlqs"][consumer])
        assert len(roles) == 4

    def routing_and_queues(self, m, exclusive=True):
        queues = [*m["queues"].values(), *m["dlqs"].values()]
        assert len({queue_key(q) for q in queues}) == 4
        sns = self.client("sns")
        main_arns = {}
        for consumer in CONSUMERS:
            main = self.queue_attributes(m["queues"][consumer])
            dlq = self.queue_attributes(m["dlqs"][consumer])
            main_arns[consumer] = main["QueueArn"]
            assert main.get("FifoQueue", "false") == "false" and dlq.get("FifoQueue", "false") == "false"
            assert int(dlq["MessageRetentionPeriod"]) == 1209600
            # Standard-queue messages expire by their original enqueue time, even
            # in the DLQ: 14 days of DLQ retention minus an 8-day replay window.
            assert int(main["MessageRetentionPeriod"]) == 518400, \
                f"{consumer} main queue retention {main['MessageRetentionPeriod']}s breaks or underuses the replay window"
            redrive = json.loads(main.get("RedrivePolicy") or "{}")
            assert redrive.get("deadLetterTargetArn") == dlq["QueueArn"], f"{consumer} redrive policy is wrong"
            assert int(redrive["maxReceiveCount"]) in (2, 3)
            allow = json.loads(dlq.get("RedriveAllowPolicy") or "{}")
            assert allow.get("redrivePermission") == "byQueue", f"{consumer} DLQ redrive allow policy is wrong"
            assert array(allow.get("sourceQueueArns", [])) == [main["QueueArn"]]
            # Without a redrive allow policy SQS lets any queue in the account dead-letter into a queue.
            assert json.loads(main.get("RedriveAllowPolicy") or "{}").get("redrivePermission") == "denyAll", \
                f"{consumer} main queue can serve as another queue's dead-letter queue"
            assert not dlq.get("RedrivePolicy"), f"{consumer} DLQ redrives elsewhere"
            assert not [x for x in array(document(dlq.get("Policy") or "{}").get("Statement", []))
                        if x.get("Effect") == "Allow"], f"{consumer} DLQ has a queue policy"
            for kind, attributes in (("main queue", main), ("DLQ", dlq)):
                assert int(attributes.get("KmsDataKeyReusePeriodSeconds") or 300) == DATA_KEY_REUSE, \
                    f"{consumer} {kind} reuses data keys for {attributes.get('KmsDataKeyReusePeriodSeconds')}s"
            assert not self.mappings_for_queue(dlq["QueueArn"]), "a DLQ has an event source mapping"
            sub = self.subscription(m, consumer)
            assert sub["Protocol"] == "sqs" and sub["SubscriptionArn"] != "PendingConfirmation"
            attrs = sns.get_subscription_attributes(SubscriptionArn=sub["SubscriptionArn"])["Attributes"]
            assert attrs["RawMessageDelivery"].lower() == "true"
            assert attrs.get("FilterPolicyScope") == "MessageBody"
            assert json.loads(attrs["FilterPolicy"]), "missing filter"
            mapping = self.wait_enabled(m, consumer, exclusive)
            assert mapping["FunctionArn"].endswith(":function:" + m["functions"][consumer])
            assert mapping["State"] == "Enabled"
            assert 5 <= mapping["BatchSize"] <= 10
            assert "ReportBatchItemFailures" in mapping.get("FunctionResponseTypes", [])
            timeout = self.worker_timeout(m, consumer)
            window = int(mapping.get("MaximumBatchingWindowInSeconds") or 0)
            visibility = int(main["VisibilityTimeout"])
            assert visibility in {VISIBILITY_FACTOR * timeout, VISIBILITY_FACTOR * timeout + window}, \
                f"{consumer} main queue visibility {visibility}s is not what AWS recommends for its {timeout}s worker"
            ceiling = (mapping.get("ScalingConfig") or {}).get("MaximumConcurrency")
            assert ceiling in (2, 3), f"{consumer} mapping does not cap concurrent batches at 3"
            reserved = self.client("lambda").get_function_concurrency(
                FunctionName=m["functions"][consumer]).get("ReservedConcurrentExecutions")
            assert reserved is None or reserved >= ceiling, f"{consumer} reserved concurrency would throttle its batches"
            allows = [x for x in array(json.loads(main["Policy"])["Statement"]) if x["Effect"] == "Allow"]
            assert allows, "SNS queue grant missing"
            for statement in allows:
                assert principals(statement) == {("Service", "sns.amazonaws.com")}, "queue grants another principal"
                assert lowered(statement["Action"]) == {"sqs:sendmessage"}
                assert array(statement["Resource"]) == [main["QueueArn"]]
                conditions = {op.lower(): {k.lower(): v for k, v in block.items()}
                              for op, block in statement.get("Condition", {}).items()}
                sources = [values for op in ("arnequals", "arnlike", "stringequals", "stringlike")
                           for key, values in conditions.get(op, {}).items() if key == "aws:sourcearn"]
                assert sources and all(array(values) == [m["topic"]] for values in sources), \
                    "queue permits an unrelated source"
        if exclusive:
            endpoints = sorted(x["Endpoint"] for x in self.topic_subscriptions(m))
            assert endpoints == sorted(main_arns.values()), "topic has subscriptions beyond the two queues"
        publisher_role = self.client("lambda").get_function_configuration(
            FunctionName=m["functions"]["publisher"])["Role"]
        topic_policy = document(sns.get_topic_attributes(TopicArn=m["topic"])["Attributes"].get("Policy") or "{}")
        allows = [x for x in array(topic_policy.get("Statement", [])) if x.get("Effect") == "Allow"]
        assert allows, "topic policy does not grant the Publisher role"
        for statement in allows:
            assert principals(statement) == {("AWS", publisher_role)}, "topic policy grants another principal"
            assert lowered(statement["Action"]) == {"sns:publish"}, "topic policy grants extra actions"
            assert array(statement["Resource"]) == [m["topic"]]

    def selective_delivery(self, m):
        # Boundary and exclusion cases are generated afresh for every verification.
        suffix = uuid.uuid4().hex[:8]
        cases = [
            ("shop-" + suffix, 0, "order.created", {"analytics"}),
            ("shop-" + suffix, 1, "order.created", {"fulfillment", "analytics"}),
            ("shop-" + suffix, 500000, "order.cancelled", {"fulfillment", "analytics"}),
            ("shop-" + suffix, 500001, "order.created", {"analytics"}),
            ("lab-" + suffix, 42, "order.created", {"analytics"}),
            ("lab-" + suffix, 1000000, "order.cancelled", {"analytics"}),
            ("other-" + suffix, 42, "order.created", set()),
            ("shopper-" + suffix, 42, "order.created", set()),
        ]
        events = [(self.publish(m, tenant=t, amount=a, kind=k), expected) for t, a, k, expected in cases]
        # Native SNS probes cover source/kind exclusions the fixed API never emits.
        for source, kind in (("unrelated.orders", "order.created"), ("pulseroute.orders", "order.unknown")):
            event = {"event_id": str(uuid.uuid4()), "tenant": "shop-" + suffix, "kind": kind, "amount": 42}
            self.client("sns").publish(TopicArn=m["topic"], Message=json.dumps(
                {"source": source, "detail-type": kind, "detail": event}))
            events.append((event, set()))
        for event, expected in events:
            for consumer in expected:
                self.assert_receipt(m, consumer, event)
        # Check absent receipts throughout a bounded observation interval.
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            for event, expected in events:
                for consumer in set(CONSUMERS) - expected:
                    assert not self.receipt(m, consumer, event), f"filter leaked to {consumer}: {event}"
            time.sleep(1)

    def idempotency(self, m):
        event = self.publish(m)
        before = {c: self.assert_receipt(m, c, event) for c in CONSUMERS}
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(self.publish, m, event_id=event["event_id"], amount=99) for _ in range(4)]
            for future in futures:
                future.result()
        second = self.publish(m, event_id=event["event_id"], tenant="shop-other", amount=77)
        for consumer in before:
            self.assert_receipt(m, consumer, second)
        time.sleep(8)
        for consumer, original in before.items():
            assert self.receipt(m, consumer, event) == original, "duplicate replaced an original receipt"

    def caller_isolation(self, m):
        assert len({x["access_key_id"] for x in m["callers"].values()}) == 3
        users = self.caller_users(m)
        assert len(set(users.values())) == 3
        probe = {"operation": "publish", "event_id": str(uuid.uuid4()),
                 "tenant": "shop-probe", "kind": "order.created", "amount": 42}
        iam = self.client("iam")
        for actor, allowed in (("publisher", "publisher"), ("operator", "replay"), ("outsider", None)):
            username = users[actor]
            keys = [k["AccessKeyId"] for k in iam.list_access_keys(UserName=username)["AccessKeyMetadata"]]
            assert keys == [m["callers"][actor]["access_key_id"]], f"{actor} must hold exactly the manifest key"
            policies = [iam.get_user_policy(UserName=username, PolicyName=n)["PolicyDocument"]
                        for page in iam.get_paginator("list_user_policies").paginate(UserName=username)
                        for n in page["PolicyNames"]]
            for page in iam.get_paginator("list_attached_user_policies").paginate(UserName=username):
                for attached in page["AttachedPolicies"]:
                    arn = attached["PolicyArn"]
                    version = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
                    policies.append(iam.get_policy_version(PolicyArn=arn, VersionId=version)["PolicyVersion"]["Document"])
            assert not iam.list_groups_for_user(UserName=username)["Groups"], "caller group grants are not permitted"
            for policy in policies:
                for statement in array(document(policy)["Statement"]):
                    if statement["Effect"] != "Allow":
                        continue
                    assert allowed is not None, "outsider has an Allow grant"
                    assert "NotAction" not in statement and "NotResource" not in statement
                    assert lowered(statement["Action"]) == {"lambda:invokefunction"}, f"{actor} has extra actions"
                    expected_arn = self.client("lambda").get_function_configuration(
                        FunctionName=m["functions"][allowed])["FunctionArn"]
                    assert array(statement["Resource"]) == [expected_arn], f"{actor} grant is not exact"
            for function in m["functions"]:
                if function != allowed:
                    self.denied(lambda: self.invoke(m, actor, function, probe))
            self.denied(lambda: self.caller("sns", m, actor).publish(TopicArn=m["topic"], Message="{}"))
            for queue in [*m["queues"].values(), *m["dlqs"].values()]:
                self.denied(lambda: self.caller("sqs", m, actor).send_message(QueueUrl=queue, MessageBody="{}"))
                self.denied(lambda: self.caller("sqs", m, actor).receive_message(QueueUrl=queue, WaitTimeSeconds=0))
            for table in m["tables"].values():
                self.denied(lambda: self.caller("dynamodb", m, actor).put_item(
                    TableName=table, Item={"delivery_id": {"S": "forged"}}))
                self.denied(lambda: self.caller("dynamodb", m, actor).get_item(
                    TableName=table, Key={"delivery_id": {"S": "forged"}}))

    def execution_roles(self, m):
        iam = self.client("iam")
        main = {c: self.queue_attributes(q)["QueueArn"] for c, q in m["queues"].items()}
        dlqs = {self.queue_attributes(q)["QueueArn"] for q in m["dlqs"].values()}
        for name, function in m["functions"].items():
            role = self.role_name(m, name)
            trust = document(iam.get_role(RoleName=role)["Role"]["AssumeRolePolicyDocument"])
            trust_allows = [x for x in array(trust["Statement"]) if x["Effect"] == "Allow"]
            assert trust_allows
            for statement in trust_allows:
                assert principals(statement) == {("Service", "lambda.amazonaws.com")}, f"{name} trust is too broad"
                assert lowered(statement["Action"]) == {"sts:assumerole"}
            if name == "publisher":
                allowed = {"sns:publish": {f"arn:aws:sns:us-east-1:{ACCOUNT}:*"}}
            elif name == "replay":
                allowed = {action: dlqs for action in QUEUE_READ}
                allowed["sqs:sendmessage"] = set(main.values())
            else:
                allowed = {action: {main[name]} for action in QUEUE_READ}
                allowed["dynamodb:putitem"] = {self.client("dynamodb").describe_table(
                    TableName=m["tables"][name])["Table"]["TableArn"]}
            for action in KMS_REQUIRED[name]:
                allowed[action.lower()] = {m["key"]}
            logs = f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:/aws/lambda/{function}"
            for action in ("logs:createloggroup", "logs:createlogstream", "logs:putlogevents"):
                allowed[action] = {logs, logs + ":*", logs + ":log-stream:*"}
            policies = [iam.get_role_policy(RoleName=role, PolicyName=n)["PolicyDocument"]
                        for page in iam.get_paginator("list_role_policies").paginate(RoleName=role)
                        for n in page["PolicyNames"]]
            for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role):
                for attached in page["AttachedPolicies"]:
                    arn = attached["PolicyArn"]
                    version = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
                    policies.append(iam.get_policy_version(PolicyArn=arn, VersionId=version)["PolicyVersion"]["Document"])
            assert policies, f"{name} has no permissions"
            for policy in policies:
                for statement in array(document(policy)["Statement"]):
                    if statement["Effect"] != "Allow":
                        continue
                    assert "NotAction" not in statement and "NotResource" not in statement
                    for action in lowered(statement["Action"]):
                        assert action in allowed, f"excess {name} action: {action}"
                        assert set(array(statement["Resource"])) <= allowed[action], f"excess {name} resource for {action}"

    def encryption(self, m):
        """KMS least privilege, evaluated the way AWS would for each request in the flow."""
        kms, iam = self.client("kms"), self.client("iam")
        key_policy = kms.get_key_policy(KeyId=m["key"], PolicyName="default")["Policy"]
        roles = {}
        for name in FUNCTIONS:
            role = self.role_name(m, name)
            roles[name] = (iam.get_role(RoleName=role)["Role"]["Arn"], self.principal_policies("role", role),
                           self.principal_tags("role", role))
        callers = {actor: (iam.get_user(UserName=user)["User"]["Arn"], self.principal_policies("user", user),
                           self.principal_tags("user", user))
                   for actor, user in self.caller_users(m).items()}
        admin = (iam.get_user(UserName="pulseroute-admin")["User"]["Arn"], self.principal_policies("user", "pulseroute-admin"),
                 self.principal_tags("user", "pulseroute-admin"))
        grants = kms.list_grants(KeyId=m["key"])["Grants"]
        queue_arns = [self.queue_attributes(m["queues"][c])["QueueArn"] for c in CONSUMERS]
        findings = kms_findings(m["key"], key_policy, m["topic"], queue_arns, roles, callers, admin, grants)
        assert not findings, "; ".join(findings[:4])

    def wait_dlq(self, m, consumer, minimum):
        # Floci's pollers retry a failed record about every 51 seconds whatever the
        # visibility timeout, so three receives take about 155 seconds.
        deadline = time.monotonic() + 420
        while time.monotonic() < deadline:
            attrs = self.queue_attributes(m["dlqs"][consumer])
            if int(attrs.get("ApproximateNumberOfMessages", 0)) >= minimum:
                return
            time.sleep(2)
        raise AssertionError(f"{consumer} poison messages did not reach DLQ")

    def poison_and_replay(self, m):
        # Pause both mappings so poison and healthy messages enter a real backlog.
        lamb = self.client("lambda")
        mappings = {c: self.mapping(m, c)["UUID"] for c in CONSUMERS}
        for mapping in mappings.values():
            lamb.update_event_source_mapping(UUID=mapping, Enabled=False)
        poison = {}
        healthy = []
        try:
            for consumer in mappings:
                poison[consumer] = self.publish(m, fail_consumer=consumer, kind="order.cancelled")
            healthy = [self.publish(m, amount=n + 101) for n in range(6)]
        finally:
            for mapping in mappings.values():
                lamb.update_event_source_mapping(UUID=mapping, Enabled=True)
        peer_receipts = {}
        for consumer, event in poison.items():
            other = "analytics" if consumer == "fulfillment" else "fulfillment"
            peer_receipts[consumer] = self.assert_receipt(m, other, event)
        for event in healthy:
            for consumer in mappings:
                self.assert_receipt(m, consumer, event)
        for consumer, event in poison.items():
            self.wait_dlq(m, consumer, 1)
            assert not self.receipt(m, consumer, event), "poison committed before replay"
        for consumer, event in poison.items():
            deadline = time.monotonic() + 50
            count = 0
            while time.monotonic() < deadline and not self.receipt(m, consumer, event):
                response = self.invoke(m, "operator", "replay", {"operation": "replay", "consumer": consumer, "limit": 1})
                assert response["status"] == "replayed" and response["consumer"] == consumer
                assert response["count"] in (0, 1)
                count += response["count"]
                time.sleep(1)
            assert count >= 1
            self.assert_receipt(m, consumer, event, replayed=True)
            if consumer == "fulfillment":
                assert not self.receipt(m, "analytics", poison["analytics"]), "replay crossed lanes"
            other = "analytics" if consumer == "fulfillment" else "fulfillment"
            assert self.receipt(m, other, event) == peer_receipts[consumer]
            response = self.invoke(m, "operator", "replay", {"operation": "replay", "consumer": consumer, "limit": 10})
            assert response["count"] == 0, "replay left extra messages (possibly healthy batch members)"
            attrs = self.queue_attributes(m["dlqs"][consumer])
            assert int(attrs.get("ApproximateNumberOfMessages", 0)) == 0
            assert int(attrs.get("ApproximateNumberOfMessagesNotVisible", 0)) == 0

    # ----- scored checks: lifecycle -------------------------------------------

    def independent_deployments(self):
        a = self.manifest
        before = self.fingerprint(a)
        self.peer_attempted = True
        self.deploy(self.peer_prefix)
        b = self.peer = self.read_manifest(self.peer_prefix)
        assert a["topic"] != b["topic"]
        for group in ("functions", "tables"):
            assert not set(a[group].values()) & set(b[group].values()), f"deployments share {group}"
        assert not {queue_key(q) for g in ("queues", "dlqs") for q in a[g].values()} \
            & {queue_key(q) for g in ("queues", "dlqs") for q in b[g].values()}, "deployments share queues"
        assert not set(self.caller_users(a).values()) & set(self.caller_users(b).values()), "deployments share callers"
        assert not {self.role_name(a, n) for n in FUNCTIONS} & {self.role_name(b, n) for n in FUNCTIONS}
        ids = self.declared_ids()
        self.assert_declared(a, ids)
        self.assert_declared(b, ids)
        self.topology(b)
        self.routing_and_queues(b)
        event = self.publish(b)
        for consumer in CONSUMERS:
            self.assert_receipt(b, consumer, event)
        own = self.publish(a, amount=43)
        for consumer in CONSUMERS:
            self.assert_receipt(a, consumer, own)
            assert not self.receipt(a, consumer, event), "events crossed deployments"
            assert not self.receipt(b, consumer, own), "events crossed deployments"
        assert self.fingerprint(a) == before, "deploying another prefix changed this deployment"

    def lossless_repair(self):
        m = self.manifest
        baseline = self.publish(m)
        before = {c: self.assert_receipt(m, c, baseline) for c in CONSUMERS}
        original = copy.deepcopy(m)
        inventory = self.inventory()
        identities = self.identities(m)
        self.deploy(self.prefix)
        assert self.read_manifest(self.prefix) == original, "repeat changed identities or credentials"
        assert self.inventory() == inventory, "repeat created or deleted resources"
        assert self.identities(m) == identities, "repeat replaced resources"
        if self.peer:
            self.peer_snapshot = self.fingerprint(self.peer)

        lamb, sns, sqs, iam, ddb = (self.client(x) for x in ("lambda", "sns", "sqs", "iam", "dynamodb"))
        roles = {name: self.role_name(m, name) for name in FUNCTIONS}
        users = self.caller_users(m)
        outsider = iam.get_user(UserName=users["outsider"])["User"]["Arn"]
        fulfillment_queue = self.queue_attributes(m["queues"]["fulfillment"])

        # Destructive drift, with a backlog published while Analytics is disconnected.
        lamb.delete_event_source_mapping(UUID=self.mapping(m, "analytics")["UUID"])
        backlog = [self.publish(m, amount=201 + n) for n in range(3)]
        for event in backlog:
            self.assert_receipt(m, "fulfillment", event)
        sns.unsubscribe(SubscriptionArn=self.subscription(m, "analytics")["SubscriptionArn"])
        subscription = self.subscription(m, "fulfillment")["SubscriptionArn"]
        sns.set_subscription_attributes(SubscriptionArn=subscription, AttributeName="FilterPolicy",
                                        AttributeValue=json.dumps({"source": ["never-match"]}))
        sns.set_subscription_attributes(SubscriptionArn=subscription, AttributeName="RawMessageDelivery",
                                        AttributeValue="false")
        lamb.update_event_source_mapping(UUID=self.mapping(m, "fulfillment")["UUID"], BatchSize=1, Enabled=False)
        conf = lamb.get_function_configuration(FunctionName=m["functions"]["fulfillment"])
        variables = conf["Environment"]["Variables"].copy()
        variables["DELIVERIES_TABLE"] = m["tables"]["analytics"]
        lamb.update_function_configuration(FunctionName=m["functions"]["fulfillment"],
                                           Environment={"Variables": variables})
        sqs.set_queue_attributes(QueueUrl=m["queues"]["analytics"], Attributes={"RedrivePolicy": ""})
        sqs.set_queue_attributes(QueueUrl=m["dlqs"]["fulfillment"], Attributes={"RedriveAllowPolicy": ""})
        ddb.update_table(TableName=m["tables"]["fulfillment"], DeletionProtectionEnabled=False)
        lamb.delete_function(FunctionName=m["functions"]["replay"])

        # Settings that a plan only resets when the configuration declares them.
        analytics_dlq = self.queue_attributes(m["dlqs"]["analytics"])["QueueArn"]
        sqs.set_queue_attributes(QueueUrl=m["dlqs"]["analytics"], Attributes={"Policy": json.dumps({
            "Version": "2012-10-17", "Statement": [{"Sid": "OpsTap", "Effect": "Allow", "Principal": "*",
                                                   "Action": ["sqs:SendMessage", "sqs:ReceiveMessage"],
                                                   "Resource": analytics_dlq}]})})
        sqs.set_queue_attributes(QueueUrl=m["dlqs"]["fulfillment"], Attributes={"RedrivePolicy": json.dumps(
            {"deadLetterTargetArn": self.sentinels["tap_arn"], "maxReceiveCount": 1})})
        sqs.set_queue_attributes(QueueUrl=m["queues"]["analytics"], Attributes={
            "RedriveAllowPolicy": json.dumps({"redrivePermission": "allowAll"}), "KmsDataKeyReusePeriodSeconds": "300"})
        ddb.update_time_to_live(TableName=m["tables"]["analytics"],
                                TimeToLiveSpecification={"Enabled": True, "AttributeName": "processed_at"})

        # Out-of-band additions that no declared attribute describes.
        self.injected = {"roles": roles, "users": users}
        iam.put_role_policy(RoleName=roles["fulfillment"], PolicyName="ops-debug", PolicyDocument=json.dumps(WIDE))
        iam.attach_role_policy(RoleName=roles["replay"], PolicyArn=self.sentinels["policy"])
        iam.put_user_policy(UserName=users["publisher"], PolicyName="ops-debug", PolicyDocument=json.dumps(WIDE))
        iam.attach_user_policy(UserName=users["operator"], PolicyArn=self.sentinels["policy"])
        self.injected["key"] = iam.create_access_key(UserName=users["operator"])["AccessKey"]["AccessKeyId"]
        iam.add_user_to_group(GroupName=self.sentinels["group"], UserName=users["outsider"])
        self.injected["subscription"] = sns.subscribe(
            TopicArn=m["topic"], Protocol="sqs", Endpoint=self.sentinels["tap_arn"],
            Attributes={"RawMessageDelivery": "true"}, ReturnSubscriptionArn=True)["SubscriptionArn"]
        self.injected["mapping"] = lamb.create_event_source_mapping(
            EventSourceArn=fulfillment_queue["QueueArn"], FunctionName=m["functions"]["analytics"],
            BatchSize=5, Enabled=False)["UUID"]
        lamb.add_permission(FunctionName=m["functions"]["publisher"], StatementId="ops-break-glass",
                            Action="lambda:InvokeFunction", Principal=outsider)
        sns.set_topic_attributes(TopicArn=m["topic"], AttributeName="Policy", AttributeValue=json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*",
                                                   "Action": "sns:Publish", "Resource": m["topic"]}]}))
        policy = json.loads(fulfillment_queue["Policy"])
        policy["Statement"] = array(policy["Statement"]) + [{
            "Sid": "OpsRead", "Effect": "Allow", "Principal": "*",
            "Action": "sqs:ReceiveMessage", "Resource": fulfillment_queue["QueueArn"]}]
        sqs.set_queue_attributes(QueueUrl=m["queues"]["fulfillment"], Attributes={"Policy": json.dumps(policy)})
        trust = document(iam.get_role(RoleName=roles["analytics"])["Role"]["AssumeRolePolicyDocument"])
        trust["Statement"] = array(trust["Statement"]) + [
            {"Effect": "Allow", "Principal": {"AWS": outsider}, "Action": "sts:AssumeRole"}]
        iam.update_assume_role_policy(RoleName=roles["analytics"], PolicyDocument=json.dumps(trust))
        # Additions behind function qualifiers: a version and an alias of the
        # Publisher that the outsider may invoke, and a mapping from an
        # unrelated queue into an alias of the Analytics worker.
        publisher = m["functions"]["publisher"]
        version = lamb.publish_version(FunctionName=publisher)["Version"]
        lamb.create_alias(FunctionName=publisher, Name="ops", FunctionVersion=version)
        lamb.add_permission(FunctionName=publisher, Qualifier="ops", StatementId="ops-alias",
                            Action="lambda:InvokeFunction", Principal=outsider)
        lamb.add_permission(FunctionName=publisher, Qualifier=version, StatementId="ops-version",
                            Action="lambda:InvokeFunction", Principal=outsider)
        analytics = m["functions"]["analytics"]
        lamb.create_alias(FunctionName=analytics, Name="ops",
                          FunctionVersion=lamb.publish_version(FunctionName=analytics)["Version"])
        self.injected["qualified"] = {"publisher": publisher, "version": version}
        self.injected["alias_mapping"] = lamb.create_event_source_mapping(
            EventSourceArn=self.sentinels["tap_arn"], FunctionName=f"{analytics}:ops", BatchSize=5, Enabled=False)["UUID"]
        ledger = ddb.describe_table(TableName=m["tables"]["fulfillment"])["Table"]["TableArn"]
        ddb.put_resource_policy(ResourceArn=ledger, Policy=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Sid": "OpsRead", "Effect": "Allow", "Principal": {"AWS": outsider},
             "Action": "dynamodb:GetItem", "Resource": ledger}]}))
        self.injected["table_policy"] = ledger

        # KMS drift: key-policy and grant access for the outsider, rotation off, an
        # unencrypted DLQ, the alias re-pointed at an unrelated key, and last (AWS
        # rejects changes to a doomed key) the key itself scheduled for deletion.
        kms = self.client("kms")
        key_id = kms.describe_key(KeyId=m["key"])["KeyMetadata"]["KeyId"]
        for alias in kms.list_aliases(KeyId=key_id)["Aliases"]:
            kms.update_alias(AliasName=alias["AliasName"], TargetKeyId=self.sentinels["kms_key"])
        key_policy = document(kms.get_key_policy(KeyId=m["key"], PolicyName="default")["Policy"])
        key_policy["Statement"] = array(key_policy["Statement"]) + [
            {"Sid": "OpsBreakGlass", "Effect": "Allow", "Principal": {"AWS": outsider},
             "Action": "kms:Decrypt", "Resource": "*"}]
        kms.put_key_policy(KeyId=m["key"], PolicyName="default", Policy=json.dumps(key_policy))
        self.injected["grant"] = kms.create_grant(KeyId=m["key"], GranteePrincipal=outsider,
                                                  Operations=["Decrypt"])["GrantId"]
        kms.disable_key_rotation(KeyId=m["key"])
        sqs.set_queue_attributes(QueueUrl=m["dlqs"]["analytics"], Attributes={"KmsMasterKeyId": ""})
        kms.schedule_key_deletion(KeyId=m["key"], PendingWindowInDays=7)

        self.deploy(self.prefix)
        self.repair_deployed = True
        self.manifest = self.read_manifest(self.prefix)
        assert self.manifest == original, "repair replaced identities, credentials or the KMS key"
        self.topology(m)
        self.routing_and_queues(m, exclusive=False)
        for consumer, receipt in before.items():
            assert self.receipt(m, consumer, baseline) == receipt
        for event in backlog:
            self.assert_receipt(m, "analytics", event)
        response = self.invoke(m, "operator", "replay", {"operation": "replay", "consumer": "fulfillment", "limit": 1})
        assert response["status"] == "replayed" and response["count"] == 0
        self.selective_delivery(m)

    def addition_convergence(self):
        assert self.repair_deployed, "repair deployment did not complete"
        m = self.manifest
        # The additions themselves first, then the policies they could have widened.
        lamb = self.client("lambda")
        queue_arns = {c: self.queue_attributes(m["queues"][c])["QueueArn"] for c in CONSUMERS}
        mappings = [x for page in lamb.get_paginator("list_event_source_mappings").paginate()
                    for x in page["EventSourceMappings"]]
        for name, function in m["functions"].items():
            # A mapping into any version or alias of a function invokes that function.
            sources = sorted(x["EventSourceArn"] for x in mappings if function_name(x.get("FunctionArn")) == function)
            expected = [queue_arns[name]] if name in CONSUMERS else []
            assert sources == expected, f"{name} has undeclared event source mappings: {sources}"
            for qualifier in (None, *self.function_qualifiers(function)):
                assert not self.function_statements(function, qualifier), \
                    f"{name}{':' + qualifier if qualifier else ''} has resource-based policy statements"
        ddb = self.client("dynamodb")
        for consumer, table in m["tables"].items():
            arn = ddb.describe_table(TableName=table)["Table"]["TableArn"]
            assert self.table_policy(arn) is None, f"{consumer} table has a resource-based policy"
        self.routing_and_queues(m)
        self.execution_roles(m)
        self.caller_isolation(m)
        self.encryption(m)
        self.sentinels_intact()
        if self.peer:
            assert self.fingerprint(self.peer) == self.peer_snapshot, "repairing one deployment changed another"

    def tidy_injections(self):
        """Undo injected additions a submission left behind, so later phases are scored on their own."""
        if not self.injected:
            return
        iam, lamb, sns = self.client("iam"), self.client("lambda"), self.client("sns")
        roles, users, policy = self.injected["roles"], self.injected["users"], self.sentinels["policy"]
        for undo in (
            lambda: iam.delete_role_policy(RoleName=roles["fulfillment"], PolicyName="ops-debug"),
            lambda: iam.detach_role_policy(RoleName=roles["replay"], PolicyArn=policy),
            lambda: iam.delete_user_policy(UserName=users["publisher"], PolicyName="ops-debug"),
            lambda: iam.detach_user_policy(UserName=users["operator"], PolicyArn=policy),
            lambda: iam.delete_access_key(UserName=users["operator"], AccessKeyId=self.injected["key"]),
            lambda: iam.remove_user_from_group(GroupName=self.sentinels["group"], UserName=users["outsider"]),
            lambda: sns.unsubscribe(SubscriptionArn=self.injected["subscription"]),
            lambda: lamb.delete_event_source_mapping(UUID=self.injected["mapping"]),
            lambda: lamb.remove_permission(FunctionName=self.manifest["functions"]["publisher"],
                                           StatementId="ops-break-glass"),
            lambda: self.client("kms").revoke_grant(KeyId=self.manifest["key"], GrantId=self.injected["grant"]),
            lambda: self.client("dynamodb").delete_resource_policy(ResourceArn=self.injected["table_policy"]),
            lambda: lamb.delete_event_source_mapping(UUID=self.injected["alias_mapping"]),
            lambda: lamb.remove_permission(FunctionName=self.injected["qualified"]["publisher"], Qualifier="ops",
                                           StatementId="ops-alias"),
            lambda: lamb.remove_permission(FunctionName=self.injected["qualified"]["publisher"],
                                           Qualifier=self.injected["qualified"]["version"], StatementId="ops-version"),
        ):
            try:
                undo()
            except Exception:
                pass
        # An alias left on the unrelated key would leak into later phases.
        kms = self.client("kms")
        for alias in kms.list_aliases(KeyId=self.sentinels["kms_key"])["Aliases"]:
            if alias["AliasName"] != self.sentinels["kms_alias"]:
                try:
                    kms.update_alias(AliasName=alias["AliasName"], TargetKeyId=self.manifest["key"])
                except Exception:
                    pass
        self.injected = {}

    def damage_and_recover(self, damage, lane, amount):
        """Damage local state, deploy, and check that the live deployment was adopted intact."""
        m = self.manifest
        # Recovery runs before destructive drift injection. Verify the live baseline
        # before deliberately pausing one mapping to retain a queued-message witness.
        # /reset affects only the operator machine; it does not reset the cloud.
        self.topology(m)
        self.routing_and_queues(m)
        self.execution_roles(m)
        self.caller_isolation(m)
        self.encryption(m)
        lamb = self.client("lambda")
        base = self.publish(m, amount=amount)
        receipts = {c: self.assert_receipt(m, c, base) for c in CONSUMERS}
        identities = self.identities(m)
        other = "fulfillment" if lane == "analytics" else "analytics"
        lamb.update_event_source_mapping(UUID=self.mapping(m, lane)["UUID"], Enabled=False)
        deadline = time.monotonic() + 30
        while self.mapping(m, lane)["State"] != "Disabled" and time.monotonic() < deadline:
            time.sleep(1)
        backlog = [self.publish(m, amount=amount + 1 + n) for n in range(3)]
        for event in backlog:
            self.assert_receipt(m, other, event)
        inventory = self.inventory()
        other_keys = inventory["access_keys"] - {x["access_key_id"] for x in m["callers"].values()}

        # Keep evidence of exposed secrets even when recovery erases local files.
        self.record_secret_exposures()
        damage()
        self.deploy(self.prefix)
        adopted = self.read_manifest(self.prefix)
        for field in ("topic", "functions", "tables"):
            assert adopted[field] == m[field], f"adoption changed {field}"
        for field in ("queues", "dlqs"):
            assert {c: queue_key(u) for c, u in adopted[field].items()} == \
                   {c: queue_key(u) for c, u in m[field].items()}, f"adoption changed {field}"
        after = self.inventory()
        for kind, values in inventory.items():
            if kind != "access_keys":
                assert after[kind] == values, f"adoption changed {kind}: extra={after[kind] - values}, missing={values - after[kind]}"
        assert other_keys <= after["access_keys"], "adoption removed unrelated access keys"
        assert self.identities(adopted) == identities, "adoption recreated resources"
        self.manifest = adopted
        self.assert_declared(adopted, self.declared_ids())
        assert self.wait_enabled(adopted, lane)["State"] == "Enabled"
        for event in backlog:
            self.assert_receipt(adopted, lane, event)
        for consumer, receipt in receipts.items():
            assert self.receipt(adopted, consumer, base) == receipt
        fresh = self.publish(adopted, amount=amount + 10)
        for consumer in CONSUMERS:
            self.assert_receipt(adopted, consumer, fresh)
        self.caller_isolation(adopted)

    def state_loss_adoption(self):
        def lose_state():
            runner("POST", "/reset", {}, timeout=120)
            assert not any(state["resources"] for state in runner("GET", "/state-summary")["states"]), \
                "local state survived the reset"
        self.damage_and_recover(lose_state, "analytics", 300)

    def unreadable_state_recovery(self):
        def truncate_state():
            # A run killed while writing state leaves a truncated file behind.
            damaged = runner("POST", "/corrupt-state", {}, timeout=120)["files"]
            assert damaged, "no Terraform state holding the deployment was found to damage"
        self.damage_and_recover(truncate_state, "fulfillment", 320)

    def record_secret_exposures(self):
        files = runner("POST", "/secret-files", {"secrets": sorted(self.secrets)}, timeout=300)["files"]
        self.exposed_secret_files.update(
            f"{f['path']} ({f['mode']:04o})" for f in files if f["mode"] & 0o077)
        return files

    def private_secrets(self):
        assert self.secrets, "no caller secrets were recorded"
        files = self.record_secret_exposures()
        assert any(Path(f["path"]).name == "manifest.json" for f in files), "no manifest holding caller secrets was found"
        exposed = sorted(self.exposed_secret_files)
        assert not exposed, f"files holding caller secrets are readable by others: {exposed[:5]}"

    def cleanup(self):
        assert self.initial_inventory is not None
        a, b = self.manifest, self.peer
        identities = self.identities(a)
        witness = None
        if b:
            # Data the other deployment holds before this one is destroyed.
            witness = self.publish(b, amount=44)
            for consumer in CONSUMERS:
                self.assert_receipt(b, consumer, witness)
        peer_snapshot = self.fingerprint(b) if b else None
        for _ in range(2):
            self.destroy(self.prefix)
        lamb, sqs, sns, ddb, iam = (self.client(x) for x in ("lambda", "sqs", "sns", "dynamodb", "iam"))
        for name, function in a["functions"].items():
            assert self.missing(lambda: lamb.get_function_configuration(FunctionName=function)), f"{name} function remains"
            role = identities[f"role:{name}"][0]
            assert self.missing(lambda: iam.get_role(RoleName=role)), f"{name} role remains"
        for actor in CALLERS:
            user = identities[f"user:{actor}"][0]
            assert self.missing(lambda: iam.get_user(UserName=user)), f"{actor} caller remains"
        for queue in [*a["queues"].values(), *a["dlqs"].values()]:
            assert self.missing(lambda: sqs.get_queue_attributes(QueueUrl=queue, AttributeNames=["QueueArn"])), "queue remains"
        for table in a["tables"].values():
            assert self.missing(lambda: ddb.describe_table(TableName=table)), "table remains"
        assert self.missing(lambda: sns.get_topic_attributes(TopicArn=a["topic"])), "topic remains"
        kms = self.client("kms")
        key = kms.describe_key(KeyId=a["key"])["KeyMetadata"]
        assert key["KeyState"] == "PendingDeletion", f"destroy left the KMS key {key['KeyState']}"
        assert not kms.list_aliases(KeyId=key["KeyId"])["Aliases"], "destroy left the key alias"
        if b:
            assert self.fingerprint(b) == peer_snapshot, "destroying one deployment changed another"
            for consumer in CONSUMERS:
                assert self.receipt(b, consumer, witness), "destroying one deployment lost another's data"
        if b or self.peer_attempted:
            for _ in range(2):
                self.destroy(self.peer_prefix)
        after = self.inventory()
        for kind, initial in self.initial_inventory.items():
            assert after[kind] == initial, f"cleanup inventory mismatch for {kind}: extra={after[kind] - initial}, missing={initial - after[kind]}"
        self.sentinels_intact()
        self.cleaned = True

    def redeploy_after_destroy(self):
        assert self.cleaned, "cleanup did not complete"
        old = self.manifest
        kms = self.client("kms")
        self.deploy(self.prefix)
        fresh = self.read_manifest(self.prefix)
        assert fresh["key"] != old["key"] and \
            kms.describe_key(KeyId=old["key"])["KeyMetadata"]["KeyState"] == "PendingDeletion", \
            "deploy revived the key that destroy scheduled for deletion"
        self.topology(fresh)
        self.routing_and_queues(fresh)
        event = self.publish(fresh, amount=45)
        for consumer in CONSUMERS:
            self.assert_receipt(fresh, consumer, event)
        for _ in range(2):
            self.destroy(self.prefix)
        after = self.inventory()
        for kind, initial in self.initial_inventory.items():
            assert after[kind] == initial, \
                f"second destroy left an inventory mismatch for {kind}: extra={after[kind] - initial}, missing={initial - after[kind]}"
        self.sentinels_intact()

    # ----- orchestration ------------------------------------------------------

    def run(self):
        try:
            self.create_sentinels()
            self.initial_inventory = self.inventory()
            self.deploy(self.prefix)
        except Exception as error:
            self.results.append({"name": "deployment", "points": 100, "earned": 0,
                                 "error": str(error)[-1000:]})
            return self.write_report()
        checks = (
            ("contract and declared state", 4, self.contract_and_state),
            ("isolated function, ledger and key topology", 6, lambda: self.topology(self.manifest)),
            ("subscriptions, policies, retention and batch configuration", 8,
             lambda: self.routing_and_queues(self.manifest)),
            ("selective delivery", 7, lambda: self.selective_delivery(self.manifest)),
            ("tenant-scoped durable idempotency", 3, lambda: self.idempotency(self.manifest)),
            ("caller isolation", 7, lambda: self.caller_isolation(self.manifest)),
            ("execution role least privilege", 5, lambda: self.execution_roles(self.manifest)),
            ("encryption key least privilege", 10, lambda: self.encryption(self.manifest)),
            ("bilateral poison and batch recovery", 6, lambda: self.poison_and_replay(self.manifest)),
            ("independent nested-prefix deployments", 6, self.independent_deployments),
            # Keep recovery independent of an earlier submission's failure to
            # repair injected drift (for example TTL or RedriveAllowPolicy).
            ("state-loss adoption", 7, self.state_loss_adoption),
            ("unreadable state recovery", 5, self.unreadable_state_recovery),
            ("lossless multi-resource drift repair", 8, self.lossless_repair),
            ("out-of-band addition convergence", 7, self.addition_convergence),
            ("private local secrets", 4, self.private_secrets),
            ("complete ownership-safe cleanup", 4, self.cleanup),
            ("fresh redeploy after destroy", 3, self.redeploy_after_destroy),
        )
        for name, points, check in checks:
            if self.manifest is None and name != "contract and declared state":
                try:
                    self.manifest = self.read_manifest(self.prefix)
                except Exception:
                    pass
            self.score(name, points, check)
            if name == "out-of-band addition convergence":
                try:
                    self.tidy_injections()
                except Exception:
                    pass
        self.write_report()

    def write_report(self):
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        raw = sum(item["earned"] for item in self.results)
        failed = {item["name"] for item in self.results if item["earned"] == 0}
        cap = 100
        gates = []
        if "selective delivery" in failed:
            cap = min(cap, 40)
            gates.append("selective delivery failed")
        if "caller isolation" in failed:
            cap = min(cap, 60)
            gates.append("caller boundary failed")
        score = min(raw, cap)
        (REPORT_DIR / "report.json").write_text(json.dumps({
            "score": score, "raw_score": raw, "cap": cap, "task_revision": "0.6.0",
            "success": score == 100, "prefixes": [self.prefix, self.peer_prefix],
            "gates": gates, "tests": self.results}, indent=2) + "\n")
        (REPORT_DIR / "reward.json").write_text(json.dumps({
            "score": score, "reward": score / 100}) + "\n")
        (REPORT_DIR / "reward.txt").write_text(f"{score / 100:.2f}\n")
        print(f"PulseRoute score: {score}/100")


if __name__ == "__main__":
    Verification().run()
