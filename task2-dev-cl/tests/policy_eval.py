"""Small IAM/KMS policy evaluator for verifying least-privilege requirements.

Floci does not enforce KMS permissions on SQS or SNS, so the verifier evaluates
the deployed key policy and identity policies against the requests AWS would
make. Semantics follow the IAM policy evaluation logic: an explicit Deny wins,
otherwise an Allow is required. For KMS, a key policy statement whose principal
is the account delegates to IAM, so the identity policy must also allow.
"""

from fnmatch import fnmatchcase
import json
from urllib.parse import unquote


ACCOUNT = "111111111111"
# Condition keys the verifier cannot model precisely (encryption context, alias
# and tag based conditions). A condition on one of these keys is treated as
# satisfied so that a correct but more specific policy is never rejected.
UNMODELED_PREFIXES = ("kms:encryptioncontext", "kms:resourcealiases", "kms:requestalias",
                      "aws:resourcetag/", "aws:requesttag/", "aws:tagkeys", "kms:grant")


def document(value):
    if isinstance(value, str):
        return json.loads(unquote(value))
    return value


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def statements(policy):
    if not policy:
        return []
    return as_list(document(policy).get("Statement", []))


def _match(pattern, value):
    return fnmatchcase(str(value).lower(), str(pattern).lower())


def action_matches(statement, action):
    if "NotAction" in statement:
        return not any(_match(p, action) for p in as_list(statement["NotAction"]))
    return any(_match(p, action) for p in as_list(statement.get("Action")))


def resource_matches(statement, resource):
    if "NotResource" in statement:
        return not any(fnmatchcase(resource, p) for p in as_list(statement["NotResource"]))
    return any(p == "*" or fnmatchcase(resource, p) for p in as_list(statement.get("Resource", "*")))


def principal_kind(statement, principal):
    """How a resource-policy statement names a principal: direct, account, or None.

    `principal` is ("AWS", arn) for IAM identities or ("Service", name).
    """
    kind, value = principal
    names = statement.get("NotPrincipal")
    if names is not None:
        listed = names == "*" or value in as_list(names.get(kind) if isinstance(names, dict) else names)
        return None if listed else "direct"
    named = statement.get("Principal")
    if named == "*":
        return "direct"
    if not isinstance(named, dict):
        return None
    values = as_list(named.get(kind))
    if "*" in values or value in values:
        return "direct"
    if kind == "AWS" and any(v in (ACCOUNT, f"arn:aws:iam::{ACCOUNT}:root") for v in values):
        return "account"
    return None


def _unmodeled(key):
    return key.lower().startswith(UNMODELED_PREFIXES)


def _compare(operator, expected, actual):
    base = operator
    if base.startswith(("String", "Arn")):
        negated = "Not" in base
        # ArnEquals and ArnLike both accept wildcards in IAM.
        like = base.endswith("Like") or base.startswith("Arn")
        ignore_case = base.endswith("IgnoreCase")
        if like:
            hit = any(fnmatchcase(actual, e) for e in expected)
        elif ignore_case:
            hit = any(actual.lower() == e.lower() for e in expected)
        else:
            hit = actual in expected
        return not hit if negated else hit
    if base == "Bool":
        return str(actual).lower() in [str(e).lower() for e in expected]
    if base.startswith("Numeric"):
        try:
            a = float(actual)
            values = [float(e) for e in expected]
        except ValueError:
            return False
        ops = {"NumericEquals": lambda x, y: x == y, "NumericNotEquals": lambda x, y: x != y,
               "NumericLessThan": lambda x, y: x < y, "NumericLessThanEquals": lambda x, y: x <= y,
               "NumericGreaterThan": lambda x, y: x > y, "NumericGreaterThanEquals": lambda x, y: x >= y}
        compare = ops.get(base)
        return bool(compare) and any(compare(a, v) for v in values)
    return False


def conditions_hold(statement, context):
    lowered = {k.lower(): v for k, v in context.items()}
    for operator, block in (statement.get("Condition") or {}).items():
        qualifier, _, op = operator.rpartition(":")
        if_exists = op.endswith("IfExists")
        op = op[:-len("IfExists")] if if_exists else op
        for key, expected in block.items():
            expected = [str(e) for e in as_list(expected)]
            present = key.lower() in lowered
            if op == "Null":
                want_absent = expected and expected[0].lower() == "true"
                if present == want_absent:
                    return False
                continue
            if not present:
                # IfExists, negated operators and ForAllValues hold when the key is absent.
                if _unmodeled(key) or if_exists or "Not" in op or qualifier.lower() == "forallvalues":
                    continue
                return False
            actual = [str(v) for v in as_list(lowered[key.lower()])]
            if qualifier.lower() == "forallvalues":
                ok = all(_compare(op, expected, a) for a in actual)
            else:
                ok = any(_compare(op, expected, a) for a in actual)
            if not ok:
                return False
    return True


def decide(policies, action, resource, context, principal=None):
    """Evaluate statements; returns 'deny', 'allow', 'account' or None (implicit deny).

    With `principal`, policies are resource policies and principal matching applies;
    'account' means the only Allow was delegated to the account (IAM must allow too).
    """
    result = None
    for policy in policies:
        for statement in statements(policy):
            kind = "direct"
            if principal is not None:
                kind = principal_kind(statement, principal)
                if kind is None:
                    continue
            if not action_matches(statement, action) or not resource_matches(statement, resource):
                continue
            if not conditions_hold(statement, context):
                continue
            if statement.get("Effect") == "Deny":
                return "deny"
            if statement.get("Effect") == "Allow":
                result = "allow" if kind == "direct" or result == "allow" else "account"
    return result


SNS_VIA = "sns.us-east-1.amazonaws.com"
SQS_VIA = "sqs.us-east-1.amazonaws.com"
# What each execution role needs, per AWS: SNS publishers to an encrypted topic
# need GenerateDataKey and Decrypt; SQS consumers need Decrypt; SQS producers
# need GenerateDataKey and Decrypt. Each request reaches KMS through that service.
REQUIRED = {
    "publisher": {"kms:GenerateDataKey": SNS_VIA, "kms:Decrypt": SNS_VIA},
    "fulfillment": {"kms:Decrypt": SQS_VIA},
    "analytics": {"kms:Decrypt": SQS_VIA},
    "replay": {"kms:Decrypt": SQS_VIA, "kms:GenerateDataKey": SQS_VIA},
}
# kms:GenerateDataKey* (as in the AWS documentation examples) also covers these.
DATA_KEY_FAMILY = ("kms:GenerateDataKeyWithoutPlaintext", "kms:GenerateDataKeyPair",
                   "kms:GenerateDataKeyPairWithoutPlaintext")
NEVER = ("kms:Encrypt", "kms:ReEncryptFrom", "kms:ReEncryptTo", "kms:CreateGrant", "kms:RetireGrant",
         "kms:RevokeGrant", "kms:DescribeKey", "kms:GetKeyPolicy", "kms:PutKeyPolicy",
         "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion", "kms:DisableKey", "kms:EnableKey",
         "kms:Sign", "kms:GenerateMac")
ADMIN_ACTIONS = ("kms:DescribeKey", "kms:PutKeyPolicy", "kms:EnableKey", "kms:CancelKeyDeletion",
                 "kms:ScheduleKeyDeletion")
# Cryptographic use of the key, which only the execution roles and SNS may have.
CRYPTO = ("kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext",
          "kms:ReEncryptFrom", "kms:ReEncryptTo")
# Any other principal in the account, holding every IAM permission, must still
# have no use of the key: the key policy must not hand usage to IAM at large.
AUDITOR = (f"arn:aws:iam::{ACCOUNT}:role/pulseroute-key-auditor",
           [{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}])
FOREIGN = (("AWS", "arn:aws:iam::222222222222:root"), ("Service", "events.amazonaws.com"),
           ("Service", "lambda.amazonaws.com"), ("Service", "s3.amazonaws.com"))


def _iam_context(arn, account=ACCOUNT, via=None, tags=None):
    context = {"aws:PrincipalArn": arn, "aws:PrincipalAccount": account, "kms:CallerAccount": account}
    for key, value in (tags or {}).items():
        context[f"aws:PrincipalTag/{key}"] = value
    if via:
        context["kms:ViaService"] = via
    return context


def _principal(entry):
    """(arn, policies) or (arn, policies, tags) -> (arn, policies, tags)."""
    arn, policies, *rest = entry
    return arn, policies, (rest[0] if rest else {})


def _route(via):
    return "by calling KMS directly" if via is None else f"through {via.split('.')[0].upper()}"


def kms_findings(key_arn, key_policy, topic_arn, queue_arns, roles, callers, admin, grants=()):
    """Return least-privilege violations for the deployment key.

    roles: {name: (role_arn, [identity policy documents])} for the four functions.
    callers: {actor: (user_arn, [identity policy documents])}.
    admin: (user_arn, [identity policy documents]) for the account administrator.
    grants: the key's grants ({"GranteePrincipal", "Operations"}). A grant cannot be
    limited to a calling service, so any grant confers direct use of the key.
    """
    findings = []
    vias = (None, SNS_VIA, SQS_VIA)
    for grant in grants:
        findings.append(f"a grant gives {grant.get('GranteePrincipal')} direct use of the key "
                        f"({', '.join(sorted(grant.get('Operations', [])))})")
    for name, entry in roles.items():
        arn, policies, tags = _principal(entry)
        principal = ("AWS", arn)
        needed = REQUIRED[name]
        for action, via in needed.items():
            if not kms_allowed(key_policy, policies, principal, action, key_arn, _iam_context(arn, via=via, tags=tags)):
                findings.append(f"{name} role cannot {action} through {via.split('.')[0].upper()}")
            # Each role may use the key only through the service that carries its messages.
            for other in vias:
                if other != via and kms_allowed(key_policy, policies, principal, action, key_arn,
                                                _iam_context(arn, via=other, tags=tags)):
                    findings.append(f"{name} role may {action} {_route(other)}")
        tolerated = set(needed)
        if "kms:GenerateDataKey" in needed:
            tolerated.update(DATA_KEY_FAMILY)
        candidates = {*NEVER, "kms:Decrypt", "kms:GenerateDataKey", *DATA_KEY_FAMILY}
        for action in sorted(candidates - tolerated):
            if any(kms_allowed(key_policy, policies, principal, action, key_arn, _iam_context(arn, via=v, tags=tags))
                   for v in vias):
                findings.append(f"{name} role may also {action}")
    for actor, entry in callers.items():
        arn, policies, tags = _principal(entry)
        for action in ("kms:Decrypt", "kms:GenerateDataKey", "kms:Encrypt", "kms:DescribeKey", "kms:CreateGrant"):
            if any(kms_allowed(key_policy, policies, ("AWS", arn), action, key_arn, _iam_context(arn, via=v, tags=tags))
                   for v in vias):
                findings.append(f"{actor} caller may {action}")
    sns = ("Service", "sns.amazonaws.com")
    own = {"aws:SourceAccount": ACCOUNT, "aws:SourceArn": topic_arn}
    # AWS does not document whether SNS reports the topic or the queue as the
    # source when it calls KMS for an encrypted queue, so either scoping passes.
    per_queue = [{"aws:SourceAccount": ACCOUNT, "aws:SourceArn": arn} for arn in queue_arns]
    for action in ("kms:GenerateDataKey", "kms:Decrypt"):
        by_topic = kms_allowed(key_policy, [], sns, action, key_arn, own)
        by_queue = all(kms_allowed(key_policy, [], sns, action, key_arn, context) for context in per_queue)
        if not (by_topic or by_queue):
            findings.append(f"SNS cannot {action} for this deployment's queues")
    foreign_topic = {"aws:SourceAccount": "222222222222", "aws:SourceArn": "arn:aws:sns:us-east-1:222222222222:orders"}
    for action in ("kms:GenerateDataKey", "kms:Decrypt"):
        if kms_allowed(key_policy, [], sns, action, key_arn, foreign_topic):
            findings.append(f"SNS may {action} on behalf of another account (no confused-deputy protection)")
    for action in NEVER:
        if any(kms_allowed(key_policy, [], sns, action, key_arn, context) for context in (own, *per_queue)):
            findings.append(f"SNS may also {action}")
    for principal in FOREIGN:
        for action in ("kms:Decrypt", "kms:GenerateDataKey", "kms:Encrypt", "kms:CreateGrant"):
            context = ({"aws:SourceAccount": "222222222222"} if principal[0] == "Service"
                       else _iam_context(principal[1], account="222222222222"))
            if kms_allowed(key_policy, [], principal, action, key_arn, context):
                findings.append(f"{principal[1]} may {action}")
    admin_arn, admin_policies, admin_tags = _principal(admin)
    for action in ADMIN_ACTIONS:
        if not kms_allowed(key_policy, admin_policies, ("AWS", admin_arn), action, key_arn,
                           _iam_context(admin_arn, tags=admin_tags)):
            findings.append(f"the account administrator cannot {action} (key lockout)")
    # Administration is not use: neither the administrator nor any other IAM
    # principal of the account may encrypt, decrypt or generate data keys.
    for label, entry in (("the account administrator", admin), ("any IAM principal with full permissions", AUDITOR)):
        arn, policies, tags = _principal(entry)
        for action in CRYPTO:
            if any(kms_allowed(key_policy, policies, ("AWS", arn), action, key_arn, _iam_context(arn, via=v, tags=tags))
                   for v in vias):
                findings.append(f"{label} may {action} with the key")
                break
    return findings


def kms_allowed(key_policy, identity_policies, principal, action, key_arn, context):
    """Effective KMS permission for an IAM identity or a service principal."""
    from_key = decide([key_policy], action, key_arn, context, principal=principal)
    if from_key == "deny":
        return False
    if principal[0] == "Service":
        return from_key == "allow"
    from_identity = decide(identity_policies, action, key_arn, context)
    if from_identity == "deny":
        return False
    if from_key == "allow":
        return True
    return from_key == "account" and from_identity == "allow"
