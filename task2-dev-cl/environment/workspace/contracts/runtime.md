# PulseRoute public runtime contract - revision 6

Deploy selective order-event routing, isolated durable ledgers, partial batch
recovery, encrypted messaging, least-privilege access, and self-healing
lifecycle automation for independent deployments. Application images are fixed;
provision and connect their infrastructure using Terraform or OpenTofu.

Endpoint: `http://aws:4566`; region: `us-east-1`; account: `111111111111`.
Administrator credentials: `/workspace/config/terraform.tfvars.json` (read-only).
The Docker daemon already contains these images:

| Function | Image | Required environment variables |
| --- | --- | --- |
| Publisher | `111111111111.dkr.ecr.us-east-1.amazonaws.com/pulseroute-publisher:2` | `TOPIC_ARN` |
| Fulfillment | `111111111111.dkr.ecr.us-east-1.amazonaws.com/pulseroute-worker:2` | `CONSUMER=fulfillment`, `DELIVERIES_TABLE` |
| Analytics | `111111111111.dkr.ecr.us-east-1.amazonaws.com/pulseroute-worker:2` | `CONSUMER=analytics`, `DELIVERIES_TABLE` |
| Replay | `111111111111.dkr.ecr.us-east-1.amazonaws.com/pulseroute-replay:2` | `FULFILLMENT_QUEUE`, `FULFILLMENT_DLQ`, `ANALYTICS_QUEUE`, `ANALYTICS_DLQ` |

Deploy four distinct functions and execution roles with at least 256 MiB of
memory. Publisher and Replay time out after at least 15 seconds; each worker
times out after exactly 15 seconds. Do not alter or replace the supplied images.
Queue environment variables hold queue URLs; `DELIVERIES_TABLE` holds a table
name. Every resource name must be valid in AWS for every allowed prefix.

## Deployments

`PULSEROUTE_PREFIX` names a deployment: 3 to 25 lowercase letters, digits or
hyphens, starting with a letter. Derive every resource name from it. One
submission directory manages any number of independent deployments, and each
`deploy.sh` or `destroy.sh` run acts only on the deployment named by its own
`PULSEROUTE_PREFIX`. One prefix may begin with another (for example `acme` and
`acme-eu`); no run may create, adopt, modify or delete another deployment's
resources. The verifier chooses its own prefixes.

## Routing

Provision one standard SNS topic, two standard main SQS queues, two distinct
standard DLQs, exactly one raw SQS subscription and one enabled Lambda event
source mapping per main queue. Publisher emits this body without SNS attributes:

```json
{"source":"pulseroute.orders","detail-type":"order.created","detail":{"event_id":"a8c25fd4-5f3a-4a90-8384-85e9bc21bdd3","tenant":"shop-7","kind":"order.created","amount":42}}
```

Configure SNS filters with **MessageBody** scope. Require `source=pulseroute.orders`
and all conditions in the applicable row, matching fields inside `detail`:

| Consumer | Tenant | Kind | Numeric amount, inclusive |
| --- | --- | --- | --- |
| Fulfillment | starts with `shop-` | `order.created` or `order.cancelled` | 1 to 500000 |
| Analytics | starts with `shop-` or `lab-` | `order.created` or `order.cancelled` | 0 to 1000000 |

Nonmatching valid publications return `published` but create no receipt. Filtering
must happen at SNS; workers do not filter. Each main queue's policy allows only
`sns.amazonaws.com` to `sqs:SendMessage` on that queue with `aws:SourceArn` equal
to the dedicated topic. No public or unrelated-topic grants are permitted.

## Ledgers and recovery

Use two distinct DynamoDB tables, each keyed by string `delivery_id`. Each worker's
`DELIVERIES_TABLE` names its own table. Fixed workers conditionally write the key
`<consumer>:<tenant>:<event_id>`. Duplicate events preserve the entire first
receipt, including `processed_at`; the same UUID in another tenant is distinct.
Receipts never expire. Both tables have deletion protection and point-in-time
recovery enabled for as long as the deployment exists.

Each mapping uses batch size 5 to 10 and enables `ReportBatchItemFailures`. Each
worker processes at most 3 batches at a time, and Lambda must never throttle a
worker's batches. Workers process all records and return only failed message
IDs. Each main queue redrives to its own DLQ after 2 or 3 receives, and its
visibility timeout is the shortest that AWS recommends for a queue that triggers
a Lambda function, given that function's timeout and the mapping's batching
window. DLQs retain messages for 14 days, have no queue policy and never redrive
anywhere themselves. Each DLQ's redrive allow policy (`byQueue`) admits only its
own main queue, and no queue may use a main queue as its dead-letter queue. Main
queues keep undelivered messages for as long as possible while still
guaranteeing that every dead-lettered message stays replayable for at least 8
days after it is dead-lettered.

Optional `fail_consumer` poisons the named consumer until replay. Healthy records
in a batch and the eligible peer must still complete. Replay receives from the
selected DLQ, marks `detail.replayed=true`, sends to its main queue, then deletes
the DLQ copy. Both lanes must recover; replay must leave the other lane untouched,
preserve event fields, drain the selected DLQ, and return count zero when empty.
Normal receipts have `replayed=false`; recovered receipts have `replayed=true`.

## Encryption

Encrypt the topic and all four queues at rest with one symmetric customer
managed KMS key owned by the deployment, with automatic rotation enabled and an
alias derived from the prefix. Each queue reuses a data key for as long as SQS
allows, keeping KMS requests to a minimum. The key policy keeps the account able
to administer the key through IAM, but administering is not using: no IAM policy
can give any principal other than the four execution roles, the administrator
you deploy with included, permission to encrypt, decrypt or generate data keys
with it. It lets Amazon SNS use the key with confused-deputy protection. Every
principal receives exactly the key permissions AWS requires for its part of the
message flow and nothing more: the Publisher role publishes to the encrypted
topic, Amazon SNS delivers into the encrypted main queues, each worker receives
from its own queue, and Replay receives from both dead-letter queues and sends
to both main queues. Grant the roles these permissions in the key policy, in
identity policies on the key's ARN, or both; each execution role can use the key
only through the AWS service that carries its messages, never by calling KMS
directly. Callers and every other principal have no use of the key.

## IAM

Execution-role trust grants `sts:AssumeRole` only to `lambda.amazonaws.com`.
Inline or attached policies must use explicit Allow actions and resources; no
`NotAction`, `NotResource`, wildcard actions, or broad resource grants. Allowed
workload permissions:

| Role | Permissions and resources |
| --- | --- |
| Publisher | `sns:Publish` on `arn:aws:sns:us-east-1:111111111111:*` |
| Each worker | `sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:GetQueueAttributes`, optional `sqs:ChangeMessageVisibility` on its own main queue; `dynamodb:PutItem` on its own table |
| Replay | `sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:GetQueueAttributes`, optional `sqs:ChangeMessageVisibility` on the two DLQs; `sqs:SendMessage` on the two main queues |

Each role additionally holds the KMS permissions that the Encryption section
requires of it, and no others.

Optional `logs:CreateLogGroup`, `logs:CreateLogStream`, and `logs:PutLogEvents` may
target only that function's `/aws/lambda/<function-name>` group and streams.
Logging is not required. Use the Publisher resource pattern shown above with
the AWS endpoints; `TOPIC_ARN` selects the dedicated topic.

The topic policy contains one Allow statement granting the Publisher execution
role `sns:Publish` on the topic, and no other Allow statement. Functions and
tables have no resource-based policy statements: callers are authorized by their
own IAM policies and workers by their event source mappings.

Provide three distinct IAM users with one access key each: `publisher` invokes
only Publisher; `operator` invokes only Replay; `outsider` invokes nothing. No
caller may directly publish SNS, send/receive/delete SQS messages, read/write
either table, invoke workers, or manage infrastructure. Worker roles cannot access
the other worker's queue/table or DLQs; Replay cannot access either table.
Caller policies must be attached directly to their users, with no IAM group
membership. Their only Allow grant is `lambda:InvokeFunction` on the designated
function's exact ARN; Outsider has no Allow grants.

## Convergence

Every successful deploy leaves the deployment exactly as declared. Drift can
affect any resource or setting this contract specifies, including the key alias.
Besides repairing deleted or modified resources, deploy removes these
out-of-band additions:

- inline or managed policies on execution roles or caller users that the
  configuration does not declare;
- access keys other than the one each caller user holds in the manifest;
- IAM group memberships of caller users;
- topic subscriptions other than the two declared queue subscriptions;
- event source mappings that read from an owned queue or invoke an owned
  function, other than the two declared worker mappings;
- resource-based policy statements on owned functions;
- resource-based policies on owned tables;
- grants on the deployment's KMS key that the configuration does not declare.

Remove the addition, never the unrelated resource it references, such as a
subscribed queue, a group, a managed policy, another function or another key.
Do not suppress required repair with `ignore_changes`.

## State and lifecycle

Keep readable local Terraform/OpenTofu state for each deployment in files named
`terraform.tfstate` under the submission directory. Every scored resource must
be declared in that state.

Local state is not durable. `deploy.sh` and `destroy.sh` may run from a fresh
copy of the submission: no state, no `.terraform` directories, no
`manifest.json`, and no files left in home or temporary directories. They may
also find a deployment's state file unreadable, for example truncated by a run
that was killed while writing it. Deploy then adopts the existing deployment. It must not recreate or duplicate the topic,
queues, tables, subscriptions, mappings, functions, roles, users or KMS key, and
must keep every receipt and queued message. Only in this situation may caller
access keys be replaced; each caller still ends with exactly one key, the one in
the new manifest.

A repeated deploy creates, deletes and replaces nothing, and preserves resource
identities, caller credentials, receipts and queued messages. A single deploy
must repair any combination of the drift described above, drain messages
published while the deployment was damaged, and restore correct routing for new
traffic without replacing queues, tables or the KMS key. If the key has been
disabled or scheduled for deletion, deploy cancels the deletion and re-enables
that same key.

Destroy removes every resource the deployment owns (functions, mappings,
subscriptions, topic, queues, tables, roles, users, access keys, policies, key
alias and anything else it created) and schedules its KMS key for deletion,
whether local state is present, missing or unreadable. Preserve unrelated resources and their data, including
resources whose names start with the same prefix; never select resources by
name prefix. A second destroy must succeed. A deploy after a destroy creates a
new deployment and never revives anything that destroy deleted or scheduled for
deletion. Each script run has a 900-second limit, and no background process
outlives the script that started it.

## Manifest

After each successful deploy, `manifest.json` in the submission directory
describes the deployment that run deployed and matches
`/workspace/contracts/manifest.schema.json` (revision 6). Values use each
service's API identifier: topic ARN, KMS key ARN, function names, queue URLs,
table names, and caller access keys. Treat it as a local secret: every file a
run leaves behind that contains a caller secret access key must be readable only
by its owner.

## Invocation API

Publisher input:

```json
{"operation":"publish","event_id":"a8c25fd4-5f3a-4a90-8384-85e9bc21bdd3","tenant":"shop-7","kind":"order.created","amount":42}
```

`event_id` is a canonical UUID. `tenant` has 1 to 32 lowercase letters, digits or
hyphens, starting with a letter or digit. `kind` is `order.created` or
`order.cancelled`; `amount` is an integer 0 to 1000000. Optional `fail_consumer`
is `fulfillment` or `analytics`. Response: `{"status":"published","event_id":"..."}`.

Replay input:

```json
{"operation":"replay","consumer":"fulfillment","limit":10}
```

`limit` is 1 to 10. Response has `status: "replayed"`, `consumer`, and `count`.
Repeated calls are allowed; SQS can return fewer messages than requested.

All requirements are scored.
