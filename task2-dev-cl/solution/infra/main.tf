terraform {
  required_version = ">= 1.8.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "= 6.50.0" }
  }
}

variable "prefix" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,24}$", var.prefix))
    error_message = "prefix must be 3-25 lowercase letters, digits or hyphens, starting with a letter"
  }
}
variable "admin_access_key" {
  type      = string
  sensitive = true
}
variable "admin_secret_key" {
  type      = string
  sensitive = true
}
variable "endpoint" {
  type    = string
  default = "http://aws:4566"
}
variable "region" {
  type    = string
  default = "us-east-1"
}
variable "table_deletion_protection" {
  description = "Stays true while the deployment exists; destroy.sh lowers it just before deleting the tables."
  type        = bool
  default     = true
}

provider "aws" {
  region                      = var.region
  access_key                  = var.admin_access_key
  secret_key                  = var.admin_secret_key
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  skip_region_validation      = true
  endpoints {
    dynamodb = var.endpoint
    iam      = var.endpoint
    kms      = var.endpoint
    lambda   = var.endpoint
    sns      = var.endpoint
    sqs      = var.endpoint
    sts      = var.endpoint
  }
}

locals {
  account   = "111111111111"
  consumers = toset(["fulfillment", "analytics"])
  services  = toset(["publisher", "fulfillment", "analytics", "replay"])
  callers   = toset(["publisher", "operator", "outsider"])
  # Caller -> the one function it may invoke. Outsider has no grant.
  invokes = { publisher = "publisher", operator = "replay" }
  images = {
    publisher   = "111111111111.dkr.ecr.us-east-1.amazonaws.com/pulseroute-publisher:2"
    fulfillment = "111111111111.dkr.ecr.us-east-1.amazonaws.com/pulseroute-worker:2"
    analytics   = "111111111111.dkr.ecr.us-east-1.amazonaws.com/pulseroute-worker:2"
    replay      = "111111111111.dkr.ecr.us-east-1.amazonaws.com/pulseroute-replay:2"
  }
  queue_read = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
  routes = {
    fulfillment = { tenant = [{ prefix = "shop-" }], amount = [{ numeric = [">=", 1, "<=", 500000] }] }
    analytics   = { tenant = [{ prefix = "shop-" }, { prefix = "lab-" }], amount = [{ numeric = [">=", 0, "<=", 1000000] }] }
  }
  # KMS needs per AWS: publishers to an encrypted topic and producers to an
  # encrypted queue need GenerateDataKey and Decrypt; consumers need Decrypt.
  # Each role reaches the key only through the service that stores its messages.
  via_sns = { StringEquals = { "kms:ViaService" = "sns.${var.region}.amazonaws.com" } }
  via_sqs = { StringEquals = { "kms:ViaService" = "sqs.${var.region}.amazonaws.com" } }
  role_statements = {
    publisher = [
      { Effect = "Allow", Action = ["sns:Publish"], Resource = ["arn:aws:sns:${var.region}:${local.account}:*"] },
      { Effect = "Allow", Action = ["kms:GenerateDataKey", "kms:Decrypt"], Resource = [aws_kms_key.orders.arn], Condition = local.via_sns },
    ]
    fulfillment = [
      { Effect = "Allow", Action = local.queue_read, Resource = [aws_sqs_queue.main["fulfillment"].arn] },
      { Effect = "Allow", Action = ["dynamodb:PutItem"], Resource = [aws_dynamodb_table.deliveries["fulfillment"].arn] },
      { Effect = "Allow", Action = ["kms:Decrypt"], Resource = [aws_kms_key.orders.arn], Condition = local.via_sqs },
    ]
    analytics = [
      { Effect = "Allow", Action = local.queue_read, Resource = [aws_sqs_queue.main["analytics"].arn] },
      { Effect = "Allow", Action = ["dynamodb:PutItem"], Resource = [aws_dynamodb_table.deliveries["analytics"].arn] },
      { Effect = "Allow", Action = ["kms:Decrypt"], Resource = [aws_kms_key.orders.arn], Condition = local.via_sqs },
    ]
    replay = [
      { Effect = "Allow", Action = local.queue_read, Resource = [for queue in aws_sqs_queue.dlq : queue.arn] },
      { Effect = "Allow", Action = ["sqs:SendMessage"], Resource = [for queue in aws_sqs_queue.main : queue.arn] },
      { Effect = "Allow", Action = ["kms:GenerateDataKey", "kms:Decrypt"], Resource = [aws_kms_key.orders.arn], Condition = local.via_sqs },
    ]
  }
  # AWS recommends a visibility timeout of at least six times the timeout of the
  # function a queue triggers; the mappings use no batching window.
  worker_timeout = 15
  # Built from names, not resource references, so the key does not wait for the roles.
  role_arns = [for service in local.services : "arn:aws:iam::${local.account}:role/${var.prefix}-${service}-lambda"]
  key_administration = [
    "kms:DescribeKey", "kms:GetKeyPolicy", "kms:PutKeyPolicy", "kms:ListKeyPolicies",
    "kms:GetKeyRotationStatus", "kms:EnableKeyRotation", "kms:DisableKeyRotation",
    "kms:EnableKey", "kms:DisableKey", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
    "kms:UpdateKeyDescription", "kms:ListResourceTags", "kms:TagResource", "kms:UntagResource",
    "kms:CreateAlias", "kms:UpdateAlias", "kms:DeleteAlias", "kms:ListAliases",
    "kms:ListGrants", "kms:RevokeGrant",
  ]
  environment = {
    publisher   = { TOPIC_ARN = aws_sns_topic.orders.arn }
    fulfillment = { CONSUMER = "fulfillment", DELIVERIES_TABLE = aws_dynamodb_table.deliveries["fulfillment"].name }
    analytics   = { CONSUMER = "analytics", DELIVERIES_TABLE = aws_dynamodb_table.deliveries["analytics"].name }
    replay = {
      FULFILLMENT_QUEUE = aws_sqs_queue.main["fulfillment"].id
      FULFILLMENT_DLQ   = aws_sqs_queue.dlq["fulfillment"].id
      ANALYTICS_QUEUE   = aws_sqs_queue.main["analytics"].id
      ANALYTICS_DLQ     = aws_sqs_queue.dlq["analytics"].id
    }
  }
}

resource "aws_kms_key" "orders" {
  description             = "PulseRoute ${var.prefix} message encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # The account administers the key through IAM, but administration is not use.
      { Sid = "AccountAdministration", Effect = "Allow", Principal = { AWS = "arn:aws:iam::${local.account}:root" },
      Action = local.key_administration, Resource = "*" },
      # IAM may grant use of the key to the four execution roles and nobody else;
      # their identity policies then limit each one to its own service.
      { Sid    = "ExecutionRolesOnly", Effect = "Allow", Principal = { AWS = "arn:aws:iam::${local.account}:root" },
        Action = ["kms:GenerateDataKey", "kms:Decrypt"], Resource = "*",
      Condition = { ArnEquals = { "aws:PrincipalArn" = local.role_arns } } },
      # SNS encrypts deliveries into the encrypted queues for this account only.
      { Sid    = "SnsDeliveries", Effect = "Allow", Principal = { Service = "sns.amazonaws.com" },
        Action = ["kms:GenerateDataKey", "kms:Decrypt"], Resource = "*",
      Condition = { StringEquals = { "aws:SourceAccount" = local.account } } },
    ]
  })
}

resource "aws_kms_alias" "orders" {
  name          = "alias/${var.prefix}-pulseroute"
  target_key_id = aws_kms_key.orders.key_id
}

resource "aws_sns_topic" "orders" {
  name              = "${var.prefix}-orders"
  kms_master_key_id = aws_kms_key.orders.arn
}

resource "aws_sns_topic_policy" "orders" {
  arn = aws_sns_topic.orders.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublisherOnly"
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.lambda["publisher"].arn }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.orders.arn
    }]
  })
}

resource "aws_dynamodb_table" "deliveries" {
  for_each                    = local.consumers
  name                        = "${var.prefix}-${each.key}-deliveries"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "delivery_id"
  deletion_protection_enabled = var.table_deletion_protection
  attribute {
    name = "delivery_id"
    type = "S"
  }
  point_in_time_recovery {
    enabled = true
  }
  # Omission leaves live TTL unmanaged; receipts must never expire, even after drift.
  ttl {
    attribute_name = "processed_at"
    enabled        = false
  }
}

resource "aws_sqs_queue" "dlq" {
  for_each                          = local.consumers
  name                              = "${var.prefix}-${each.key}-dlq"
  message_retention_seconds         = 1209600
  visibility_timeout_seconds        = 30
  kms_master_key_id                 = aws_kms_key.orders.arn
  kms_data_key_reuse_period_seconds = 86400
}

# A standard queue's messages expire by their original enqueue time even after
# they move to the DLQ, so 14 days of DLQ retention leaves 8 days for replay
# only if a message spent at most 6 days in its main queue.
resource "aws_sqs_queue" "main" {
  for_each                          = local.consumers
  name                              = "${var.prefix}-${each.key}"
  visibility_timeout_seconds        = 6 * local.worker_timeout
  message_retention_seconds         = 518400
  kms_master_key_id                 = aws_kms_key.orders.arn
  kms_data_key_reuse_period_seconds = 86400
}

# Separate redrive resources avoid the main <-> DLQ reference cycle and let all
# four queues be deleted in parallel (each SQS delete waits about two minutes).
resource "aws_sqs_queue_redrive_policy" "main" {
  for_each  = local.consumers
  queue_url = aws_sqs_queue.main[each.key].id
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq[each.key].arn
    maxReceiveCount     = 2
  })
}

resource "aws_sqs_queue_redrive_allow_policy" "dlq" {
  for_each  = local.consumers
  queue_url = aws_sqs_queue.dlq[each.key].id
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.main[each.key].arn]
  })
}

# Without this, SQS lets any queue in the account dead-letter into a main queue.
resource "aws_sqs_queue_redrive_allow_policy" "main" {
  for_each             = local.consumers
  queue_url            = aws_sqs_queue.main[each.key].id
  redrive_allow_policy = jsonencode({ redrivePermission = "denyAll" })
}

resource "aws_sqs_queue_policy" "from_topic" {
  for_each  = local.consumers
  queue_url = aws_sqs_queue.main[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowOrderTopic"
      Effect    = "Allow"
      Principal = { Service = "sns.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.main[each.key].arn
      Condition = { ArnEquals = { "aws:SourceArn" = aws_sns_topic.orders.arn } }
    }]
  })
}

resource "aws_sns_topic_subscription" "queue" {
  for_each             = local.consumers
  topic_arn            = aws_sns_topic.orders.arn
  protocol             = "sqs"
  endpoint             = aws_sqs_queue.main[each.key].arn
  raw_message_delivery = true
  filter_policy_scope  = "MessageBody"
  filter_policy = jsonencode({
    source = ["pulseroute.orders"]
    detail = merge(local.routes[each.key], { kind = ["order.created", "order.cancelled"] })
  })
  depends_on = [aws_sqs_queue_policy.from_topic]
}

resource "aws_iam_role" "lambda" {
  for_each              = local.services
  name                  = "${var.prefix}-${each.key}-lambda"
  force_detach_policies = true
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "service" {
  for_each = local.services
  name     = "${var.prefix}-${each.key}"
  role     = aws_iam_role.lambda[each.key].id
  policy   = jsonencode({ Version = "2012-10-17", Statement = local.role_statements[each.key] })
}

# Exclusive resources remove inline policies and attachments added out of band.
resource "aws_iam_role_policies_exclusive" "service" {
  for_each     = local.services
  role_name    = aws_iam_role.lambda[each.key].name
  policy_names = [aws_iam_role_policy.service[each.key].name]
}

resource "aws_iam_role_policy_attachments_exclusive" "service" {
  for_each    = local.services
  role_name   = aws_iam_role.lambda[each.key].name
  policy_arns = []
}

resource "aws_lambda_function" "service" {
  for_each      = local.services
  function_name = "${var.prefix}-${each.key}"
  package_type  = "Image"
  image_uri     = local.images[each.key]
  role          = aws_iam_role.lambda[each.key].arn
  timeout       = local.worker_timeout
  memory_size   = 256
  # Keep the value explicit through import and apply-time plan expansion.
  publish = false
  # Floci reports an empty image configuration; declaring it keeps repeat plans clean.
  image_config {}
  environment {
    variables = local.environment[each.key]
  }
  depends_on = [aws_iam_role_policies_exclusive.service]
}

resource "aws_lambda_event_source_mapping" "worker" {
  for_each                = local.consumers
  event_source_arn        = aws_sqs_queue.main[each.key].arn
  function_name           = aws_lambda_function.service[each.key].arn
  batch_size              = 5
  function_response_types = ["ReportBatchItemFailures"]
  enabled                 = true
  # Caps concurrent batches without reserved concurrency, which would throttle
  # batches and push them toward the DLQ.
  scaling_config {
    maximum_concurrency = 3
  }
}

# No force_destroy: Floci does not implement the SSH-key and certificate listings
# it triggers. The convergence pass removes stray keys and group memberships first.
resource "aws_iam_user" "caller" {
  for_each = local.callers
  name     = "${var.prefix}-${each.key}-caller"
}

resource "aws_iam_access_key" "caller" {
  for_each = local.callers
  user     = aws_iam_user.caller[each.key].name
}

resource "aws_iam_user_policy" "caller" {
  for_each = local.invokes
  name     = "${var.prefix}-${each.key}-invoke"
  user     = aws_iam_user.caller[each.key].name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["lambda:InvokeFunction"], Resource = aws_lambda_function.service[each.value].arn }]
  })
}

resource "aws_iam_user_policies_exclusive" "caller" {
  for_each     = local.callers
  user_name    = aws_iam_user.caller[each.key].name
  policy_names = [for name, policy in aws_iam_user_policy.caller : policy.name if name == each.key]
}

resource "aws_iam_user_policy_attachments_exclusive" "caller" {
  for_each    = local.callers
  user_name   = aws_iam_user.caller[each.key].name
  policy_arns = []
}

output "manifest" {
  sensitive = true
  value = {
    prefix    = var.prefix
    endpoint  = var.endpoint
    region    = var.region
    account   = local.account
    topic     = aws_sns_topic.orders.arn
    key       = aws_kms_key.orders.arn
    functions = { for name, function in aws_lambda_function.service : name => function.function_name }
    queues    = { for name, queue in aws_sqs_queue.main : name => queue.id }
    dlqs      = { for name, queue in aws_sqs_queue.dlq : name => queue.id }
    tables    = { for name, table in aws_dynamodb_table.deliveries : name => table.name }
    callers = {
      for name, key in aws_iam_access_key.caller : name => {
        access_key_id     = key.id
        secret_access_key = key.secret
      }
    }
  }
}

# Identities the convergence pass keeps; everything else attached to them is removed.
output "owned" {
  value = {
    topic         = aws_sns_topic.orders.arn
    key           = aws_kms_key.orders.arn
    subscriptions = [for subscription in aws_sns_topic_subscription.queue : subscription.arn]
    queues        = concat([for queue in aws_sqs_queue.main : queue.arn], [for queue in aws_sqs_queue.dlq : queue.arn])
    dlq_urls      = [for queue in aws_sqs_queue.dlq : queue.id]
    tables        = [for table in aws_dynamodb_table.deliveries : table.name]
    functions     = [for function in aws_lambda_function.service : function.function_name]
    mappings      = [for mapping in aws_lambda_event_source_mapping.worker : mapping.uuid]
    caller_keys   = { for name, user in aws_iam_user.caller : user.name => aws_iam_access_key.caller[name].id }
  }
}
