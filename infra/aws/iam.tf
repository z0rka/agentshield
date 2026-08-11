# IAM.
#
# Execution roles pull images and write logs. Task roles are what the application code runs as,
# and they are separate per service so the blast radius of a compromised container is the set of
# things that one service legitimately does.
#
# The split that matters: the worker cannot read the credential encryption key. It never
# decrypts a target configuration - the control plane does that and dispatches the result - so
# granting it would be handing the most sensitive key in the system to the process that parses
# adversarial input.

data "aws_iam_policy_document" "ecs_task_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${local.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# The execution role resolves `secrets` entries in the task definition, so it needs read access
# to exactly those secrets and the key they are encrypted under. Listed explicitly, never
# wildcarded: `secretsmanager:GetSecretValue` on `*` is read access to every secret in the
# account, and it is the most common way this role is written.
data "aws_iam_policy_document" "execution_secrets" {
  statement {
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      aws_secretsmanager_secret.credential_key.arn,
      aws_secretsmanager_secret.internal_token.arn,
      aws_secretsmanager_secret.judge_api_key.arn,
      aws_db_instance.main.master_user_secret[0].secret_arn,
    ]
  }

  statement {
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.database.arn]
  }
}

resource "aws_iam_role_policy" "execution_secrets" {
  name   = "secrets"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution_secrets.json
}

resource "aws_iam_role" "control_plane" {
  name               = "${local.name}-control-plane"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json
}

data "aws_iam_policy_document" "control_plane" {
  statement {
    sid       = "ProduceScanEvents"
    actions   = ["kafka-cluster:Connect", "kafka-cluster:DescribeCluster"]
    resources = [aws_msk_serverless_cluster.main.arn]
  }

  statement {
    sid = "WriteTopics"
    actions = [
      "kafka-cluster:CreateTopic",
      "kafka-cluster:DescribeTopic",
      "kafka-cluster:WriteData",
    ]
    resources = ["${local.msk_topic_arn_prefix}/*"]
  }
}

resource "aws_iam_role_policy" "control_plane" {
  name   = "kafka"
  role   = aws_iam_role.control_plane.id
  policy = data.aws_iam_policy_document.control_plane.json
}

resource "aws_iam_role" "engine_api" {
  name               = "${local.name}-engine-api"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json
}

resource "aws_iam_role" "engine_worker" {
  name               = "${local.name}-engine-worker"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json
}

data "aws_iam_policy_document" "engine_worker" {
  statement {
    sid       = "ConsumeScanEvents"
    actions   = ["kafka-cluster:Connect", "kafka-cluster:DescribeCluster"]
    resources = [aws_msk_serverless_cluster.main.arn]
  }

  statement {
    sid = "ReadTopics"
    actions = [
      "kafka-cluster:DescribeTopic",
      "kafka-cluster:ReadData",
    ]
    resources = ["${local.msk_topic_arn_prefix}/*"]
  }

  statement {
    sid       = "JoinConsumerGroup"
    actions   = ["kafka-cluster:AlterGroup", "kafka-cluster:DescribeGroup"]
    resources = ["${local.msk_group_arn_prefix}/*"]
  }
}

resource "aws_iam_role_policy" "engine_worker" {
  name   = "kafka"
  role   = aws_iam_role.engine_worker.id
  policy = data.aws_iam_policy_document.engine_worker.json
}

data "aws_iam_policy_document" "flow_logs_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "${local.name}-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
}

data "aws_iam_policy_document" "flow_logs" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]
    resources = ["${aws_cloudwatch_log_group.flow_logs.arn}:*"]
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  name   = "write"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs.json
}

locals {
  # MSK topic and group ARNs are derived from the cluster ARN by substituting the resource type.
  # There is no attribute for them, and building the string from account/region separately is
  # how these end up pointing at a cluster that no longer exists.
  msk_cluster_arn_parts = split(":", aws_msk_serverless_cluster.main.arn)
  msk_arn_prefix        = join(":", slice(local.msk_cluster_arn_parts, 0, 5))
  msk_cluster_suffix    = replace(aws_msk_serverless_cluster.main.arn, "${local.msk_arn_prefix}:cluster/", "")

  msk_topic_arn_prefix = "${local.msk_arn_prefix}:topic/${local.msk_cluster_suffix}"
  msk_group_arn_prefix = "${local.msk_arn_prefix}:group/${local.msk_cluster_suffix}"
}
