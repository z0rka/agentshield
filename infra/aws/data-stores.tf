# PostgreSQL and Kafka.
#
# Both managed. The interesting property of a scan platform is not that it can run its own
# broker; running one badly is a way to lose findings, and findings are the product.

resource "aws_db_subnet_group" "main" {
  name       = local.name
  subnet_ids = [for subnet in aws_subnet.private : subnet.id]
}

resource "aws_kms_key" "database" {
  description             = "AgentShield database encryption (${var.environment})."
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "database" {
  name          = "alias/${local.name}-database"
  target_key_id = aws_kms_key.database.key_id
}

resource "aws_db_instance" "main" {
  identifier     = local.name
  engine         = "postgres"
  engine_version = "16"
  instance_class = var.database_instance_class

  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.database.arn

  db_name  = "agentshield"
  username = "agentshield"
  # Rotated by RDS into Secrets Manager. The alternative leaves a password in Terraform
  # state, a plaintext credential in an S3 bucket no matter how the variable is declared.
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.database.key_id

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.database.id]
  publicly_accessible    = false
  multi_az               = var.environment == "prod"

  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:30-sun:05:30"

  auto_minor_version_upgrade = true
  deletion_protection        = var.database_deletion_protection
  skip_final_snapshot        = false
  final_snapshot_identifier  = "${local.name}-final"

  enabled_cloudwatch_logs_exports = ["postgresql"]
  performance_insights_enabled    = true

  # Findings are append-mostly and the audit log is the reason this database matters. Point-in-
  # time recovery is the only thing standing between a bad migration and losing the history a
  # regression baseline is compared against.
  copy_tags_to_snapshot = true
}

resource "aws_msk_serverless_cluster" "main" {
  cluster_name = local.name

  vpc_config {
    subnet_ids         = [for subnet in aws_subnet.private : subnet.id]
    security_group_ids = [aws_security_group.kafka.id]
  }

  client_authentication {
    sasl {
      iam {
        enabled = true
      }
    }
  }
}

# Secrets the services read at start-up. Values are set out of band - `terraform apply` creates
# the container, never the contents, so a secret is not readable from state.
resource "aws_secretsmanager_secret" "credential_key" {
  name        = "${local.name}/credential-key"
  description = "AES-256 key for target credential encryption. 32 bytes, base64. Set out of band."
  kms_key_id  = aws_kms_key.database.id

  recovery_window_in_days = 30
}

resource "aws_secretsmanager_secret" "internal_token" {
  name        = "${local.name}/internal-token"
  description = "Shared token for control-plane-to-engine calls. Set out of band."
  kms_key_id  = aws_kms_key.database.id

  recovery_window_in_days = 30
}

resource "aws_secretsmanager_secret" "judge_api_key" {
  name        = "${local.name}/judge-api-key"
  description = "Anthropic API key for the LLM judges. Only the worker may read it."
  kms_key_id  = aws_kms_key.database.id

  recovery_window_in_days = 30
}
