output "api_url" {
  description = "Base URL for the control plane API."
  value       = "${local.tls_enabled ? "https" : "http"}://${aws_lb.main.dns_name}"
}

output "cluster_name" {
  description = "ECS cluster name."
  value       = aws_ecs_cluster.main.name
}

output "database_endpoint" {
  description = "RDS endpoint. Reachable only from the control plane security group."
  value       = aws_db_instance.main.endpoint
}

output "kafka_bootstrap_servers" {
  description = "MSK Serverless bootstrap, IAM SASL."
  value       = aws_msk_serverless_cluster.main.bootstrap_brokers_sasl_iam
}

output "secrets_to_populate" {
  description = <<-EOT
    Secrets Terraform created empty. Each needs a value before the services will start; the
    README has the commands. Terraform creates the container and never the contents, so no
    secret value is recoverable from state.
  EOT
  value = {
    credential_key = aws_secretsmanager_secret.credential_key.name
    internal_token = aws_secretsmanager_secret.internal_token.name
    judge_api_key  = aws_secretsmanager_secret.judge_api_key.name
  }
}

output "reachable_from" {
  description = "CIDRs allowed to reach the load balancer. Empty means nobody, which is the default."
  value       = var.allowed_ingress_cidrs
}
