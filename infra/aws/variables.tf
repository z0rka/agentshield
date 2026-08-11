variable "region" {
  description = "AWS region."
  type        = string
  default     = "eu-west-1"
}

variable "environment" {
  description = "Environment name. Used in resource names, so it has to be DNS-safe."
  type        = string
  default     = "dev"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,15}$", var.environment))
    error_message = "environment must be lowercase alphanumeric with hyphens, 2-16 characters."
  }
}

variable "vpc_cidr" {
  description = "CIDR for the VPC. /16 leaves room for the /20 subnets below."
  type        = string
  default     = "10.40.0.0/16"
}

variable "availability_zone_count" {
  description = "How many AZs to spread across. Two is the minimum an ALB accepts."
  type        = number
  default     = 2

  validation {
    condition     = var.availability_zone_count >= 2
    error_message = "an ALB requires subnets in at least two availability zones."
  }
}

variable "control_plane_image" {
  description = "Container image for the Java control plane, including tag."
  type        = string
}

variable "engine_image" {
  description = "Container image for the Python security engine. The API and the worker are the same image with different commands."
  type        = string
}

variable "control_plane_desired_count" {
  description = "Control plane tasks. Two so a deployment is not an outage."
  type        = number
  default     = 2
}

variable "engine_api_desired_count" {
  description = "Engine API tasks."
  type        = number
  default     = 2
}

variable "engine_worker_desired_count" {
  description = "Worker tasks. Scans are queued, so this scales on lag, not on requests."
  type        = number
  default     = 2
}

variable "database_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t4g.micro"
}

variable "database_deletion_protection" {
  description = "Refuse `terraform destroy` on the database. Default on; the findings history is the product."
  type        = bool
  default     = true
}

variable "allowed_ingress_cidrs" {
  description = <<-EOT
    CIDRs allowed to reach the load balancer. Defaults to nothing: the first apply produces a
    reachable-by-no-one deployment, and opening it is an explicit act. `0.0.0.0/0` here with a
    permissive default would be exactly the mistake this project scans for.
  EOT
  type        = list(string)
  default     = []
}

variable "certificate_arn" {
  description = <<-EOT
    ACM certificate for the HTTPS listener. When empty the listener is HTTP only, which is
    acceptable for a private evaluation environment and nowhere else; the README says so and
    `local.tls_enabled` is what the rest of the configuration keys off.
  EOT
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "CloudWatch log retention. Scan logs can contain redacted evidence, so they are not kept forever."
  type        = number
  default     = 30
}

variable "judge_model" {
  description = "Model id for the LLM judges. Judges never gate CI on their own."
  type        = string
  default     = "claude-sonnet-5"
}

variable "max_concurrent_runs" {
  description = "Per-worker cap on concurrent scans. A scanner is a traffic generator; this is the throttle."
  type        = number
  default     = 10
}
