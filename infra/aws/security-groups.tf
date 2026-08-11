# Security groups.
#
# Every rule references another security group, never a CIDR, so the graph below *is* the
# access-control policy. Read the `source_security_group_id` fields top to bottom and you have
# the whole story:
#
#   internet ──► alb ──► control-plane ──► engine-api
#                            │  │              │
#                            │  └──► database  │
#                            └────────► kafka ◄┘
#                                         ▲
#                                  engine-worker ──► the internet (targets under test)
#
# The worker has no ingress rule at all. Not a narrow one - none. Nothing in this account can
# open a connection to it, which is the point: it is the component that parses adversarial
# output from systems it is attacking.

resource "aws_security_group" "alb" {
  name        = "${local.name}-alb"
  description = "Public load balancer."
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${local.name}-alb" }
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  for_each = local.tls_enabled ? toset(var.allowed_ingress_cidrs) : toset([])

  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from an explicitly allowed range."
  cidr_ipv4         = each.value
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  for_each = local.tls_enabled ? toset([]) : toset(var.allowed_ingress_cidrs)

  security_group_id = aws_security_group.alb.id
  description       = "HTTP. Only reachable when no certificate is configured; see README."
  cidr_ipv4         = each.value
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_control_plane" {
  security_group_id            = aws_security_group.alb.id
  description                  = "Forward to the control plane."
  referenced_security_group_id = aws_security_group.control_plane.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_security_group" "control_plane" {
  name        = "${local.name}-control-plane"
  description = "Java control plane. Reachable only from the load balancer."
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${local.name}-control-plane" }
}

resource "aws_vpc_security_group_ingress_rule" "control_plane_from_alb" {
  security_group_id            = aws_security_group.control_plane.id
  description                  = "The only way in."
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "control_plane_out" {
  security_group_id = aws_security_group.control_plane.id
  description       = "Database, broker, engine API and the AWS endpoints. Not narrowed by port because the destinations are already constrained by their own ingress rules."
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_security_group" "engine_api" {
  name        = "${local.name}-engine-api"
  description = "Python engine API. Internal only."
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${local.name}-engine-api" }
}

resource "aws_vpc_security_group_ingress_rule" "engine_api_from_control_plane" {
  security_group_id            = aws_security_group.engine_api.id
  description                  = "Synchronous dispatch from the control plane."
  referenced_security_group_id = aws_security_group.control_plane.id
  from_port                    = 8081
  to_port                      = 8081
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "engine_api_out" {
  security_group_id = aws_security_group.engine_api.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_security_group" "engine_worker" {
  name        = "${local.name}-engine-worker"
  description = "Scan worker. No ingress rules by design - nothing may open a connection to it."
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${local.name}-engine-worker" }
}

# Deliberately no aws_vpc_security_group_ingress_rule for the worker.
#
# It consumes from Kafka and calls out to targets; both are outbound. An empty ingress set is
# the strongest statement available here, and it is worth more than any inbound rule could be:
# the worker is the process that renders attacker-influenced trajectories into reports.

resource "aws_vpc_security_group_egress_rule" "engine_worker_out" {
  security_group_id = aws_security_group.engine_worker.id
  description       = "Kafka, the control plane, the model API and the targets under test. Egress is the product."
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_security_group" "database" {
  name        = "${local.name}-database"
  description = "PostgreSQL. Control plane only."
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${local.name}-database" }
}

resource "aws_vpc_security_group_ingress_rule" "database_from_control_plane" {
  security_group_id            = aws_security_group.database.id
  description                  = "The control plane owns the schema; nothing else connects."
  referenced_security_group_id = aws_security_group.control_plane.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_security_group" "kafka" {
  name        = "${local.name}-kafka"
  description = "MSK Serverless."
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${local.name}-kafka" }
}

resource "aws_vpc_security_group_ingress_rule" "kafka_from_control_plane" {
  security_group_id            = aws_security_group.kafka.id
  description                  = "Producer."
  referenced_security_group_id = aws_security_group.control_plane.id
  from_port                    = 9098
  to_port                      = 9098
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "kafka_from_engine_worker" {
  security_group_id            = aws_security_group.kafka.id
  description                  = "Consumer."
  referenced_security_group_id = aws_security_group.engine_worker.id
  from_port                    = 9098
  to_port                      = 9098
  ip_protocol                  = "tcp"
}

resource "aws_security_group" "vpc_endpoints" {
  name        = "${local.name}-vpc-endpoints"
  description = "Interface endpoints for the AWS APIs."
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${local.name}-vpc-endpoints" }
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_tasks" {
  for_each = {
    control_plane = aws_security_group.control_plane.id
    engine_api    = aws_security_group.engine_api.id
    engine_worker = aws_security_group.engine_worker.id
  }

  security_group_id            = aws_security_group.vpc_endpoints.id
  description                  = "HTTPS from ${each.key}."
  referenced_security_group_id = each.value
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}
