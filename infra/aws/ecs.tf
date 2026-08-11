# ECS services.
#
# Three of them, and the third is the reason this is not a single container. The worker consumes
# scan events and runs the attacks; it is the only component that talks to the systems under
# test, and it is isolated accordingly - its own role, its own security group, no ingress.

resource "aws_ecs_cluster" "main" {
  name = local.name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_cluster_capacity_providers" "main" {
  cluster_name       = aws_ecs_cluster.main.name
  capacity_providers = ["FARGATE"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

resource "aws_cloudwatch_log_group" "services" {
  for_each = toset(["control-plane", "engine-api", "engine-worker"])

  name              = "/ecs/${local.name}/${each.key}"
  retention_in_days = var.log_retention_days
}

locals {
  kafka_bootstrap = aws_msk_serverless_cluster.main.bootstrap_brokers_sasl_iam

  # Every task gets these. Kept in one place so a new service cannot quietly ship without
  # tracing configured, which is how a distributed system becomes undebuggable.
  common_environment = [
    { name = "OTEL_EXPORTER_OTLP_ENDPOINT", value = "http://localhost:4317" },
    { name = "OTEL_TRACES_EXPORTER", value = "otlp" },
    { name = "AGENTSHIELD_ENVIRONMENT", value = var.environment },
  ]

  log_configuration = {
    for name in ["control-plane", "engine-api", "engine-worker"] :
    name => {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.services[name].name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }
}

resource "aws_ecs_task_definition" "control_plane" {
  family                   = "${local.name}-control-plane"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 1024
  memory                   = 2048
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.control_plane.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([{
    name      = "control-plane"
    image     = var.control_plane_image
    essential = true

    portMappings = [{ containerPort = 8080, protocol = "tcp" }]

    environment = concat(local.common_environment, [
      { name = "SPRING_PROFILES_ACTIVE", value = var.environment },
      { name = "POSTGRES_URL", value = "jdbc:postgresql://${aws_db_instance.main.endpoint}/agentshield" },
      { name = "POSTGRES_USER", value = "agentshield" },
      { name = "KAFKA_BOOTSTRAP_SERVERS", value = local.kafka_bootstrap },
      { name = "KAFKA_SECURITY_PROTOCOL", value = "SASL_SSL" },
      { name = "KAFKA_SASL_MECHANISM", value = "AWS_MSK_IAM" },
      { name = "AGENTSHIELD_ENGINE_URL", value = "http://${aws_service_discovery_service.engine_api.name}.${aws_service_discovery_private_dns_namespace.main.name}:8081" },
      { name = "OTEL_SERVICE_NAME", value = "agentshield-control-plane" },
    ])

    # Secrets are references, never values. A plaintext key in `environment` is readable by
    # anyone holding `ecs:DescribeTaskDefinition`, which is a much larger set of people than
    # anyone intends.
    secrets = [
      { name = "POSTGRES_PASSWORD", valueFrom = "${aws_db_instance.main.master_user_secret[0].secret_arn}:password::" },
      { name = "AGENTSHIELD_CREDENTIAL_KEY", valueFrom = aws_secretsmanager_secret.credential_key.arn },
      { name = "AGENTSHIELD_INTERNAL_TOKEN", valueFrom = aws_secretsmanager_secret.internal_token.arn },
    ]

    readonlyRootFilesystem = true
    user                   = "10001:10001"

    linuxParameters = {
      capabilities = { drop = ["ALL"] }
    }

    mountPoints = [{ sourceVolume = "tmp", containerPath = "/tmp", readOnly = false }]

    healthCheck = {
      command     = ["CMD-SHELL", "curl -fsS http://localhost:8080/actuator/health || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 60
    }

    logConfiguration = local.log_configuration["control-plane"]
  }])

  volume {
    name = "tmp"
  }
}

resource "aws_ecs_task_definition" "engine_api" {
  family                   = "${local.name}-engine-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 1024
  memory                   = 2048
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.engine_api.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([{
    name      = "engine-api"
    image     = var.engine_image
    essential = true

    portMappings = [{ containerPort = 8081, protocol = "tcp" }]

    environment = concat(local.common_environment, [
      { name = "OTEL_SERVICE_NAME", value = "agentshield-engine-api" },
    ])

    secrets = [
      { name = "AGENTSHIELD_INTERNAL_TOKEN", valueFrom = aws_secretsmanager_secret.internal_token.arn },
    ]

    readonlyRootFilesystem = true
    user                   = "10001:10001"

    linuxParameters = {
      capabilities = { drop = ["ALL"] }
    }

    mountPoints = [{ sourceVolume = "tmp", containerPath = "/tmp", readOnly = false }]

    healthCheck = {
      command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:8081/health')\" || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 30
    }

    logConfiguration = local.log_configuration["engine-api"]
  }])

  volume {
    name = "tmp"
  }
}

resource "aws_ecs_task_definition" "engine_worker" {
  family                   = "${local.name}-engine-worker"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 2048
  memory                   = 4096
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.engine_worker.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([{
    name      = "engine-worker"
    image     = var.engine_image
    essential = true
    command   = ["agentshield-engine-worker"]

    environment = concat(local.common_environment, [
      { name = "KAFKA_BOOTSTRAP_SERVERS", value = local.kafka_bootstrap },
      { name = "KAFKA_SECURITY_PROTOCOL", value = "SASL_SSL" },
      { name = "KAFKA_SASL_MECHANISM", value = "AWS_MSK_IAM" },
      { name = "AGENTSHIELD_KAFKA_GROUP_ID", value = "agentshield-security-engine" },
      { name = "AGENTSHIELD_MAX_CONCURRENT_RUNS", value = tostring(var.max_concurrent_runs) },
      { name = "AGENTSHIELD_JUDGE_MODEL", value = var.judge_model },
      { name = "AGENTSHIELD_CONTROL_PLANE_URL", value = "http://${aws_lb.main.dns_name}" },
      { name = "OTEL_SERVICE_NAME", value = "agentshield-engine-worker" },
    ])

    # No credential key here. The worker never decrypts a target configuration; it receives
    # what it needs in the dispatched event. See iam.tf.
    secrets = [
      { name = "AGENTSHIELD_INTERNAL_TOKEN", valueFrom = aws_secretsmanager_secret.internal_token.arn },
      { name = "ANTHROPIC_API_KEY", valueFrom = aws_secretsmanager_secret.judge_api_key.arn },
    ]

    readonlyRootFilesystem = true
    user                   = "10001:10001"

    linuxParameters = {
      capabilities = { drop = ["ALL"] }
    }

    mountPoints = [{ sourceVolume = "tmp", containerPath = "/tmp", readOnly = false }]

    logConfiguration = local.log_configuration["engine-worker"]
  }])

  volume {
    name = "tmp"
  }
}

resource "aws_service_discovery_private_dns_namespace" "main" {
  name = "${local.name}.internal"
  vpc  = aws_vpc.main.id
}

resource "aws_service_discovery_service" "engine_api" {
  name = "engine-api"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.main.id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }
}

resource "aws_ecs_service" "control_plane" {
  name            = "control-plane"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.control_plane.arn
  desired_count   = var.control_plane_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [for subnet in aws_subnet.private : subnet.id]
    security_groups  = [aws_security_group.control_plane.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.control_plane.arn
    container_name   = "control-plane"
    container_port   = 8080
  }

  # Roll forward only if the new tasks pass their health checks, and roll back automatically if
  # they do not. The alternative is a deployment that replaces a working control plane with a
  # crash-looping one and leaves it there.
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  health_check_grace_period_seconds  = 120
  enable_execute_command             = false

  depends_on = [aws_lb_listener.main]
}

resource "aws_ecs_service" "engine_api" {
  name            = "engine-api"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.engine_api.arn
  desired_count   = var.engine_api_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [for subnet in aws_subnet.private : subnet.id]
    security_groups  = [aws_security_group.engine_api.id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.engine_api.arn
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  enable_execute_command = false
}

resource "aws_ecs_service" "engine_worker" {
  name            = "engine-worker"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.engine_worker.arn
  desired_count   = var.engine_worker_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [for subnet in aws_subnet.private : subnet.id]
    security_groups  = [aws_security_group.engine_worker.id]
    assign_public_ip = false
  }

  # No load balancer and no service registry: nothing addresses the worker. It reads from Kafka.
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  # A scan in flight should finish, never be killed mid-trajectory, and a half-run scan is
  # the thing that produces a false all-clear.
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  enable_execute_command             = false
}
