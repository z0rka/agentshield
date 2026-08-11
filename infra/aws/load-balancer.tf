resource "aws_lb" "main" {
  name               = local.name
  load_balancer_type = "application"
  internal           = false
  subnets            = [for subnet in aws_subnet.public : subnet.id]
  security_groups    = [aws_security_group.alb.id]

  # An ALB that quietly forwards conflicting Content-Length and Transfer-Encoding headers is a
  # request-smuggling primitive. Dropping them is the default in newer ALBs; setting it makes
  # the choice reviewable.
  drop_invalid_header_fields = true
  enable_deletion_protection = var.environment == "prod"
  idle_timeout               = 120
}

resource "aws_lb_target_group" "control_plane" {
  name        = "${local.name}-cp"
  port        = 8080
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.main.id

  health_check {
    path                = "/actuator/health"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 15
    timeout             = 5
    matcher             = "200"
  }

  # Long enough for a queued request to finish, short enough that a deployment is not a wait.
  deregistration_delay = 30
}

resource "aws_lb_listener" "main" {
  load_balancer_arn = aws_lb.main.arn
  port              = local.tls_enabled ? 443 : 80
  protocol          = local.tls_enabled ? "HTTPS" : "HTTP"
  ssl_policy        = local.tls_enabled ? "ELBSecurityPolicy-TLS13-1-2-2021-06" : null
  certificate_arn   = local.tls_enabled ? var.certificate_arn : null

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.control_plane.arn
  }
}

# Present only when TLS is configured, because a redirect to a port with no listener is worse
# than no redirect.
resource "aws_lb_listener" "redirect_to_https" {
  count = local.tls_enabled ? 1 : 0

  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
