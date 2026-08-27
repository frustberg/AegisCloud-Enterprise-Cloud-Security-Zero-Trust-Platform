terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-south-1"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ---------------------------------------------------------------------------
# This module replaces (or sits alongside) the static EC2 demo app with a
# real containerized workload — the point is to demonstrate container/
# application security, not just network/identity security: image
# scanning, task-level IAM (not instance-level), and a private ALB instead
# of a bare EC2 instance. This is what broadens the project from "network
# security engineer" territory into "cloud security engineer" territory.
# ---------------------------------------------------------------------------

variable "vpc_id" {
  type = string
}
variable "workloads_subnet_ids" {
  type = list(string)
}
variable "permission_boundary_arn" {
  type = string
}

# ---------------------------------------------------------------------------
# ECR repository with scan-on-push enabled — every image you push gets
# scanned by Amazon Inspector (basic scanning is free) for known CVEs
# before it's ever eligible to run. This is the "shift-left" equivalent
# for container images that Phase 11's Checkov/OPA gate is for Terraform.
# ---------------------------------------------------------------------------
resource "aws_ecr_repository" "demo_app" {
  name                 = "aegiscloud-demo-app"
  image_tag_mutability = "IMMUTABLE" # prevents tag overwriting - a real supply-chain hardening measure

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
  }

  tags = { Project = "aegiscloud" }
}

resource "aws_ecr_repository_policy" "demo_app" {
  repository = aws_ecr_repository.demo_app.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyPullFromOutsideThisAccount"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
        Condition = {
          StringNotEquals = {
            "aws:PrincipalAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# ECS cluster + Fargate service — no EC2 instances to patch, no SSH
# surface at all. Task role is scoped to exactly what the app needs
# (nothing, in this demo — but the pattern is what matters: task-level
# IAM, not instance-level, so two tasks on the same infrastructure never
# share credentials).
# ---------------------------------------------------------------------------
resource "aws_ecs_cluster" "aegiscloud" {
  name = "aegiscloud-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = { Project = "aegiscloud" }
}

resource "aws_iam_role" "ecs_task_execution" {
  name                 = "aegiscloud-ecs-task-execution-role"
  permissions_boundary = var.permission_boundary_arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_managed" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# The TASK role (what the running container itself can do) is deliberately
# near-empty — this app doesn't need to call any AWS API. If you extend the
# demo app to do something real (read from DynamoDB, write to S3), add
# ONLY those specific permissions here, scoped to specific resource ARNs.
resource "aws_iam_role" "ecs_task" {
  name                 = "aegiscloud-ecs-task-role"
  permissions_boundary = var.permission_boundary_arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_ecs_task_definition" "demo_app" {
  family                   = "aegiscloud-demo-app"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name         = "demo-app"
      image        = "${aws_ecr_repository.demo_app.repository_url}:latest"
      essential    = true
      portMappings = [{ containerPort = 8080, protocol = "tcp" }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.demo_app.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "demo-app"
        }
      }
      # Container-level security hardening — non-root, read-only root FS.
      # Matches the Dockerfile in docs/demo-app-dockerfile — build your own
      # image with this Dockerfile and push it to the ECR repo above.
      readonlyRootFilesystem = true
      user                   = "1000:1000"
    }
  ])

  tags = { Project = "aegiscloud" }
}

resource "aws_kms_key" "logs" {
  description             = "KMS key for CloudWatch Logs"
  deletion_window_in_days = 7
}

resource "aws_cloudwatch_log_group" "demo_app" {
  name              = "/ecs/aegiscloud-demo-app"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.logs.arn

  tags = {
    Project = "aegiscloud"
  }
}



# ---------------------------------------------------------------------------
# Internal ALB — private (no internet-facing listener), sits inside the
# workloads tier, fronted by Verified Access (see the endpoint update in
# verified-access/fargate-endpoint.tf).
# ---------------------------------------------------------------------------
resource "aws_security_group" "alb" {
  name        = "aegiscloud-fargate-alb-sg"
  description = "Internal ALB - only reachable from within the VPC (Verified Access)"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.42.0.0/16"]
  }
  egress {
    description = "Outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Project = "aegiscloud" }
}

resource "aws_security_group" "fargate_service" {
  name        = "aegiscloud-fargate-service-sg"
  description = "Only allows inbound from the internal ALB"
  vpc_id      = var.vpc_id

  ingress {
    description     = "HTTP from VPC"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    description = "Outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Project = "aegiscloud" }
}

resource "aws_s3_bucket" "alb_logs" {
  bucket = "aegiscloud-alb-logs-600294641908"
}

resource "aws_lb" "internal" {
  name               = "aegiscloud-internal-alb"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.workloads_subnet_ids

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    enabled = true
  }

  tags = { Project = "aegiscloud" }
}

resource "aws_lb_target_group" "demo_app" {
  name        = "aegiscloud-demo-app-tg"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip" # required for Fargate awsvpc networking

  health_check {
    path                = "/health"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
  }

  tags = { Project = "aegiscloud" }
}

resource "aws_lb_listener" "demo_app" {
  load_balancer_arn = aws_lb.internal.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.demo_app.arn
  }
}

resource "aws_ecs_service" "demo_app" {
  name            = "aegiscloud-demo-app-service"
  cluster         = aws_ecs_cluster.aegiscloud.id
  task_definition = aws_ecs_task_definition.demo_app.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.workloads_subnet_ids
    security_groups  = [aws_security_group.fargate_service.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.demo_app.arn
    container_name   = "demo-app"
    container_port   = 8080
  }

  depends_on = [aws_lb_listener.demo_app]
  tags       = { Project = "aegiscloud" }
}

output "ecr_repository_url" {
  value = aws_ecr_repository.demo_app.repository_url
}
output "internal_alb_arn" {
  value = aws_lb.internal.arn
}
output "internal_alb_dns_name" {
  value = aws_lb.internal.dns_name
}
