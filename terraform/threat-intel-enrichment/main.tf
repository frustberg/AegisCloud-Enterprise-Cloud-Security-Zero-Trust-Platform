terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

variable "permission_boundary_arn" {
  type = string
}

variable "guardduty_high_severity_rule_arn" {
  description = "Output from terraform/guardduty apply"
  type        = string
}

variable "guardduty_high_severity_rule_name" {
  description = "Name of the rule (needed for the target/permission resources)"
  type        = string
  default     = "aegiscloud-guardduty-high-severity"
}

variable "abuseipdb_api_key" {
  description = "Your free-tier AbuseIPDB API key - https://www.abuseipdb.com/api"
  type        = string
  sensitive   = true
}

# ---------------------------------------------------------------------------
# Store the API key in Secrets Manager rather than a plaintext Lambda env
# var — this is the correct pattern for any external API credential, and
# worth being able to explain why in an interview (env vars are visible to
# anyone with lambda:GetFunctionConfiguration; Secrets Manager access is a
# separate, auditable, rotatable IAM permission).
# ---------------------------------------------------------------------------
resource "aws_secretsmanager_secret" "abuseipdb_key" {
  name = "aegiscloud/abuseipdb-api-key"
  tags = { Project = "aegiscloud" }
}

resource "aws_secretsmanager_secret_version" "abuseipdb_key" {
  secret_id     = aws_secretsmanager_secret.abuseipdb_key.id
  secret_string = jsonencode({ api_key = var.abuseipdb_api_key })
}

data "archive_file" "enrich_finding" {
  type        = "zip"
  source_file = "${path.module}/../../lambda/enrich_guardduty_with_threatintel.py"
  output_path = "${path.module}/build/enrich_guardduty_with_threatintel.zip"
}

resource "aws_iam_role" "enrich_finding_role" {
  name                 = "aegiscloud-enrich-finding-role"
  permissions_boundary = var.permission_boundary_arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "enrich_finding_policy" {
  name = "enrich-finding-scoped"
  role = aws_iam_role.enrich_finding_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "securityhub:BatchImportFindings"
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = aws_secretsmanager_secret.abuseipdb_key.arn
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_lambda_function" "enrich_finding" {
  function_name    = "aegiscloud-enrich-guardduty-threatintel"
  role             = aws_iam_role.enrich_finding_role.arn
  handler          = "enrich_guardduty_with_threatintel.lambda_handler"
  runtime          = "python3.12"
  timeout          = 15
  filename         = data.archive_file.enrich_finding.output_path
  source_code_hash = data.archive_file.enrich_finding.output_base64sha256
  tags             = { Project = "aegiscloud" }

  environment {
    variables = {
      ABUSEIPDB_SECRET_NAME = aws_secretsmanager_secret.abuseipdb_key.name
      AWS_ACCOUNT_ID          = data.aws_caller_identity.current.account_id
    }
  }
}

resource "aws_cloudwatch_event_target" "enrich_finding_target" {
  rule = var.guardduty_high_severity_rule_name
  arn  = aws_lambda_function.enrich_finding.arn
}

resource "aws_lambda_permission" "allow_eventbridge_enrich" {
  statement_id  = "AllowEventBridgeInvokeEnrichment"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.enrich_finding.function_name
  principal     = "events.amazonaws.com"
  source_arn    = var.guardduty_high_severity_rule_arn
}
