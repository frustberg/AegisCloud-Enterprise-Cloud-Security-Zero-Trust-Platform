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
  region = "ap-south-1"
}

data "aws_caller_identity" "current" {}

variable "permission_boundary_arn" {
  description = "Output from terraform/guardrails apply"
  type        = string
}

# ---------------------------------------------------------------------------
# AWS Config — single-account, no delegated admin / aggregator needed.
# ---------------------------------------------------------------------------



resource "aws_iam_role" "lambda_role" {

  name = "aegiscloud-remediation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"

      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_config_config_rule" "s3_public_read_prohibited" {
  name = "s3-bucket-public-read-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
  depends_on = []
}

resource "aws_config_config_rule" "restricted_ssh" {
  name = "restricted-ssh"
  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }
  depends_on = []
}

# New rule vs. the multi-account version — covers the "SCP can't restrict
# root, permission boundary can't either" gap noted in Phase 2; this at
# least gives you DETECTIVE coverage of root usage/MFA even though
# PREVENTIVE coverage of root isn't achievable in a single-account,
# no-Organizations-member-accounts setup.
resource "aws_config_config_rule" "root_mfa_enabled" {
  name = "root-account-mfa-enabled"
  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }
  depends_on = []
}

# ---------------------------------------------------------------------------
# Security Hub — single account, standards enabled directly, no aggregator.
# ---------------------------------------------------------------------------
resource "aws_securityhub_account" "aegiscloud" {}

resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:ap-south-1::standards/cis-aws-foundations-benchmark/v/1.4.0"
  depends_on    = [aws_securityhub_account.aegiscloud]
}

resource "aws_securityhub_standards_subscription" "nist" {
  standards_arn = "arn:aws:securityhub:ap-south-1::standards/nist-800-53/v/5.0.0"
  depends_on    = [aws_securityhub_account.aegiscloud]
}

# ---------------------------------------------------------------------------
# Lambda: S3 public-bucket remediation (unchanged logic from original design)
# ---------------------------------------------------------------------------
data "archive_file" "remediate_s3" {
  type        = "zip"
  source_file = "${path.module}/../../lambda/remediate_s3_public.py"
  output_path = "${path.module}/build/remediate_s3_public.zip"
}

resource "aws_iam_role" "remediate_s3_role" {
  name                 = "aegiscloud-remediate-s3-role"
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

resource "aws_iam_role_policy" "remediate_s3_policy" {
  name = "remediate-s3-scoped"
  role = aws_iam_role.remediate_s3_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketAcl", "s3:PutBucketAcl",
          "s3:PutPublicAccessBlock", "s3:GetPublicAccessBlock",
          "s3:GetBucketPolicyStatus", "s3:PutBucketPolicy"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_lambda_function" "remediate_s3" {
  function_name    = "aegiscloud-remediate-s3-public"
  role             = aws_iam_role.remediate_s3_role.arn
  handler          = "remediate_s3_public.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  filename         = data.archive_file.remediate_s3.output_path
  source_code_hash = data.archive_file.remediate_s3.output_base64sha256
  tags             = { Project = "aegiscloud" }
}

# ---------------------------------------------------------------------------
# Lambda: Security group remediation (unchanged logic from original design)
# ---------------------------------------------------------------------------
data "archive_file" "remediate_sg" {
  type        = "zip"
  source_file = "${path.module}/../../lambda/remediate_sg_open.py"
  output_path = "${path.module}/build/remediate_sg_open.zip"
}

resource "aws_iam_role" "remediate_sg_role" {
  name                 = "aegiscloud-remediate-sg-role"
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

resource "aws_iam_role_policy" "remediate_sg_policy" {
  name = "remediate-sg-scoped"
  role = aws_iam_role.remediate_sg_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ec2:DescribeSecurityGroups", "ec2:RevokeSecurityGroupIngress"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_lambda_function" "remediate_sg" {
  function_name    = "aegiscloud-remediate-sg-open"
  role             = aws_iam_role.remediate_sg_role.arn
  handler          = "remediate_sg_open.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  filename         = data.archive_file.remediate_sg.output_path
  source_code_hash = data.archive_file.remediate_sg.output_base64sha256
  tags             = { Project = "aegiscloud" }
}

# ---------------------------------------------------------------------------
# EventBridge — Config compliance-change events trigger the right Lambda
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "config_compliance_change" {
  name = "aegiscloud-config-compliance-change"
  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      configRuleName      = ["s3-bucket-public-read-prohibited", "restricted-ssh"]
      newEvaluationResult = { complianceType = ["NON_COMPLIANT"] }
    }
  })
}

resource "aws_cloudwatch_event_target" "s3_remediation_target" {
  rule = aws_cloudwatch_event_rule.config_compliance_change.name
  arn  = aws_lambda_function.remediate_s3.arn
}

resource "aws_cloudwatch_event_target" "sg_remediation_target" {
  rule = aws_cloudwatch_event_rule.config_compliance_change.name
  arn  = aws_lambda_function.remediate_sg.arn
}

resource "aws_lambda_permission" "allow_eventbridge_s3" {
  statement_id  = "AllowEventBridgeInvokeS3Remediation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediate_s3.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.config_compliance_change.arn
}

resource "aws_lambda_permission" "allow_eventbridge_sg" {
  statement_id  = "AllowEventBridgeInvokeSgRemediation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediate_sg.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.config_compliance_change.arn
}
