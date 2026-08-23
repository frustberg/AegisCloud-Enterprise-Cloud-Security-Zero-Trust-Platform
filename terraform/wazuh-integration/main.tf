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

variable "permission_boundary_arn" {
  type = string
}

# ---------------------------------------------------------------------------
# Dedicated bucket for findings your Wazuh manager will pull from. Separate
# from the Config delivery bucket so the Wazuh reader credential's access
# can be scoped to exactly this one bucket and nothing else Config writes.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "findings_export" {
  bucket = "aegiscloud-findings-export-${data.aws_caller_identity.current.account_id}"
  tags   = { Project = "aegiscloud" }
}

resource "aws_s3_bucket_public_access_block" "findings_export" {
  bucket                  = aws_s3_bucket.findings_export.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle rule so this doesn't grow forever during testing.
resource "aws_s3_bucket_lifecycle_configuration" "findings_export" {
  bucket = aws_s3_bucket.findings_export.id
  rule {
    id     = "expire-old-findings"
    status = "Enabled"
    expiration {
      days = 30
    }
  }
}

# ---------------------------------------------------------------------------
# Lambda: writes each incoming Security Hub finding as a JSON object into
# S3. Replaces the "push to Wazuh over the internet" Lambda from the
# original design — this direction (AWS -> S3) requires no network path
# into your home network at all.
# ---------------------------------------------------------------------------
data "archive_file" "export_findings" {
  type        = "zip"
  source_file = "${path.module}/../../lambda/export_findings_to_s3.py"
  output_path = "${path.module}/build/export_findings_to_s3.zip"
}

resource "aws_iam_role" "export_findings_role" {
  name                 = "aegiscloud-export-findings-role"
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

resource "aws_iam_role_policy" "export_findings_policy" {
  name = "export-findings-scoped"
  role = aws_iam_role.export_findings_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.findings_export.arn}/securityhub-findings/*"
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_lambda_function" "export_findings" {
  function_name    = "aegiscloud-export-findings-to-s3"
  role             = aws_iam_role.export_findings_role.arn
  handler          = "export_findings_to_s3.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  filename         = data.archive_file.export_findings.output_path
  source_code_hash = data.archive_file.export_findings.output_base64sha256
  tags             = { Project = "aegiscloud" }

  environment {
    variables = {
      TARGET_BUCKET = aws_s3_bucket.findings_export.id
      TARGET_PREFIX = "securityhub-findings/"
    }
  }
}

resource "aws_cloudwatch_event_rule" "securityhub_finding_imported" {
  name = "aegiscloud-securityhub-finding-imported"
  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
  })
}

resource "aws_cloudwatch_event_target" "export_findings_target" {
  rule = aws_cloudwatch_event_rule.securityhub_finding_imported.name
  arn  = aws_lambda_function.export_findings.arn
}

resource "aws_lambda_permission" "allow_eventbridge_export" {
  statement_id  = "AllowEventBridgeInvokeExportFindings"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.export_findings.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.securityhub_finding_imported.arn
}

# ---------------------------------------------------------------------------
# IAM user + access key for the Wazuh manager's aws-s3 wodle. This is the
# ONLY credential involved in the entire SIEM integration, and it can do
# exactly one thing: read objects from this one bucket/prefix. It cannot
# write, delete, list other buckets, or touch anything else in the account.
#
# In a production environment you'd avoid long-lived access keys entirely
# (use IAM Roles Anywhere from the Wazuh VM instead) - noted as a stated
# limitation/future improvement in docs/wazuh-virtualbox-setup.md, worth
# mentioning proactively in an interview as something you'd harden next.
# ---------------------------------------------------------------------------
resource "aws_iam_user" "wazuh_reader" {
  name                 = "aegiscloud-wazuh-reader"
  permissions_boundary = var.permission_boundary_arn
  tags                 = { Project = "aegiscloud" }
}

resource "aws_iam_user_policy" "wazuh_reader_policy" {
  name = "wazuh-s3-readonly-scoped"
  user = aws_iam_user.wazuh_reader.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.findings_export.arn}/securityhub-findings/*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.findings_export.arn
        Condition = {
          StringLike = { "s3:prefix" = ["securityhub-findings/*"] }
        }
      }
    ]
  })
}

resource "aws_iam_access_key" "wazuh_reader_key" {
  user = aws_iam_user.wazuh_reader.name
}

output "findings_bucket_name" {
  value = aws_s3_bucket.findings_export.id
}

output "aegiscloud_wazuh_reader_access_key_id" {
  value = aws_iam_access_key.wazuh_reader_key.id
}

output "aegiscloud_wazuh_reader_secret_access_key" {
  value     = aws_iam_access_key.wazuh_reader_key.secret
  sensitive = true
}
