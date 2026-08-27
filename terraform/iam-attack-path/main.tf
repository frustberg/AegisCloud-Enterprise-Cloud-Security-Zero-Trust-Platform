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
  type = string
}

# ---------------------------------------------------------------------------
# Reports bucket — Cloudsplaining runs in CI (see
# github-actions/iam-risk-scan.yml) and uploads its JSON report here, which
# triggers the ingestion Lambda below.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "cloudsplaining_reports" {
  bucket = "aegiscloud-cloudsplaining-reports-${data.aws_caller_identity.current.account_id}"
  tags   = { Project = "aegiscloud" }
}

resource "aws_s3_bucket_public_access_block" "cloudsplaining_reports" {
  bucket                  = aws_s3_bucket.cloudsplaining_reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudsplaining_reports" {
  bucket = aws_s3_bucket.cloudsplaining_reports.id
  rule {
    id     = "expire-old-reports"
    status = "Enabled"
    expiration { days = 90 }
  }
}

# ---------------------------------------------------------------------------
# Lambda: ingest the report into Security Hub on upload
# ---------------------------------------------------------------------------
data "archive_file" "ingest_findings" {
  type        = "zip"
  source_file = "${path.module}/../../lambda/ingest_cloudsplaining_findings.py"
  output_path = "${path.module}/build/ingest_cloudsplaining_findings.zip"
}

resource "aws_iam_role" "ingest_findings_role" {
  name                 = "aegiscloud-ingest-cloudsplaining-role"
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

resource "aws_iam_role_policy" "ingest_findings_policy" {
  name = "ingest-cloudsplaining-scoped"
  role = aws_iam_role.ingest_findings_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.cloudsplaining_reports.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = "securityhub:BatchImportFindings"
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

resource "aws_lambda_function" "ingest_findings" {
  function_name    = "aegiscloud-ingest-cloudsplaining"
  role             = aws_iam_role.ingest_findings_role.arn
  handler          = "ingest_cloudsplaining_findings.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60
  filename         = data.archive_file.ingest_findings.output_path
  source_code_hash = data.archive_file.ingest_findings.output_base64sha256
  tags             = { Project = "aegiscloud" }

  environment {
    variables = {
      AWS_ACCOUNT_ID = data.aws_caller_identity.current.account_id
    }
  }
}

resource "aws_lambda_permission" "allow_s3_invoke" {
  statement_id  = "AllowS3InvokeIngest"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ingest_findings.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.cloudsplaining_reports.arn
}

resource "aws_s3_bucket_notification" "cloudsplaining_upload" {
  bucket = aws_s3_bucket.cloudsplaining_reports.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.ingest_findings.arn
    events              = ["s3:ObjectCreated:*"]
    filter_suffix       = ".json"
  }

  depends_on = [aws_lambda_permission.allow_s3_invoke]
}

# ---------------------------------------------------------------------------
# IAM identity for CI to assume (extends the GitHub Actions OIDC role from
# foundation/oidc.tf) — needs read access to IAM (to scan policies) and
# write access to this bucket (to upload the report).
# ---------------------------------------------------------------------------
resource "aws_iam_policy" "iam_scan_and_upload" {
  name        = "aegiscloud-iam-scan-and-upload"
  description = "Attach to the GitHub Actions OIDC role to allow Cloudsplaining scans"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:GetAccountAuthorizationDetails", "iam:ListPolicies", "iam:GetPolicy", "iam:GetPolicyVersion"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudsplaining_reports.arn}/*"
      }
    ]
  })
}

output "cloudsplaining_reports_bucket" {
  value = aws_s3_bucket.cloudsplaining_reports.id
}

output "iam_scan_and_upload_policy_arn" {
  value = aws_iam_policy.iam_scan_and_upload.arn
}
