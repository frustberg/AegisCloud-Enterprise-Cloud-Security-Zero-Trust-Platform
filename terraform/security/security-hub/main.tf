resource "aws_securityhub_account" "aegiscloud" {}

resource "aws_securityhub_standards_subscription" "aws_foundational" {
  standards_arn = "arn:aws:securityhub:ap-south-1::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [
    aws_securityhub_account.aegiscloud
  ]
}