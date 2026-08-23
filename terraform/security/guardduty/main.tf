resource "aws_guardduty_detector" "aegiscloud" {

  enable = true

  finding_publishing_frequency = "FIFTEEN_MINUTES"
}