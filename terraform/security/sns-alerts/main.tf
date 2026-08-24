resource "aws_sns_topic" "security_alerts" {

  name = "aegiscloud-security-alerts"

}

resource "aws_sns_topic_subscription" "email" {

  topic_arn = aws_sns_topic.security_alerts.arn

  protocol = "email"

  endpoint = var.alert_email

}

resource "aws_cloudwatch_event_rule" "securityhub_findings" {

  name = "securityhub-findings"

  event_pattern = jsonencode({

    source = [
      "aws.securityhub"
    ]

    detail-type = [
      "Security Hub Findings - Imported"
    ]

    detail = {
      findings = {
        Severity = {
          Label = [
            "CRITICAL"
          ]
        }
      }
    }
  })

}


resource "aws_cloudwatch_event_target" "sns" {

  rule = aws_cloudwatch_event_rule.securityhub_findings.name

  arn = aws_sns_topic.security_alerts.arn

}

resource "aws_sns_topic_policy" "securityhub" {

  arn = aws_sns_topic.security_alerts.arn

  policy = jsonencode({

    Version = "2012-10-17"

    Statement = [

      {

        Sid = "AllowEventBridge"

        Effect = "Allow"

        Principal = {
          Service = "events.amazonaws.com"
        }

        Action = "sns:Publish"

        Resource = aws_sns_topic.security_alerts.arn

      }

    ]

  })

}

