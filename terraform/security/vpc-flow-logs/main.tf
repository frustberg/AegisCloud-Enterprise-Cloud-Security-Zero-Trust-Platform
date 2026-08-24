variable "vpc_id" {
  type = string
}

resource "aws_cloudwatch_log_group" "flow_logs" {

  name = "/aegiscloud/vpc-flow-logs"

  retention_in_days = 30
}

resource "aws_iam_role" "flow_logs" {

  name = "aegiscloud-flowlogs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Effect = "Allow"

      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }

      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {

  role = aws_iam_role.flow_logs.id

  policy = jsonencode({

    Version = "2012-10-17"

    Statement = [

      {
        Effect = "Allow"

        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]

        Resource = "*"
      }
    ]
  })
}

resource "aws_flow_log" "vpc" {

  vpc_id = var.vpc_id

  traffic_type = "ALL"

  log_destination_type = "cloud-watch-logs"

  log_destination = aws_cloudwatch_log_group.flow_logs.arn

  iam_role_arn = aws_iam_role.flow_logs.arn
}

