resource "aws_inspector2_enabler" "ec2" {

  account_ids = [
    data.aws_caller_identity.current.account_id
  ]

  resource_types = [
    "EC2"
  ]
}

data "aws_caller_identity" "current" {}