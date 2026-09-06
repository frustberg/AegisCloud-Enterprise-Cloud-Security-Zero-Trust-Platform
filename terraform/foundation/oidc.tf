# ---------------------------------------------------------------------------
# GitHub Actions OIDC federation — single account version. Same security
# property as before: no long-lived AWS keys stored in GitHub, the trust
# policy's repo/branch condition is what stops any other GitHub Actions
# workflow in the world from assuming this role.
# ---------------------------------------------------------------------------

resource "aws_iam_openid_connect_provider" "github_actions" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

# IMPORTANT: replace "your-github-org/aegiscloud" with your actual repo path.
resource "aws_iam_role" "github_actions_deploy" {
  name = "aegiscloud-github-actions-deploy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github_actions.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:frustberg/AegisCloud-Enterprise-Cloud-Security-Zero-Trust-Platform:ref:refs/heads/main"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "github_actions_deploy_policy" {
  name = "terraform-deploy-scoped"
  role = aws_iam_role.github_actions_deploy.id

  # Scoped to only what Terraform needs to plan/apply this project's
  # resources in this one account. Still no AdministratorAccess, even
  # though there's only one account to protect now — the point of least
  # privilege doesn't go away just because the blast radius did.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:*",
          "iam:Get*",
          "iam:List*",
          "iam:CreateRole",
          "iam:CreatePolicy",
          "iam:AttachRolePolicy",
          "iam:PutRolePolicy",
          "iam:TagRole",
          "iam:CreateUser",
          "iam:PutUserPolicy",
          "iam:CreateAccessKey",
          "lambda:*",
          "events:*",
          "config:*",
          "securityhub:*",
          "sso:*",
          "identitystore:*",
          "ec2-instance-connect:*",
          "verifiedaccess:*",
          "s3:*",
          "logs:*",
          "organizations:Describe*",
          "organizations:List*",
          "organizations:EnableAWSServiceAccess"
        ]
        Resource = "*"
      }
    ]
  })
}

output "github_actions_role_arn" {
  value = aws_iam_role.github_actions_deploy.arn
}
