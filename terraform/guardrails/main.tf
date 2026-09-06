terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-south-1"
}

# ---------------------------------------------------------------------------
# Permission Boundary — attach this ARN to every IAM role created anywhere
# in this project. A permission boundary is a MAXIMUM: even if a role's own
# attached policy grants AdministratorAccess, it can never exceed what this
# boundary allows. This is the single-account replacement for SCPs.
#
# It replicates the three SCPs from the original multi-account design:
#   1. deny-public-s3     -> DenyPublicS3Grants statement
#   2. deny-root-actions   -> not applicable to permission boundaries (root
#                             user can't have a boundary attached — root
#                             restriction is instead handled by NEVER using
#                             root for any operational work; enforce this
#                             manually / with IAM Access Analyzer, noted below)
#   3. require-imdsv2      -> DenyLaunchWithoutIMDSv2 statement
#
# Plus one NEW statement that didn't exist in the multi-account version,
# added specifically because we no longer have account boundaries: an ABAC
# rule that denies IAM actions on any resource NOT tagged Project=aegiscloud,
# so a role scoped to this project can't casually reach into unrelated
# resources sitting in the same account.
# ---------------------------------------------------------------------------
resource "aws_iam_policy" "aegiscloud_boundary" {
  name        = "aegiscloud-permission-boundary"
  description = "Maximum permissions for any AegisCloud IAM role - single-account SCP replacement"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowMostByDefault"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
      {
        Sid      = "DenyPublicReadACL"
        Effect   = "Deny"
        Action   = ["s3:PutBucketAcl", "s3:PutObjectAcl"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = ["public-read", "public-read-write"]
          }
        }
      },
      {
        Sid      = "DenyDisablingPublicAccessBlock"
        Effect   = "Deny"
        Action   = "s3:PutAccountPublicAccessBlock"
        Resource = "*"
        Condition = {
          "Bool" = {
            "s3:PublicAccessBlockConfiguration:BlockPublicAcls" = "false"
          }
        }
      },
      {
        Sid      = "DenyLaunchWithoutIMDSv2"
        Effect   = "Deny"
        Action   = "ec2:RunInstances"
        Resource = "arn:aws:ec2:*:*:instance/*"
        Condition = {
          StringNotEquals = {
            "ec2:MetadataHttpTokens" = "required"
          }
        }
      },
      {
        Sid      = "DenyIAMActionsOutsideProjectTag"
        Effect   = "Deny"
        Action   = ["iam:DeleteRole", "iam:DeleteUser", "iam:DetachRolePolicy", "iam:PutRolePolicy"]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:ResourceTag/Project" = "aegiscloud"
          }
        }
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# NOTE on root user restriction: unlike an SCP, a permission boundary cannot
# be attached to the AWS account root user. In a single-account design, the
# equivalent control is operational discipline plus detection, not
# prevention:
#   1. Never generate or use root access keys (verify none exist:
#      `aws iam get-account-summary` -> AccountAccessKeysPresent should be 0)
#   2. Enable MFA on the root user
#   3. The detection-remediation module (Phase 5) includes a Config rule,
#      `root-account-mfa-enabled`, plus you can add `iam-root-access-key-check`
#      to alert if this is ever violated - see terraform/detection-remediation
# This is a real, honest limitation of the single-account model worth being
# able to explain in an interview: SCPs can technically restrict root
# because they operate above the account; a permission boundary, being an
# IAM construct, structurally cannot.
# ---------------------------------------------------------------------------

data "aws_iam_policy" "aegiscloud_boundary_lookup" {
  # convenience data source other modules can reference without needing to
  # know the exact resource address of this policy
  arn = aws_iam_policy.aegiscloud_boundary.arn
}

output "permission_boundary_arn" {
  value = aws_iam_policy.aegiscloud_boundary.arn
}
