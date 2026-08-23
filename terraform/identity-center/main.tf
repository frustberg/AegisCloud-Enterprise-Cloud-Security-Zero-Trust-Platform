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
  region = "us-east-1"
}

data "aws_ssoadmin_instances" "this" {}
data "aws_caller_identity" "current" {}

locals {
  sso_instance_arn  = tolist(data.aws_ssoadmin_instances.this.arns)[0]
  identity_store_id = tolist(data.aws_ssoadmin_instances.this.identity_store_ids)[0]
}

variable "permission_boundary_arn" {
  description = "Output from terraform/guardrails apply"
  type        = string
}

# ---------------------------------------------------------------------------
# Same three permission sets as the multi-account design. The difference:
# all three are now assigned within THIS account, since there's only one.
# The permission boundary from Phase 2 is what keeps WorkloadAdmin and
# BreakGlassAdmin from actually being able to do anything outside the
# aegiscloud-tagged resources or the guardrail-restricted actions, even
# though PowerUserAccess/AdministratorAccess sound broad.
# ---------------------------------------------------------------------------
resource "aws_ssoadmin_permission_set" "security_auditor" {
  name             = "SecurityAuditorReadOnly"
  description      = "Read-only access to security tooling (Security Hub, Config, GuardDuty, CloudTrail)"
  instance_arn     = local.sso_instance_arn
  session_duration = "PT4H"
}

resource "aws_ssoadmin_managed_policy_attachment" "security_auditor_policy" {
  instance_arn       = local.sso_instance_arn
  managed_policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
  permission_set_arn = aws_ssoadmin_permission_set.security_auditor.arn
}

resource "aws_ssoadmin_permission_set" "workload_admin" {
  name             = "WorkloadAdmin"
  description      = "Elevated access, capped by the aegiscloud permission boundary"
  instance_arn     = local.sso_instance_arn
  session_duration = "PT8H"
}

resource "aws_ssoadmin_managed_policy_attachment" "workload_admin_policy" {
  instance_arn       = local.sso_instance_arn
  managed_policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
  permission_set_arn = aws_ssoadmin_permission_set.workload_admin.arn
}

resource "aws_ssoadmin_permission_set" "break_glass_admin" {
  name             = "BreakGlassAdmin"
  description      = "Emergency full admin - manual assignment only, must be logged, session capped at 1hr"
  instance_arn     = local.sso_instance_arn
  session_duration = "PT1H"
}

resource "aws_ssoadmin_managed_policy_attachment" "break_glass_admin_policy" {
  instance_arn       = local.sso_instance_arn
  managed_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
  permission_set_arn = aws_ssoadmin_permission_set.break_glass_admin.arn
}

# ---------------------------------------------------------------------------
# Account assignment — with a single account, this is now trivially just
# "this account." Replace group_id after SCIM sync has run once (find it in
# IAM Identity Center console > Groups).
# ---------------------------------------------------------------------------
variable "security_engineers_group_id" {
  description = "Identity Store group ID for the Entra-synced SecurityEngineers group"
  type        = string
}

resource "aws_ssoadmin_account_assignment" "security_auditor_assignment" {
  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.security_auditor.arn
  principal_id       = var.security_engineers_group_id
  principal_type     = "GROUP"
  target_id          = data.aws_caller_identity.current.account_id
  target_type        = "AWS_ACCOUNT"
}
