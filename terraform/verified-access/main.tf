terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

terraform {

  backend "s3" {

    bucket         = "aegiscloud-terraform-state-600294641908"
    key            = "verified-access/terraform.tfstate"
    region         = "ap-south-1"

    dynamodb_table = "terraform-lock"

    encrypt        = true
  }
}

provider "aws" {
  region = "ap-south-1"
}

# ---------------------------------------------------------------------------
# Variables now sourced from terraform/foundation outputs instead of a
# separate account's networking module — same shape, different origin.
# ---------------------------------------------------------------------------
variable "vpc_id" {
  type = string
}
variable "demo_app_security_group_id" {
  type = string
}
variable "demo_app_network_interface_id" {
  type = string
}
variable "oidc_client_id" {
  type = string
}
variable "oidc_client_secret" {
  type      = string
  sensitive = true
}
variable "oidc_issuer" {
  description = "e.g. https://login.microsoftonline.com/<tenant-id>/v2.0"
  type        = string
}

resource "aws_verifiedaccess_trust_provider" "entra_id" {
  trust_provider_type      = "user"
  user_trust_provider_type = "oidc"
  policy_reference_name    = "entra_id"

  oidc_options {
    authorization_endpoint = "${var.oidc_issuer}/oauth2/v2.0/authorize"
    client_id              = var.oidc_client_id
    client_secret          = var.oidc_client_secret
    issuer                 = var.oidc_issuer
    token_endpoint         = "${var.oidc_issuer}/oauth2/v2.0/token"
    user_info_endpoint     = "https://graph.microsoft.com/oidc/userinfo"
    scope                  = "openid profile email"
  }
}

resource "aws_verifiedaccess_instance" "aegiscloud" {
  description = "AegisCloud ZTNA control plane - single account edition"
}

resource "aws_verifiedaccess_instance_trust_provider_attachment" "attach_entra" {
  verifiedaccess_instance_id       = aws_verifiedaccess_instance.aegiscloud.id
  verifiedaccess_trust_provider_id = aws_verifiedaccess_trust_provider.entra_id.id
}

resource "aws_verifiedaccess_group" "internal_apps" {

  depends_on = [
    aws_verifiedaccess_instance_trust_provider_attachment.attach_entra
  ]

  verifiedaccess_instance_id = aws_verifiedaccess_instance.aegiscloud.id
  description                = "Internal applications requiring Zero Trust access"



  policy_document = <<-EOT
    permit(principal, action, resource)
    when {
      context.entra_id.groups.contains("SecurityEngineers")
    };
  EOT
}

