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
# GuardDuty is fundamentally different from everything in Phase 5's
# detection-remediation module: Config rules are DETERMINISTIC compliance
# checks ("is this bucket public: yes/no"). GuardDuty is BEHAVIORAL/ML-based
# threat detection — it profiles what's normal for your account (API call
# patterns, network traffic, DNS queries) and flags deviations: credential
# exfiltration, cryptomining, C2 communication, reconnaissance, privilege
# escalation attempts. This is the difference between "checking a
# configuration" and "detecting an attack in progress" — and it's the
# detection source that Phase 10's adversary emulation will actually be
# tested against.
# ---------------------------------------------------------------------------
resource "aws_guardduty_detector" "aegiscloud" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = false # no EKS in this project — leave off to avoid unnecessary cost
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = { Project = "aegiscloud" }
}

# ---------------------------------------------------------------------------
# GuardDuty findings flow into Security Hub automatically once both are
# enabled in the account (this is native AWS behavior, no extra wiring
# needed) — so they inherit the same S3 export path to Wazuh built in
# Phase 8, and the same CIS/NIST-mapped dashboard from Phase 7. This one
# resource block is what upgrades your entire detection surface from
# "compliance checks" to "compliance checks + behavioral threat detection,"
# for free, because the pipeline downstream was already built to be
# source-agnostic.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# EventBridge rule specifically for HIGH/CRITICAL GuardDuty findings — used
# by Phase 14 (threat intel enrichment) to trigger enrichment only on
# findings that actually warrant the extra API calls (don't enrich every
# LOW severity finding, that's wasted spend and noise).
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "guardduty_high_severity" {
  name = "aegiscloud-guardduty-high-severity"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 7] }] # GuardDuty severity scale is 0.1-8.9; 7+ is High/Critical
    }
  })

  tags = { Project = "aegiscloud" }
}

output "guardduty_detector_id" {
  value = aws_guardduty_detector.aegiscloud.id
}

output "guardduty_high_severity_rule_arn" {
  value = aws_cloudwatch_event_rule.guardduty_high_severity.arn
}
