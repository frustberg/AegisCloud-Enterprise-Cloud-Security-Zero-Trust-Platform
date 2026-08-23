# AegisCloud — OPA policy: no S3 bucket may be planned with public ACLs.
#
# This is a SECOND, independent layer beyond Checkov and beyond the
# runtime IAM Permission Boundary (Phase 2) and Config rule (Phase 5) —
# defense in depth applied to your own pipeline: even if Checkov's
# built-in check somehow missed something, this custom Conftest/OPA
# policy is a second gate written specifically for THIS project's threat
# model, evaluated against the Terraform plan JSON itself (not just the
# HCL source), which catches cases where a variable or module composition
# would produce a public bucket that isn't obvious from reading the raw
# .tf files.
#
# Run with Conftest (https://www.conftest.dev/):
#   terraform plan -out=tfplan.binary
#   terraform show -json tfplan.binary > tfplan.json
#   conftest test --policy policy-as-code/opa tfplan.json
#
# Wired into CI via github-actions/policy-gate.yml.

package main

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_acl"
  acl := resource.change.after.acl
  acl == "public-read"
  msg := sprintf("S3 bucket ACL '%v' sets public-read - denied by aegiscloud policy no_public_s3.rego", [resource.address])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_s3_bucket_public_access_block"
  resource.change.after.block_public_acls == false
  msg := sprintf("%v disables block_public_acls - all AegisCloud buckets must block public ACLs", [resource.address])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_security_group"
  rule := resource.change.after.ingress[_]
  rule.cidr_blocks[_] == "0.0.0.0/0"
  rule.from_port <= 22
  rule.to_port >= 22
  msg := sprintf("%v allows SSH (port 22) from 0.0.0.0/0 - denied by aegiscloud policy", [resource.address])
}
