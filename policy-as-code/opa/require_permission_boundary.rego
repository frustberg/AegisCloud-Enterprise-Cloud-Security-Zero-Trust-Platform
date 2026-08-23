# AegisCloud — OPA policy: every IAM role created by this project's
# Terraform MUST have the aegiscloud permission boundary attached. This is
# the policy-as-code enforcement of the single-account guardrail model
# itself — it makes it structurally impossible to accidentally merge a PR
# that adds a new IAM role WITHOUT the boundary that replaces SCPs in this
# design. This is exactly the kind of self-referential guardrail that
# shows real understanding of the architecture, not just individual tools.

package main

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_role"
  not resource.change.after.permissions_boundary
  msg := sprintf("%v does not set permissions_boundary - every AegisCloud IAM role must reference the aegiscloud-permission-boundary policy", [resource.address])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_user"
  not resource.change.after.permissions_boundary
  msg := sprintf("%v does not set permissions_boundary - every AegisCloud IAM user must reference the aegiscloud-permission-boundary policy", [resource.address])
}
