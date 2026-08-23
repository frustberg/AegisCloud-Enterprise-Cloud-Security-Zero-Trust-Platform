#!/bin/bash
#
# AegisCloud — Adversary Emulation Runner
#
# Runs a curated set of Stratus Red Team attack techniques against your
# OWN AegisCloud account, then checks whether GuardDuty/Security Hub/your
# remediation Lambdas actually detected and/or responded to each one.
# This is what turns the project from "I configured detections" into
# "I proved my detections work by attacking my own environment."
#
# Stratus Red Team (https://github.com/DataDog/stratus-red-team) executes
# REAL attack API calls (not simulated) using your actual AWS credentials,
# then cleans up after itself. Only run this against an account you own
# and control — never against shared or production infrastructure.
#
# Prerequisites:
#   brew install datadog/stratus-red-team/stratus-red-team
#   (or download a release binary: https://github.com/DataDog/stratus-red-team/releases)

set -euo pipefail

RESULTS_DIR="./attack-emulation-results"
mkdir -p "$RESULTS_DIR"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
RESULTS_FILE="$RESULTS_DIR/run-${TIMESTAMP}.json"

# ---------------------------------------------------------------------------
# Techniques selected specifically because they map to detection sources
# already built in this project:
#   - aws.credential-access.ec2-instance-credentials -> tests GuardDuty's
#     InstanceCredentialExfiltration finding + the IMDSv2 permission
#     boundary guardrail from Phase 2 (this one SHOULD be blocked/detected)
#   - aws.exfiltration.s3-backdoor-bucket-policy -> tests GuardDuty's S3
#     data-access findings + the deny-public-s3 permission boundary
#   - aws.persistence.iam-backdoor-role -> tests whether Cloudsplaining
#     (Phase 12) and GuardDuty's PrivilegeEscalation findings catch a
#     newly-created backdoor trust relationship
#   - aws.defense-evasion.cloudtrail-stop -> tests whether disabling your
#     own audit trail is itself detected (a classic "cover your tracks"
#     technique — this one is worth knowing your setup does NOT
#     currently catch, see the honest gap noted in the README)
# ---------------------------------------------------------------------------
TECHNIQUES=(
  "aws.credential-access.ec2-instance-credentials"
  "aws.exfiltration.s3-backdoor-bucket-policy"
  "aws.persistence.iam-backdoor-role"
  "aws.defense-evasion.cloudtrail-stop"
)

echo "=== AegisCloud Adversary Emulation Run — ${TIMESTAMP} ===" | tee -a "$RESULTS_FILE"
echo "[]" > "$RESULTS_FILE.tmp"

for technique in "${TECHNIQUES[@]}"; do
  echo ""
  echo ">>> Warming up: ${technique}"
  stratus warmup "$technique"

  echo ">>> Detonating: ${technique}"
  DETONATE_START=$(date -u +"%s")
  stratus detonate "$technique" --no-cleanup=false || true
  DETONATE_END=$(date -u +"%s")

  echo ">>> Waiting 90s for GuardDuty/Config/EventBridge pipelines to process..."
  sleep 90

  echo ">>> Recording result for ${technique}"
  python3 - "$technique" "$DETONATE_START" "$DETONATE_END" "$RESULTS_FILE.tmp" <<'PYEOF'
import json
import sys

technique, start, end, results_path = sys.argv[1:5]

with open(results_path) as f:
    results = json.load(f)

results.append({
    "technique": technique,
    "detonated_at_epoch": int(start),
    "detonation_duration_seconds": int(end) - int(start),
    "manual_verification_needed": True,
    "notes": "Check GuardDuty findings, Security Hub, and CloudWatch Logs for the remediation Lambdas manually - see docs/attack-navigator-mapping.md for what to look for per technique"
})

with open(results_path, "w") as f:
    json.dump(results, f, indent=2)
PYEOF

  echo ">>> Cleaning up: ${technique}"
  stratus cleanup "$technique"
done

mv "$RESULTS_FILE.tmp" "$RESULTS_FILE"
echo ""
echo "=== Run complete. Results: ${RESULTS_FILE} ==="
echo ""
echo "NEXT STEP: for each technique above, manually check:"
echo "  1. GuardDuty console -> Findings -> filter by time range of this run"
echo "  2. Security Hub console -> Findings -> same time range"
echo "  3. CloudWatch Logs for aegiscloud-remediate-s3-public / aegiscloud-remediate-sg-open"
echo "  4. Record what fired (or didn't) in docs/attack-navigator-mapping.md"
echo "     then run scripts/generate-attack-navigator-layer.py to build the coverage map"
