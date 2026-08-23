"""
AegisCloud — Ingests Cloudsplaining IAM risk-scan results into Security Hub
as custom ASFF findings.

Cloudsplaining (https://github.com/salesforce/cloudsplaining) is an
open-source tool that scans IAM policies for privilege escalation paths,
resource exposure risk, and overly permissive wildcard actions — the kind
of "technically not a misconfiguration, but a latent risk" issue that
Config/Security Hub's managed rules don't catch, because those check
individual settings, not policy GRAPHS.

This Lambda does NOT run Cloudsplaining itself — that runs in the CI/CD
pipeline (see github-actions/iam-risk-scan.yml) against the account's IAM
policies, and uploads its JSON report to S3. This Lambda is triggered by
that S3 upload, parses the report, and pushes each finding into Security
Hub so it shows up in the same dashboard as everything else, instead of
living only as a CI artifact nobody looks at after the PR merges.

Trigger: S3 ObjectCreated event on the cloudsplaining-reports/ prefix.

IAM: this function's execution role needs only:
  - s3:GetObject on the specific report prefix
  - securityhub:BatchImportFindings
  - logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents
"""

import json
import logging
import os
import boto3
from datetime import datetime, timezone
from urllib.parse import unquote_plus

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")
securityhub = boto3.client("securityhub")

AWS_ACCOUNT_ID = os.environ["AWS_ACCOUNT_ID"]
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

# Cloudsplaining categorizes findings under these risk types — mapped here
# to a rough severity so the Security Hub finding reflects actual risk,
# not just "something Cloudsplaining flagged."
RISK_SEVERITY_MAP = {
    "PrivilegeEscalation": "CRITICAL",
    "ResourceExposure": "HIGH",
    "DataExfiltration": "HIGH",
    "ServiceWildcard": "MEDIUM",
    "CredentialsExposure": "CRITICAL",
}


def lambda_handler(event, context):
    findings_imported = 0

    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = unquote_plus(record["s3"]["object"]["key"])

        logger.info(json.dumps({"event": "processing_report", "bucket": bucket, "key": key}))

        obj = s3.get_object(Bucket=bucket, Key=key)
        report = json.loads(obj["Body"].read())

        # Cloudsplaining's JSON output structure: top-level keys are IAM
        # entity ARNs/names, each containing a list of "actions" flagged
        # under different risk categories.
        for entity_name, entity_data in report.items():
            if not isinstance(entity_data, dict):
                continue

            for risk_type, risk_data in entity_data.items():
                if risk_type not in RISK_SEVERITY_MAP:
                    continue
                if not risk_data:  # empty finding for this risk type
                    continue

                now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
                finding_id = f"aegiscloud-cloudsplaining-{entity_name}-{risk_type}".replace(
                    "/", "-").replace(":", "-")[:128]

                asff_finding = {
                    "SchemaVersion": "2018-10-08",
                    "Id": finding_id,
                    "ProductArn": f"arn:aws:securityhub:{AWS_REGION}:{AWS_ACCOUNT_ID}:product/{AWS_ACCOUNT_ID}/default",
                    "GeneratorId": "aegiscloud-cloudsplaining-iam-risk-scan",
                    "AwsAccountId": AWS_ACCOUNT_ID,
                    "Types": ["Sensitive Data Identifications/IAM Policy Risk"],
                    "CreatedAt": now,
                    "UpdatedAt": now,
                    "Severity": {"Label": RISK_SEVERITY_MAP[risk_type]},
                    "Title": f"IAM policy risk: {risk_type} on {entity_name}",
                    "Description": (
                        f"Cloudsplaining flagged '{entity_name}' for {risk_type}. "
                        f"This means the policy attached to this IAM entity permits "
                        f"actions that, combined with resource access, create a "
                        f"{risk_type.lower()} path — even though no individual "
                        f"setting is technically 'non-compliant' under standard "
                        f"Config rules. Review the actions and scope the policy to "
                        f"specific resources/conditions."
                    ),
                    "Resources": [
                        {
                            "Type": "AwsIamRole" if ":role/" in entity_name else "AwsIamUser",
                            "Id": entity_name if entity_name.startswith("arn:") else
                                  f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/{entity_name}",
                            "Region": AWS_REGION,
                        }
                    ],
                    "RecordState": "ACTIVE",
                    "Workflow": {"Status": "NEW"},
                }

                try:
                    response = securityhub.batch_import_findings(Findings=[asff_finding])
                    if response["FailedCount"] == 0:
                        findings_imported += 1
                except Exception as exc:
                    logger.error(f"Failed to import finding for {entity_name}/{risk_type}: {exc}")

    logger.info(json.dumps({"event": "ingest_complete", "findings_imported": findings_imported}))
    return {"status": "complete", "findings_imported": findings_imported}
