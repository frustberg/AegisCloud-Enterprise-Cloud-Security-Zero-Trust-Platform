"""
AegisCloud (single-account edition) — Exports Security Hub findings to S3
as individual JSON objects, for a Wazuh manager (running anywhere with
outbound internet access — e.g. your home VirtualBox VM) to pull on a
schedule via its native aws-s3 wodle.

This REPLACES the original design's "push finding to Wazuh over HTTP"
Lambda. The direction of the connection matters:
  - Original design: AWS Lambda -> HTTPS POST -> your Wazuh manager
    (requires your home network to accept inbound connections, i.e. port
    forwarding + a stable public IP or dynamic DNS - not something you
    want to set up for a portfolio project, and not great practice even
    for a real deployment)
  - This design: AWS Lambda -> S3 (object write, entirely within AWS) ...
    then separately, your Wazuh manager -> S3 (object read, initiated
    FROM your side, outbound only) on its own schedule.
No inbound connection to your home network is ever required.

Trigger: EventBridge rule on Security Hub finding-imported events.

IAM: this function's execution role needs only:
  - s3:PutObject on the specific bucket/prefix (see terraform/wazuh-integration)
  - logs:CreateLogGroup / CreateLogStream / PutLogEvents
"""

import json
import logging
import os
import time
import uuid
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")

TARGET_BUCKET = os.environ["TARGET_BUCKET"]
TARGET_PREFIX = os.environ.get("TARGET_PREFIX", "securityhub-findings/")


def lambda_handler(event, context):
    findings = event.get("detail", {}).get("findings", [])
    if not findings:
        logger.info("No findings in event payload, nothing to export.")
        return {"status": "no_findings"}

    written = 0
    for finding in findings:
        # Trim to the fields actually useful for a SIEM alert - the full
        # Security Hub finding object is large and mostly boilerplate.
        record = {
            "finding_id": finding.get("Id"),
            "account_id": finding.get("AwsAccountId"),
            "region": finding.get("Region"),
            "severity": finding.get("Severity", {}).get("Label"),
            "title": finding.get("Title"),
            "description": finding.get("Description"),
            "resource_type": (finding.get("Resources") or [{}])[0].get("Type"),
            "resource_id": (finding.get("Resources") or [{}])[0].get("Id"),
            "compliance_status": finding.get("Compliance", {}).get("Status"),
            "generator_id": finding.get("GeneratorId"),
            "first_observed_at": finding.get("FirstObservedAt"),
            "updated_at": finding.get("UpdatedAt"),
            "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        # Key layout: securityhub-findings/YYYY/MM/DD/<uuid>.json — date
        # partitioning matches what Wazuh's aws-s3 wodle expects and makes
        # manual browsing in S3 sane too.
        date_path = time.strftime("%Y/%m/%d", time.gmtime())
        key = f"{TARGET_PREFIX}{date_path}/{uuid.uuid4()}.json"

        try:
            s3.put_object(
                Bucket=TARGET_BUCKET,
                Key=key,
                Body=json.dumps(record).encode("utf-8"),
                ContentType="application/json",
            )
            written += 1
        except Exception as exc:
            logger.error(f"Failed to write finding {record['finding_id']} to S3: {exc}")

    logger.info(json.dumps({
        "event": "export_complete",
        "total_findings": len(findings),
        "written_to_s3": written,
        "bucket": TARGET_BUCKET
    }))

    return {"status": "complete", "written": written, "total": len(findings)}
