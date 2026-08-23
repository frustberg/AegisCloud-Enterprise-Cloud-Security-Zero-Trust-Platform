"""
AegisCloud — Enriches high-severity GuardDuty findings with external threat
intelligence (AbuseIPDB) before they flow onward to Security Hub / the
Wazuh export pipeline, so an analyst sees actionable context instead of a
bare IP address.

Trigger: EventBridge rule on GuardDuty findings with severity >= 7
         (High/Critical — see terraform/guardduty/main.tf)

What it does:
  1. Extracts the remote IP address from the GuardDuty finding (the
     structure varies by finding type — this handles the common
     Recon/UnauthorizedAccess/CryptoCurrency shapes).
  2. Queries the free-tier AbuseIPDB API for that IP's abuse confidence
     score and report history.
  3. Writes an ENRICHED custom finding to Security Hub via BatchImportFindings,
     in proper ASFF (AWS Security Finding Format), so it shows up in the
     Security Hub dashboard as its own finding, cross-referenced to the
     original GuardDuty finding ID.
  4. This enriched finding flows through the SAME export-to-S3 pipeline
     built in Phase 8 automatically — no changes needed there.

Get a free AbuseIPDB API key at https://www.abuseipdb.com/api (1000
requests/day on the free tier, plenty for a portfolio project).

IAM: this function's execution role needs only:
  - securityhub:BatchImportFindings
  - secretsmanager:GetSecretValue (for the AbuseIPDB API key)
  - logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents
"""

import json
import logging
import os
import urllib.request
import urllib.parse
import boto3
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

securityhub = boto3.client("securityhub")
secrets_client = boto3.client("secretsmanager")

ABUSEIPDB_SECRET_NAME = os.environ["ABUSEIPDB_SECRET_NAME"]
AWS_ACCOUNT_ID = os.environ["AWS_ACCOUNT_ID"]
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")


def get_abuseipdb_key():
    secret = secrets_client.get_secret_value(SecretId=ABUSEIPDB_SECRET_NAME)
    return json.loads(secret["SecretString"])["api_key"]


def extract_remote_ip(finding):
    """GuardDuty finding shapes vary by type — this covers the common
    ones where a remote IP is the actionable indicator."""
    detail = finding.get("service", {}).get("action", {})

    for action_key in ("networkConnectionAction", "portProbeAction", "awsApiCallAction"):
        action = detail.get(action_key, {})
        remote_ip = (
            action.get("remoteIpDetails", {}).get("ipAddressV4")
            or action.get("remotePortDetails", {}).get("ipAddressV4")
        )
        if remote_ip:
            return remote_ip

    return None


def query_abuseipdb(ip_address, api_key):
    params = urllib.parse.urlencode({"ipAddress": ip_address, "maxAgeInDays": 90})
    req = urllib.request.Request(
        f"https://api.abuseipdb.com/api/v2/check?{params}",
        headers={"Key": api_key, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())["data"]


def lambda_handler(event, context):
    detail = event.get("detail", {})
    finding_id = detail.get("id")
    finding_type = detail.get("type")
    severity = detail.get("severity")

    logger.info(json.dumps({
        "event": "enrichment_triggered",
        "finding_id": finding_id,
        "finding_type": finding_type
    }))

    remote_ip = extract_remote_ip(detail)
    if not remote_ip:
        logger.info(f"No remote IP found in finding {finding_id}, nothing to enrich.")
        return {"status": "no_ip_found"}

    api_key = get_abuseipdb_key()

    try:
        intel = query_abuseipdb(remote_ip, api_key)
    except Exception as exc:
        logger.error(f"AbuseIPDB lookup failed for {remote_ip}: {exc}")
        return {"status": "lookup_failed", "error": str(exc)}

    abuse_score = intel.get("abuseConfidenceScore", 0)
    total_reports = intel.get("totalReports", 0)
    country = intel.get("countryCode", "unknown")
    is_tor = intel.get("isTor", False)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # Build a proper ASFF (AWS Security Finding Format) record so this
    # shows up correctly in the Security Hub console, not just as a raw
    # log line — this is the part that demonstrates you can EXTEND AWS's
    # native tooling, not just consume it.
    asff_finding = {
        "SchemaVersion": "2018-10-08",
        "Id": f"aegiscloud-enrichment-{finding_id}",
        "ProductArn": f"arn:aws:securityhub:{AWS_REGION}:{AWS_ACCOUNT_ID}:product/{AWS_ACCOUNT_ID}/default",
        "GeneratorId": "aegiscloud-threat-intel-enrichment",
        "AwsAccountId": AWS_ACCOUNT_ID,
        "Types": ["Unusual Behaviors/Network Flow"],
        "CreatedAt": now,
        "UpdatedAt": now,
        "Severity": {
            "Label": "CRITICAL" if abuse_score >= 75 else "HIGH" if abuse_score >= 40 else "MEDIUM"
        },
        "Title": f"Threat intel enrichment: {remote_ip} has {abuse_score}% abuse confidence",
        "Description": (
            f"Original GuardDuty finding {finding_id} ({finding_type}) involved remote IP "
            f"{remote_ip}. AbuseIPDB reports {total_reports} abuse reports, "
            f"{abuse_score}% confidence score, geolocated to {country}"
            f"{', flagged as a Tor exit node' if is_tor else ''}."
        ),
        "Resources": [
            {
                "Type": "Other",
                "Id": f"ip-address:{remote_ip}",
                "Region": AWS_REGION,
            }
        ],
        "RecordState": "ACTIVE",
        "Workflow": {"Status": "NEW"},
    }

    try:
        response = securityhub.batch_import_findings(Findings=[asff_finding])
        if response["FailedCount"] > 0:
            logger.error(f"Failed to import enriched finding: {response['FailedFindings']}")
        else:
            logger.info(json.dumps({
                "event": "enrichment_complete",
                "original_finding_id": finding_id,
                "remote_ip": remote_ip,
                "abuse_score": abuse_score
            }))
    except Exception as exc:
        logger.error(f"BatchImportFindings failed: {exc}")
        raise

    return {
        "status": "enriched",
        "remote_ip": remote_ip,
        "abuse_score": abuse_score,
        "total_reports": total_reports,
    }
