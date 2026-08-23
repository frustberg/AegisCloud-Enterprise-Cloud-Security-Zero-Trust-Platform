"""
AegisCloud — Auto-remediation for publicly exposed S3 buckets.

Trigger: EventBridge rule on AWS Config compliance-change events for the
         's3-bucket-public-read-prohibited' / 's3-bucket-public-write-prohibited'
         managed rules.

What it does:
  1. Reads the non-compliant bucket name out of the Config event.
  2. Re-applies the S3 Block Public Access settings on that bucket.
  3. Strips any bucket ACL grants to the "AllUsers" / "AuthenticatedUsers"
     well-known groups.
  4. Writes a structured log line (CloudWatch Logs) with a timestamp, so you
     can measure detection-to-remediation time for your portfolio evidence.

IAM: this function's execution role should be scoped to exactly:
  - s3:GetBucketAcl, s3:PutBucketAcl
  - s3:GetBucketPolicyStatus, s3:PutBucketPolicy
  - s3:PutPublicAccessBlock, s3:GetPublicAccessBlock
  - logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents
No wildcard resource, no unrelated services.
"""

import json
import logging
import time
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")

PUBLIC_GRANTEE_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def lambda_handler(event, context):
    start_time = time.time()

    detail = event.get("detail", {})
    config_rule_name = detail.get("configRuleName", "")
    resource_id = detail.get("resourceId")  # this is the bucket name for S3 rules
    new_evaluation = detail.get("newEvaluationResult", {})
    compliance_type = new_evaluation.get("complianceType")

    logger.info(json.dumps({
        "event": "remediation_triggered",
        "rule": config_rule_name,
        "bucket": resource_id,
        "compliance_type": compliance_type
    }))

    if compliance_type != "NON_COMPLIANT" or not resource_id:
        logger.info("Nothing to remediate — resource is compliant or unidentified.")
        return {"status": "no_action"}

    bucket_name = resource_id

    # Step 1 — re-apply the account/bucket-level public access block. This is
    # the single most effective control: it overrides any ACL or bucket
    # policy that would otherwise grant public access.
    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        logger.info(f"Public access block re-applied on {bucket_name}")
    except Exception as exc:
        logger.error(f"Failed to set public access block on {bucket_name}: {exc}")
        raise

    # Step 2 — strip any public grants directly from the bucket ACL, in case
    # the block-public-access setting was itself the thing an attacker/user
    # tried to disable.
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        clean_grants = [
            grant for grant in acl["Grants"]
            if grant.get("Grantee", {}).get("URI") not in PUBLIC_GRANTEE_URIS
        ]

        if len(clean_grants) != len(acl["Grants"]):
            s3.put_bucket_acl(
                Bucket=bucket_name,
                AccessControlPolicy={
                    "Grants": clean_grants,
                    "Owner": acl["Owner"],
                },
            )
            logger.info(f"Removed public ACL grants from {bucket_name}")
    except Exception as exc:
        logger.error(f"Failed to clean ACL grants on {bucket_name}: {exc}")
        raise

    elapsed_ms = round((time.time() - start_time) * 1000, 2)
    logger.info(json.dumps({
        "event": "remediation_complete",
        "bucket": bucket_name,
        "elapsed_ms": elapsed_ms
    }))

    return {
        "status": "remediated",
        "bucket": bucket_name,
        "elapsed_ms": elapsed_ms,
    }
