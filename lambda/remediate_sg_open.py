"""
AegisCloud — Auto-remediation for security groups with unrestricted
(0.0.0.0/0) inbound rules on sensitive ports.

Trigger: EventBridge rule on AWS Config compliance-change events for the
         'restricted-ssh' and 'vpc-sg-open-only-to-authorized-ports'
         managed rules.

What it does:
  1. Reads the non-compliant security group ID out of the Config event.
  2. Finds any ingress rule that allows 0.0.0.0/0 or ::/0 on a sensitive
     port (22, 3389, 3306, 5432, 1433, 27017 by default — edit SENSITIVE_PORTS).
  3. Revokes exactly those rules (does not touch legitimate rules on other
     ports, so it doesn't break the workload).
  4. Logs a structured, timestamped remediation record.

IAM: this function's execution role should be scoped to exactly:
  - ec2:DescribeSecurityGroups
  - ec2:RevokeSecurityGroupIngress
  - logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents
No wildcard resource, no unrelated services.
"""

import json
import logging
import time
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client("ec2")

SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 27017}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def lambda_handler(event, context):
    start_time = time.time()

    detail = event.get("detail", {})
    config_rule_name = detail.get("configRuleName", "")
    resource_id = detail.get("resourceId")  # security group ID
    new_evaluation = detail.get("newEvaluationResult", {})
    compliance_type = new_evaluation.get("complianceType")

    logger.info(json.dumps({
        "event": "remediation_triggered",
        "rule": config_rule_name,
        "security_group": resource_id,
        "compliance_type": compliance_type
    }))

    if compliance_type != "NON_COMPLIANT" or not resource_id:
        logger.info("Nothing to remediate — resource is compliant or unidentified.")
        return {"status": "no_action"}

    sg_id = resource_id
    revoked_rules = []

    try:
        response = ec2.describe_security_groups(GroupIds=[sg_id])
        sg = response["SecurityGroups"][0]

        for permission in sg.get("IpPermissions", []):
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")

            # Skip rules that don't cover a sensitive port at all.
            port_is_sensitive = (
                from_port is not None
                and to_port is not None
                and any(from_port <= p <= to_port for p in SENSITIVE_PORTS)
            )
            if not port_is_sensitive:
                continue

            open_ipv4 = [
                r for r in permission.get("IpRanges", [])
                if r.get("CidrIp") in OPEN_CIDRS
            ]
            open_ipv6 = [
                r for r in permission.get("Ipv6Ranges", [])
                if r.get("CidrIpv6") in OPEN_CIDRS
            ]

            if open_ipv4 or open_ipv6:
                revoke_permission = {
                    "IpProtocol": permission["IpProtocol"],
                    "FromPort": from_port,
                    "ToPort": to_port,
                    "IpRanges": open_ipv4,
                    "Ipv6Ranges": open_ipv6,
                }
                ec2.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[revoke_permission],
                )
                revoked_rules.append(revoke_permission)
                logger.info(
                    f"Revoked open ingress on {sg_id} port {from_port}-{to_port}"
                )

    except Exception as exc:
        logger.error(f"Failed to remediate security group {sg_id}: {exc}")
        raise

    elapsed_ms = round((time.time() - start_time) * 1000, 2)
    logger.info(json.dumps({
        "event": "remediation_complete",
        "security_group": sg_id,
        "rules_revoked": len(revoked_rules),
        "elapsed_ms": elapsed_ms
    }))

    return {
        "status": "remediated" if revoked_rules else "no_matching_rules",
        "security_group": sg_id,
        "rules_revoked": revoked_rules,
        "elapsed_ms": elapsed_ms,
    }
