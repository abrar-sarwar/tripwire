"""TripWire Detection #3 — S3 Bucket Made Public.

ATT&CK: T1530 (Data from Cloud Storage), T1567.002 downstream.
Triggers: s3:PutBucketPolicy with Principal '*', s3:PutBucketAcl granting
AllUsers/AuthenticatedUsers, or s3:DeletePublicAccessBlock.
Action: ALERT and AUTO-REMEDIATE (delete bucket policy + re-apply full
PublicAccessBlock), unless bucket is on PROTECTED_BUCKETS allowlist.
"""
import json
import os
import boto3

TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
PROTECTED = {b.strip() for b in os.environ.get("PROTECTED_BUCKETS", "").split(",") if b.strip()}
ATTACK_ID = "T1530"
DETECTION_NAME = "S3 Bucket Made Public"
SEVERITY = "CRITICAL"


def _policy_is_public(policy):
    if not isinstance(policy, dict):
        return False
    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        p = stmt.get("Principal")
        if p == "*":
            return True
        if isinstance(p, dict):
            aws = p.get("AWS")
            if aws == "*" or (isinstance(aws, list) and "*" in aws):
                return True
    return False


def _acl_is_public(grants):
    for g in grants or []:
        uri = (g.get("grantee", {}) or {}).get("uri", "")
        if "AllUsers" in uri or "AuthenticatedUsers" in uri:
            return True
    return False


def _is_public_event(detail):
    name = detail.get("eventName")
    rp = detail.get("requestParameters", {}) or {}
    if name == "PutBucketPolicy":
        policy = rp.get("bucketPolicy")
        if isinstance(policy, str):
            try:
                policy = json.loads(policy)
            except Exception:
                return False
        return _policy_is_public(policy)
    if name == "PutBucketAcl":
        return _acl_is_public(
            (rp.get("AccessControlPolicy") or {}).get("AccessControlList", {}).get("Grants")
        )
    if name == "DeletePublicAccessBlock":
        return True
    return False


def _remediate(bucket):
    """Best-effort: delete the policy and re-apply PublicAccessBlock.

    Returns (ok: bool, detail: str). Never raises — the alert publish must
    succeed even if remediation fails (e.g., bucket gone in a race).
    """
    s3 = boto3.client("s3")
    try:
        s3.delete_bucket_policy(Bucket=bucket)
    except Exception:
        pass
    try:
        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            },
        )
        return True, "bucket policy deleted and PublicAccessBlock re-applied (all four flags)."
    except Exception as e:
        return False, f"FAILED ({e.__class__.__name__}): {e}"


def lambda_handler(event, _context):
    detail = event.get("detail", {})
    if not _is_public_event(detail):
        return {"status": "ignored"}

    bucket = (detail.get("requestParameters", {}) or {}).get("bucketName", "unknown")
    actor = detail.get("userIdentity", {}).get("arn", "unknown")
    src_ip = detail.get("sourceIPAddress", "unknown")
    ua = detail.get("userAgent", "unknown")
    when = detail.get("eventTime", "unknown")
    event_id = detail.get("eventID", "unknown")
    name = detail.get("eventName", "?")

    protected = bucket in PROTECTED
    remediation_ok = False
    if protected:
        remediation_line = f"PROTECTED bucket ({bucket}) - auto-remediation skipped. Investigate manually."
    else:
        remediation_ok, detail = _remediate(bucket)
        remediation_line = f"REMEDIATED - {detail}" if remediation_ok else f"REMEDIATION {detail}"

    subject = f"[TripWire] CRITICAL - S3 bucket {bucket} made public"
    message = (
        f"[TripWire] {SEVERITY} - {DETECTION_NAME}\n\n"
        f"WHO:    {actor} via {ua} from {src_ip}\n"
        f"WHAT:   s3:{name} on {bucket}\n"
        f"WHERE:  bucket={bucket}\n"
        f"WHEN:   {when}\n"
        f"ATT&CK: {ATTACK_ID}\n\n"
        f"AUTO-REMEDIATION: {remediation_line}\n\n"
        f"RECOMMENDED ACTION:\n"
        f"If this exposure was intentional, re-apply the policy after re-confirming "
        f"with the bucket owner. Otherwise the bucket is now private again - investigate "
        f"why {actor} attempted to expose it.\n\n"
        f"Raw event ID: {event_id}\n"
    )
    boto3.client("sns").publish(TopicArn=TOPIC_ARN, Subject=subject[:99], Message=message)
    return {"status": "alerted", "remediated": remediation_ok, "protected": protected, "bucket": bucket}
