"""TripWire Detection #1 — Root Account Console Login.

ATT&CK: T1078.004 Valid Cloud Accounts.
Trigger: CloudTrail ConsoleLogin where userIdentity.type == "Root".
Action: alert via SNS (no auto-remediation — root lockout risk is too high).
"""
import os
import boto3

TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
ATTACK_ID = "T1078.004"
DETECTION_NAME = "Root Account Console Login"
SEVERITY = "HIGH"


def lambda_handler(event, _context):
    detail = event.get("detail", {})
    if detail.get("userIdentity", {}).get("type") != "Root":
        return {"status": "ignored", "reason": "not-root"}

    actor = "ROOT"
    src_ip = detail.get("sourceIPAddress", "unknown")
    ua = detail.get("userAgent", "unknown")
    event_name = detail.get("eventName", "ConsoleLogin")
    event_source = detail.get("eventSource", "signin.amazonaws.com")
    region = detail.get("awsRegion", "unknown")
    when = detail.get("eventTime", "unknown")
    event_id = detail.get("eventID", "unknown")
    success = detail.get("responseElements", {}).get("ConsoleLogin", "unknown")

    subject = f"[TripWire] {SEVERITY} - Root login ({success})"
    message = (
        f"[TripWire] {SEVERITY} - {DETECTION_NAME}\n\n"
        f"WHO:    {actor} via {ua} from {src_ip}\n"
        f"WHAT:   {event_source} / {event_name}  result={success}\n"
        f"WHERE:  region={region}\n"
        f"WHEN:   {when}\n"
        f"ATT&CK: {ATTACK_ID}\n\n"
        f"RECOMMENDED ACTION:\n"
        f"Verify this login was you. If not, rotate the root password and root MFA "
        f"immediately, revoke all root access keys, and review CloudTrail for actions "
        f"taken by the root principal in the last 24 hours.\n\n"
        f"Raw event ID: {event_id}\n"
    )

    boto3.client("sns").publish(TopicArn=TOPIC_ARN, Subject=subject[:99], Message=message)
    return {"status": "alerted", "eventId": event_id}
