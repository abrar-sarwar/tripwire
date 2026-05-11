"""TripWire Detection #5 — CloudTrail Disabled / Stopped / Deleted.

ATT&CK: T1562.008 Impair Defenses — Disable Cloud Logs.
Triggers: cloudtrail:StopLogging, DeleteTrail, UpdateTrail with
EnableLogFileValidation=false.
Action: alert only (auto-restart risks fighting a legitimate admin change —
page a human instead).
"""
import os
import boto3

TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
ATTACK_ID = "T1562.008"
DETECTION_NAME = "CloudTrail Disabled"
SEVERITY = "CRITICAL"
SUSPICIOUS = {"StopLogging", "DeleteTrail"}


def _is_suspicious(detail):
    name = detail.get("eventName")
    if name in SUSPICIOUS:
        return True
    if name == "UpdateTrail":
        rp = detail.get("requestParameters", {}) or {}
        if rp.get("enableLogFileValidation") is False:
            return True
    return False


def lambda_handler(event, _context):
    detail = event.get("detail", {})
    if not _is_suspicious(detail):
        return {"status": "ignored"}

    actor = detail.get("userIdentity", {}).get("arn", "unknown")
    src_ip = detail.get("sourceIPAddress", "unknown")
    ua = detail.get("userAgent", "unknown")
    when = detail.get("eventTime", "unknown")
    event_id = detail.get("eventID", "unknown")
    name = detail.get("eventName", "?")
    trail = (detail.get("requestParameters", {}) or {}).get("name", "unknown")
    trail_short = trail.split("/")[-1] if isinstance(trail, str) else trail

    subject = f"[TripWire] CRITICAL - CloudTrail {name} on {trail_short}"
    message = (
        f"[TripWire] {SEVERITY} - {DETECTION_NAME}\n\n"
        f"WHO:    {actor} via {ua} from {src_ip}\n"
        f"WHAT:   cloudtrail:{name}  trail={trail}\n"
        f"WHERE:  region={detail.get('awsRegion', 'unknown')}\n"
        f"WHEN:   {when}\n"
        f"ATT&CK: {ATTACK_ID}\n\n"
        f"RECOMMENDED ACTION:\n"
        f"Confirm this change was intentional. If not, immediately run:\n"
        f"  aws cloudtrail start-logging --name {trail_short}\n"
        f"and review CloudTrail activity for the 5 minutes preceding this event - "
        f"the actor is likely about to do something they don't want logged.\n\n"
        f"Raw event ID: {event_id}\n"
    )
    boto3.client("sns").publish(TopicArn=TOPIC_ARN, Subject=subject[:99], Message=message)
    return {"status": "alerted", "eventId": event_id}
