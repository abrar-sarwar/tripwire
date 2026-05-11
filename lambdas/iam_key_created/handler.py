"""TripWire Detection #2 — IAM Access Key Created.

ATT&CK: T1098.001 Additional Cloud Credentials.
Trigger: CloudTrail iam:CreateAccessKey.
Action: alert (no auto-revoke — the operator may be legitimate and locking the
new key out can disrupt active automation).
"""
import os
import boto3

TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
ATTACK_ID = "T1098.001"
DETECTION_NAME = "IAM Access Key Created"
SEVERITY = "HIGH"


def lambda_handler(event, _context):
    detail = event.get("detail", {})
    if detail.get("eventName") != "CreateAccessKey":
        return {"status": "ignored"}

    actor = detail.get("userIdentity", {}).get("arn", "unknown")
    src_ip = detail.get("sourceIPAddress", "unknown")
    ua = detail.get("userAgent", "unknown")
    target_user = detail.get("requestParameters", {}).get("userName", "unknown")
    new_key = detail.get("responseElements", {}).get("accessKey", {}).get("accessKeyId", "unknown")
    region = detail.get("awsRegion", "unknown")
    when = detail.get("eventTime", "unknown")
    event_id = detail.get("eventID", "unknown")

    subject = f"[TripWire] {SEVERITY} - IAM access key created for {target_user}"
    message = (
        f"[TripWire] {SEVERITY} - {DETECTION_NAME}\n\n"
        f"WHO:    {actor} via {ua} from {src_ip}\n"
        f"WHAT:   iam:CreateAccessKey  user={target_user}  newKeyId={new_key}\n"
        f"WHERE:  region={region}\n"
        f"WHEN:   {when}\n"
        f"ATT&CK: {ATTACK_ID}\n\n"
        f"RECOMMENDED ACTION:\n"
        f"Confirm this key creation was intentional. If not, run:\n"
        f"  aws iam update-access-key --user-name {target_user} --access-key-id {new_key} --status Inactive\n"
        f"then aws iam delete-access-key, and rotate any other credentials owned by {actor}.\n\n"
        f"Raw event ID: {event_id}\n"
    )
    boto3.client("sns").publish(TopicArn=TOPIC_ARN, Subject=subject[:99], Message=message)
    return {"status": "alerted", "eventId": event_id}
