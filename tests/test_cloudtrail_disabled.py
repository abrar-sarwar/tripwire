import json
from pathlib import Path
from unittest.mock import patch, MagicMock

FIXTURE = Path(__file__).parent / "fixtures" / "cloudtrail_stopped.json"


def test_alerts_on_stop_logging(monkeypatch):
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:tripwire-alerts")
    event = json.loads(FIXTURE.read_text())
    with patch("boto3.client") as mc:
        sns = MagicMock(); mc.return_value = sns
        from cloudtrail_disabled import handler
        handler.lambda_handler(event, None)
    assert sns.publish.called
    body = sns.publish.call_args.kwargs["Message"]
    assert "StopLogging" in body
    assert "tripwire-trail" in body
    assert "T1562.008" in body


def test_alerts_on_delete_trail(monkeypatch):
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:tripwire-alerts")
    event = json.loads(FIXTURE.read_text())
    event["detail"]["eventName"] = "DeleteTrail"
    with patch("boto3.client") as mc:
        sns = MagicMock(); mc.return_value = sns
        from cloudtrail_disabled import handler
        handler.lambda_handler(event, None)
    assert sns.publish.called


def test_alerts_on_update_trail_disabling_log_validation(monkeypatch):
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:tripwire-alerts")
    event = json.loads(FIXTURE.read_text())
    event["detail"]["eventName"] = "UpdateTrail"
    event["detail"]["requestParameters"]["enableLogFileValidation"] = False
    with patch("boto3.client") as mc:
        sns = MagicMock(); mc.return_value = sns
        from cloudtrail_disabled import handler
        handler.lambda_handler(event, None)
    assert sns.publish.called


def test_ignored_for_unrelated_event(monkeypatch):
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:tripwire-alerts")
    event = json.loads(FIXTURE.read_text())
    event["detail"]["eventName"] = "StartLogging"
    with patch("boto3.client") as mc:
        sns = MagicMock(); mc.return_value = sns
        from cloudtrail_disabled import handler
        handler.lambda_handler(event, None)
    assert not sns.publish.called
