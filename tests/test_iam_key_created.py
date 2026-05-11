import json
from pathlib import Path
from unittest.mock import patch, MagicMock

FIXTURE = Path(__file__).parent / "fixtures" / "iam_key_created.json"


def test_alerts_on_create_access_key(monkeypatch):
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:tripwire-alerts")
    event = json.loads(FIXTURE.read_text())
    with patch("boto3.client") as mock_client:
        sns = MagicMock(); mock_client.return_value = sns
        from iam_key_created import handler
        handler.lambda_handler(event, None)
    assert sns.publish.called
    body = sns.publish.call_args.kwargs["Message"]
    assert "AKIAEXAMPLE12345" in body
    assert "abrar-admin" in body
    assert "T1098.001" in body


def test_ignores_other_iam_events(monkeypatch):
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:tripwire-alerts")
    event = json.loads(FIXTURE.read_text())
    event["detail"]["eventName"] = "ListAccessKeys"
    with patch("boto3.client") as mock_client:
        sns = MagicMock(); mock_client.return_value = sns
        from iam_key_created import handler
        handler.lambda_handler(event, None)
    assert not sns.publish.called
