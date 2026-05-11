import json
from pathlib import Path
from unittest.mock import patch, MagicMock

FIXTURE = Path(__file__).parent / "fixtures" / "root_login.json"


def test_handler_publishes_to_sns_on_root_login(monkeypatch):
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:tripwire-alerts")
    event = json.loads(FIXTURE.read_text())

    with patch("boto3.client") as mock_client:
        sns = MagicMock()
        mock_client.return_value = sns
        from root_login import handler
        handler.lambda_handler(event, None)

    assert sns.publish.called, "SNS publish must be called on a root login event"
    args = sns.publish.call_args.kwargs
    assert args["TopicArn"] == "arn:aws:sns:us-east-1:123456789012:tripwire-alerts"
    assert "Root" in args["Subject"] or "root" in args["Subject"]
    body = args["Message"]
    assert "203.0.113.42" in body
    assert "T1078.004" in body
    assert "ConsoleLogin" in body
    assert "evt-root-001" in body


def test_handler_ignores_non_root_login(monkeypatch):
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:tripwire-alerts")
    event = json.loads(FIXTURE.read_text())
    event["detail"]["userIdentity"]["type"] = "IAMUser"

    with patch("boto3.client") as mock_client:
        sns = MagicMock()
        mock_client.return_value = sns
        from root_login import handler
        handler.lambda_handler(event, None)

    assert not sns.publish.called
