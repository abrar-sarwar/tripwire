import json
from pathlib import Path
from unittest.mock import patch, MagicMock

FIXTURE = Path(__file__).parent / "fixtures" / "s3_public_policy.json"


def _patched_clients():
    sns, s3 = MagicMock(), MagicMock()
    def factory(name, *a, **kw):
        return {"sns": sns, "s3": s3}[name]
    return factory, sns, s3


def test_detects_public_policy_and_remediates(monkeypatch):
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:tripwire-alerts")
    monkeypatch.setenv("PROTECTED_BUCKETS", "tripwire-cloudtrail-123456789012-us-east-1,tripwire-cfn-123456789012-us-east-1")
    event = json.loads(FIXTURE.read_text())
    factory, sns, s3 = _patched_clients()
    with patch("boto3.client", side_effect=factory):
        from s3_public import handler
        handler.lambda_handler(event, None)
    assert sns.publish.called
    body = sns.publish.call_args.kwargs["Message"]
    assert "tripwire-test-victim-bucket" in body
    assert "REMEDIATED" in body
    s3.delete_bucket_policy.assert_called_with(Bucket="tripwire-test-victim-bucket")
    s3.put_public_access_block.assert_called_once()


def test_protected_bucket_is_not_remediated(monkeypatch):
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:tripwire-alerts")
    monkeypatch.setenv("PROTECTED_BUCKETS", "tripwire-cloudtrail-123456789012-us-east-1")
    event = json.loads(FIXTURE.read_text())
    event["detail"]["requestParameters"]["bucketName"] = "tripwire-cloudtrail-123456789012-us-east-1"
    factory, sns, s3 = _patched_clients()
    with patch("boto3.client", side_effect=factory):
        from s3_public import handler
        handler.lambda_handler(event, None)
    assert sns.publish.called
    assert not s3.delete_bucket_policy.called
    assert not s3.put_public_access_block.called
    body = sns.publish.call_args.kwargs["Message"]
    assert "PROTECTED" in body


def test_alert_still_sent_when_remediation_fails(monkeypatch):
    """If put_public_access_block raises (e.g. bucket gone in a race), the SNS alert must still go out."""
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:tripwire-alerts")
    monkeypatch.setenv("PROTECTED_BUCKETS", "")
    event = json.loads(FIXTURE.read_text())
    factory, sns, s3 = _patched_clients()
    s3.put_public_access_block.side_effect = Exception("NoSuchBucket")
    with patch("boto3.client", side_effect=factory):
        from s3_public import handler
        handler.lambda_handler(event, None)
    assert sns.publish.called
    body = sns.publish.call_args.kwargs["Message"]
    assert "FAILED" in body
    assert "NoSuchBucket" in body


def test_non_public_policy_is_ignored(monkeypatch):
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:tripwire-alerts")
    monkeypatch.setenv("PROTECTED_BUCKETS", "")
    event = json.loads(FIXTURE.read_text())
    event["detail"]["requestParameters"]["bucketPolicy"]["Statement"][0]["Principal"] = {"AWS": "arn:aws:iam::123456789012:root"}
    factory, sns, s3 = _patched_clients()
    with patch("boto3.client", side_effect=factory):
        from s3_public import handler
        handler.lambda_handler(event, None)
    assert not sns.publish.called
