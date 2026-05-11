import json
from pathlib import Path
from unittest.mock import patch, MagicMock

FIXTURE = Path(__file__).parent / "fixtures" / "sg_open_22.json"


def _patched():
    sns, ec2 = MagicMock(), MagicMock()
    def factory(name, *a, **kw):
        return {"sns": sns, "ec2": ec2}[name]
    return factory, sns, ec2


def test_detects_ssh_open_and_revokes(monkeypatch):
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:tripwire-alerts")
    event = json.loads(FIXTURE.read_text())
    factory, sns, ec2 = _patched()
    with patch("boto3.client", side_effect=factory):
        from sg_open import handler
        handler.lambda_handler(event, None)
    assert sns.publish.called
    body = sns.publish.call_args.kwargs["Message"]
    assert "sg-0123456789abcdef0" in body
    assert "REMEDIATED" in body
    ec2.revoke_security_group_ingress.assert_called_once()
    kwargs = ec2.revoke_security_group_ingress.call_args.kwargs
    assert kwargs["GroupId"] == "sg-0123456789abcdef0"
    assert kwargs["IpPermissions"][0]["FromPort"] == 22


def test_rdp_open(monkeypatch):
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:tripwire-alerts")
    event = json.loads(FIXTURE.read_text())
    event["detail"]["requestParameters"]["ipPermissions"]["items"][0]["fromPort"] = 3389
    event["detail"]["requestParameters"]["ipPermissions"]["items"][0]["toPort"] = 3389
    factory, sns, ec2 = _patched()
    with patch("boto3.client", side_effect=factory):
        from sg_open import handler
        handler.lambda_handler(event, None)
    assert sns.publish.called
    assert ec2.revoke_security_group_ingress.called


def test_ignored_when_cidr_is_internal(monkeypatch):
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:tripwire-alerts")
    event = json.loads(FIXTURE.read_text())
    event["detail"]["requestParameters"]["ipPermissions"]["items"][0]["ipRanges"]["items"] = [{"cidrIp": "10.0.0.0/8"}]
    factory, sns, ec2 = _patched()
    with patch("boto3.client", side_effect=factory):
        from sg_open import handler
        handler.lambda_handler(event, None)
    assert not sns.publish.called
    assert not ec2.revoke_security_group_ingress.called


def test_ignored_when_port_is_not_22_or_3389(monkeypatch):
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:tripwire-alerts")
    event = json.loads(FIXTURE.read_text())
    event["detail"]["requestParameters"]["ipPermissions"]["items"][0]["fromPort"] = 80
    event["detail"]["requestParameters"]["ipPermissions"]["items"][0]["toPort"] = 80
    factory, sns, ec2 = _patched()
    with patch("boto3.client", side_effect=factory):
        from sg_open import handler
        handler.lambda_handler(event, None)
    assert not sns.publish.called


def test_wide_port_range_covering_22(monkeypatch):
    """If the rule covers ports 0-65535 (with the world), that includes SSH and must alert."""
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:tripwire-alerts")
    event = json.loads(FIXTURE.read_text())
    event["detail"]["requestParameters"]["ipPermissions"]["items"][0]["fromPort"] = 0
    event["detail"]["requestParameters"]["ipPermissions"]["items"][0]["toPort"] = 65535
    factory, sns, ec2 = _patched()
    with patch("boto3.client", side_effect=factory):
        from sg_open import handler
        handler.lambda_handler(event, None)
    assert sns.publish.called
    assert ec2.revoke_security_group_ingress.called
