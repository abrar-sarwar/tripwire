# TripWire

Serverless AWS detection-and-response. Five detections, two auto-remediations, one CloudFormation stack.

## What it watches

| # | Detection | ATT&CK | Action |
| --- | --- | --- | --- |
| 1 | Root account console login | T1078.004 | Alert |
| 2 | IAM access key created | T1098.001 | Alert |
| 3 | S3 bucket made public (policy / ACL / PAB deleted) | T1530 | **Alert + auto-revert to private** |
| 4 | Security group opens SSH/RDP to 0.0.0.0/0 | T1190 | **Alert + auto-revoke offending rule** |
| 5 | CloudTrail disabled / deleted | T1562.008 | Alert |

> A sixth detection (GuardDuty findings) was scoped but dropped during build because the account needs a one-time Console click to subscribe to GuardDuty before the API will accept calls. The handler skeleton is gone; re-adding it is a 30-line patch documented in [`docs/superpowers/plans/2026-05-11-tripwire.md`](docs/superpowers/plans/2026-05-11-tripwire.md) Task 11. After clicking "Enable GuardDuty" in the Console, re-add the handler, append the `GuardDutyFindingRule` to `template.yaml`, and redeploy.

The five are the actions an attacker takes after gaining initial AWS access — the same actions seen in Capital One (2019), Scattered Spider (2023–24), UNC5537/Snowflake (2024), Salesloft Drift / Salesforce (2025), and ongoing ShinyHunters campaigns into 2026. Legitimate-looking control-plane changes performed with stolen credentials, often at night, that disappear into CloudTrail noise unless something specifically watches for them.

TripWire is that something.

## Every alert answers the same five questions

```
[TripWire] HIGH - Root Account Console Login

WHO:    ROOT via Mozilla/5.0 from 203.0.113.42
WHAT:   signin.amazonaws.com / ConsoleLogin  result=Success
WHERE:  region=us-east-1
WHEN:   2026-05-11T14:32:11Z
ATT&CK: T1078.004

RECOMMENDED ACTION:
Verify this login was you. If not, rotate the root password and root MFA…
```

A responder reads it on their phone at 2 AM and knows whether to escalate.

## Architecture

See [`docs/architecture.md`](docs/architecture.md). One sentence: CloudTrail → EventBridge default bus → per-detection Lambda → SNS email, plus inline boto3 remediation for the two reversible cases.

## Free-tier accounting

All five detections + the audit pipeline are within AWS Always Free. **Total ongoing cost: $0/mo.** Detail table in [`docs/architecture.md`](docs/architecture.md).

## Deploying from scratch

Prerequisites:
- AWS CLI v2 configured (`aws sts get-caller-identity` works, region `us-east-1`)
- Python 3.12 (Lambda runtime; tests also work on 3.14)
- ~10 minutes

```bash
# 1. Bootstrap (one-time, lives outside the CloudFormation stack so teardown can't blind you)
ACCT=$(aws sts get-caller-identity --query Account --output text)

# CloudTrail S3 log bucket — Block Public Access on so Detection #3 never trips on it
aws s3api create-bucket --bucket tripwire-cloudtrail-${ACCT}-us-east-1 --region us-east-1
aws s3api put-public-access-block --bucket tripwire-cloudtrail-${ACCT}-us-east-1 \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Bucket policy (see docs/superpowers/plans/2026-05-11-tripwire.md Task 1 for the JSON)

# Multi-region trail with log file validation
aws cloudtrail create-trail --name tripwire-trail \
  --s3-bucket-name tripwire-cloudtrail-${ACCT}-us-east-1 \
  --is-multi-region-trail --enable-log-file-validation --region us-east-1
aws cloudtrail start-logging --name tripwire-trail --region us-east-1

# SNS topic + email
aws sns create-topic --name tripwire-alerts --region us-east-1
aws sns subscribe --topic-arn arn:aws:sns:us-east-1:${ACCT}:tripwire-alerts \
  --protocol email --notification-endpoint you@example.com --region us-east-1
# Click the confirmation link in the email AWS sends.

# CloudFormation deployment bucket
aws s3api create-bucket --bucket tripwire-cfn-${ACCT}-us-east-1 --region us-east-1
aws s3api put-public-access-block --bucket tripwire-cfn-${ACCT}-us-east-1 \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# 2. Edit deploy.sh to set ACCOUNT_ID to your account, then:
./deploy.sh
```

## Triggering each detection (to demo)

| # | One-line trigger | Expected email |
| --- | --- | --- |
| 1 | Sign in to AWS Console as **root** user (incognito; sign out immediately) | "[TripWire] HIGH - Root login (Success)" |
| 2 | `aws iam create-access-key --user-name <yours>` then immediately `delete-access-key` | "[TripWire] HIGH - IAM access key created for ..." |
| 3 | `aws s3api create-bucket --bucket tripwire-trigger-test-$(date +%s)`, then `delete-public-access-block`, then `put-bucket-policy` with `Principal:"*"` | "[TripWire] CRITICAL - S3 bucket ... made public" — bucket is private again |
| 4 | `aws ec2 create-security-group ...` then `authorize-security-group-ingress --port 22 --cidr 0.0.0.0/0` | "[TripWire] CRITICAL - SG ... opened SSH/RDP to internet" — rule revoked |
| 5 | `aws cloudtrail stop-logging --name tripwire-trail` then immediately `start-logging` | "[TripWire] CRITICAL - CloudTrail StopLogging on tripwire-trail" |

Latency from trigger to email: ~1–2 minutes (CloudTrail's delivery to EventBridge is the dominant factor).

## Local testing

```bash
python3 -m venv .venv
.venv/bin/pip install pytest boto3
.venv/bin/python -m pytest tests/ -v
```

19 unit tests across the 5 detections. No AWS calls, no moto, no third-party deps in the Lambda code itself — `boto3` is provided by the Lambda runtime; tests need it locally to mock against.

## Teardown

```bash
./teardown.sh
```

Removes Lambdas, IAM roles, and EventBridge rules. Does **not** remove CloudTrail, SNS, or the CloudTrail S3 bucket — by design.

## What's out of scope

- Workload protection (no EC2 agent, no container scanning)
- Identity hygiene (no MFA enforcement, no key rotation)
- Multi-account or multi-region (single account, single region)
- Compliance reports
- ML or behavioral analytics

Each of those is a real product category served by Wiz / Lacework / CrowdStrike. TripWire is a focused demo that the *core* of cloud detection-and-response can be a few hundred lines of Python — and that the hard part isn't engineering, it's knowing which six events to watch.

## Repo layout

- `template.yaml` — single-region CloudFormation stack
- `deploy.sh` / `teardown.sh` — one-command deploy and rollback
- `lambdas/<detection>/handler.py` — each handler is self-contained, ~80 lines, boto3 only
- `tests/test_<detection>.py` — pytest unit tests using `unittest.mock` on `boto3.client`
- `docs/architecture.md` — architecture diagram and design rationale
- `docs/superpowers/plans/2026-05-11-tripwire.md` — the implementation plan, including the dropped Detection #6
