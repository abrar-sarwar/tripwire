# TripWire

> A serverless detection-and-response system for the AWS control plane. Sub-60-second auto-remediation, $0/month on AWS Free Tier.

![AWS Free Tier](https://img.shields.io/badge/AWS-Free%20Tier-FF9900?logo=amazonaws&logoColor=white)
![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![CloudFormation](https://img.shields.io/badge/IaC-CloudFormation-7B68EE)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-CC0000)
![Tests](https://img.shields.io/badge/tests-17%20passing-44CC11)

## The Problem

A medium-sized AWS account generates millions of CloudTrail events per day. Almost all of them are routine. A handful are not: root logins, IAM key creation, public S3 exposure, security groups opened to the internet, CloudTrail itself being disabled. Those are the exact actions documented in real cloud breaches over the last few years. Capital One in 2019. Scattered Spider in 2023 and 2024. UNC5537 against Snowflake in 2024. Salesloft Drift against Salesforce in 2025. The ShinyHunters campaigns continuing into 2026. The pattern keeps repeating: legitimate-looking control-plane changes performed with stolen credentials, usually at 2 AM, that disappear into the audit log unless something is specifically watching for them.

Most small and mid-sized organizations have no detection in place for these. Wiz, Lacework, and CrowdStrike Falcon Cloud Security all cover this territory and more, but they cost tens of thousands of dollars per year. TripWire is the focused, free-tier alternative: five detections, two of them with automatic remediation, deployable in about ten minutes.

## What TripWire Does

- **Continuously monitors** the AWS control plane via CloudTrail and EventBridge. Pattern-based rules filter millions of events down to the half-dozen that matter.
- **Alerts within seconds** on five high-risk event categories. Every alert answers *WHO / WHAT / WHERE / WHEN / ATT&CK / RECOMMENDED ACTION*, formatted so a responder on their phone at 2 AM can triage without opening a laptop.
- **Auto-remediates two** of the five: public S3 buckets, and security groups opening SSH or RDP to the internet. Both reversals happen in under 60 seconds. Verified end-to-end on a real CloudTrail event during the build.

## Architecture

```mermaid
flowchart TB
    API[AWS API call<br/>signin / iam / s3 / ec2 / cloudtrail]
    CT[CloudTrail trail<br/>multi-region, log file validation]
    EB{EventBridge default bus<br/>5 pattern-match rules}

    API -->|management event| CT
    CT -->|emitted automatically| EB

    EB -->|userIdentity.type<br/>= Root| L1[Lambda<br/>root-login]
    EB -->|iam:<br/>CreateAccessKey| L2[Lambda<br/>iam-key-created]
    EB -->|s3:PutBucketPolicy<br/>PutBucketAcl<br/>DeletePublicAccessBlock| L3[Lambda<br/>s3-public]
    EB -->|ec2:<br/>AuthorizeSecurityGroup<br/>Ingress| L4[Lambda<br/>sg-open]
    EB -->|cloudtrail:<br/>StopLogging<br/>DeleteTrail| L5[Lambda<br/>cloudtrail-disabled]

    SNS[(SNS topic<br/>tripwire-alerts)]
    INBOX[Email inbox]
    SLACK[Slack webhook]

    L1 -->|alert payload| SNS
    L2 -->|alert payload| SNS
    L3 -->|alert + remediation note| SNS
    L4 -->|alert + remediation note| SNS
    L5 -->|alert payload| SNS
    SNS -->|email| INBOX
    SNS -.->|future / optional| SLACK

    L3 -.->|s3:DeleteBucketPolicy<br/>s3:PutBucketPublicAccessBlock| R3[S3 bucket<br/>reverted to private]
    L4 -.->|ec2:RevokeSecurityGroupIngress| R4[Security group<br/>rule revoked]

    CW[CloudWatch Logs<br/>audit trail of every invocation]
    L1 -.-> CW
    L2 -.-> CW
    L3 -.-> CW
    L4 -.-> CW
    L5 -.-> CW

    classDef remediation fill:#ffebee,stroke:#c62828,color:#b71c1c
    class R3,R4 remediation
```

CloudTrail captures every management API call in the account and emits it onto the EventBridge default bus. Five EventBridge rules pattern-match the specific event shapes TripWire cares about and invoke a dedicated Lambda within seconds. Each Lambda publishes a structured alert to SNS, and for two of the five it also calls boto3 directly to undo the dangerous change before the alert is sent.

## The Detections

| # | Detection | Trigger | Action | MITRE ATT&CK |
|---|-----------|---------|--------|--------------|
| 1 | Root account login | `ConsoleLogin` with `userIdentity.type = Root` | Alert via SNS | [T1078.004 Valid Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) |
| 2 | IAM access key created | `iam:CreateAccessKey` | Alert via SNS | [T1098.001 Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/) |
| 3 | S3 bucket made public | `s3:PutBucketPolicy` / `PutBucketAcl` / `DeletePublicAccessBlock` | **Auto-revert to private** + alert | [T1530 Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/) |
| 4 | Security group opens 22/3389 to `0.0.0.0/0` | `ec2:AuthorizeSecurityGroupIngress` | **Auto-revoke rule** + alert | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |
| 5 | CloudTrail disabled or deleted | `cloudtrail:StopLogging` / `DeleteTrail` / `UpdateTrail` (with log validation off) | CRITICAL alert | [T1562.008 Disable Cloud Logs](https://attack.mitre.org/techniques/T1562/008/) |

**#1. Root account login.** AWS best practice is that nobody ever signs in as root after initial account setup. A successful root login is therefore one of the highest-signal events available. TripWire alerts and recommends rotating root credentials and reviewing the past 24 hours of CloudTrail activity. There is no auto-remediation here: the cost of accidentally locking out a legitimate root user is far higher than the cost of a brief delay before manual response.

**#2. IAM access key created.** Creating a long-lived access key is one of the most common persistence mechanisms in real cloud-breach forensics. The alert names the actor, the target user, and the new key ID, and includes the exact CLI commands to revoke it. Auto-disabling the key was considered and rejected. A legitimate operator's new key going dead in production is harder to recover from than a brief alert.

**#3. S3 bucket made public.** A publicly readable bucket is the standard exfiltration pathway in the documented cluster of S3 data breaches. TripWire inspects every `PutBucketPolicy`, `PutBucketAcl`, and `DeletePublicAccessBlock` event. If the change would expose the bucket (a `"Principal": "*"` policy, an `AllUsers` ACL grant, or PAB removal), the Lambda deletes the bucket policy, re-applies all four PublicAccessBlock flags, and *then* sends the alert. A `PROTECTED_BUCKETS` allowlist (containing the CloudTrail log bucket and the CloudFormation deploy bucket) prevents TripWire from ever auto-remediating its own dependencies. The safety trade-off is deliberate: 30 seconds of inconvenience for an admin who intentionally exposed a bucket costs far less than minutes of open exfiltration.

**#4. Security group opens management ports to the internet.** Opening port 22 or 3389 to `0.0.0.0/0` is classic initial-access setup. TripWire revokes the offending rule via `ec2:RevokeSecurityGroupIngress` and alerts. The remediation handles both literal `0.0.0.0/0` rules and wider port ranges that happen to cover 22 or 3389 (for example, `0-65535`). Same logic as #3: a legitimate bastion host should be scoped to an office IP range, not the open internet, so reverting an open-to-the-world rule is the right default.

**#5. CloudTrail disabled.** Disabling the audit trail is the textbook "blind the defender" maneuver, and it almost always precedes something more destructive. TripWire alerts with `CRITICAL` severity and includes the exact CLI to re-enable logging. Auto-restart was deliberately not built. Legitimate maintenance changes to a trail are plausible enough that fighting them in code would be the wrong default. A paged human reviews and decides.

## Proof It Works

- **17 unit tests, all passing.** They cover each handler's event parser, alert formatter, and (for #3 and #4) remediation paths. See [`tests/`](tests/).
- **Three of the five detections were verified end-to-end on live CloudTrail events:**
  - **#2** (IAM key created) fired in **4 seconds** from `aws iam create-access-key` to Lambda invocation
  - **#3** (S3 made public) fired in **7 seconds**, and the throwaway public bucket was **auto-reverted to private** with all four PublicAccessBlock flags re-applied before the alert email landed
  - **#5** (CloudTrail disabled) fired in **6 seconds** from `aws cloudtrail stop-logging` to Lambda invocation
- **One real bug caught during live triggering and fixed.** Detection #3's Lambda originally requested `s3:PutPublicAccessBlock` in its IAM role. The correct IAM action name is `s3:PutBucketPublicAccessBlock`. The bucket policy was being deleted, but PAB re-application was silently failing with AccessDenied because the `try/except` was swallowing the exception without logging. Discovery was only possible because the detection was tested against a real CloudTrail event, not just unit-tested in isolation. Both bugs are fixed in [commit `51936ee`](https://github.com/abrar-sarwar/tripwire/commit/51936ee). The IAM action is corrected, and the remediation path now `print()`s any exception so a future failure surfaces in CloudWatch Logs immediately.

Detections **#1** (which requires actually signing in as root) and **#4** (which requires creating a throwaway security group) were not exercised against live CloudTrail events during this build. Their pipelines were verified by direct Lambda invocation with the fixture event, which exercises every code path except the EventBridge rule pattern itself. Pattern correctness for both was independently verified with `aws events test-event-pattern` against the documented CloudTrail event shape.

## Deploy It Yourself

```bash
# 1. Clone
git clone https://github.com/abrar-sarwar/tripwire.git
cd tripwire

# 2. Configure AWS CLI (https://docs.aws.amazon.com/cli/latest/userguide/getting-started-quickstart.html)
aws sts get-caller-identity   # should return your account ID

# 3. Deploy: bootstrap commands plus the CloudFormation stack
./scripts/deploy.sh

# 4. Confirm the SNS subscription email AWS sends, then fire a synthetic event:
./scripts/test-detection.sh
```

An alert email titled **`[TripWire] HIGH - Root login (Success)`** should land within 30 seconds. The repo includes fixtures for every detection in [`tests/fixtures/`](tests/fixtures/). Point `test-detection.sh` at any of them to fire a different detection.

**Tear it all down:**

```bash
./scripts/teardown.sh
```

The teardown script removes Lambdas, IAM roles, EventBridge rules, and the SNS topic. It deliberately leaves CloudTrail and the CloudTrail S3 bucket alone. Destroying audit history on a teardown is exactly the failure mode TripWire is designed to detect, so the bootstrap resources stay.

## Cost

Everything fits within the AWS Always Free tier on a quiet account:

| Service | Usage | Free tier |
|---|---|---|
| CloudTrail management trail | 1 trail | First trail free |
| Lambda | <1,000 invocations / month expected | 1,000,000 / month |
| SNS email | <100 emails / month expected | 1,000 / month |
| EventBridge | default bus, AWS-source events only | Free |
| S3 (CloudTrail logs) | <1 GB / month | 5 GB |
| CloudWatch Logs | <50 MB / month | 5 GB |

**Total ongoing cost: $0/month.** GuardDuty (which would have powered a sixth detection, see *Future Work* below) is the only chargeable AWS service in this design space and is explicitly out of scope.

## What TripWire Doesn't Do

Deliberate scope choices, not missing features:

- No workload protection. No EC2 agent, no container scanning, no malware detection.
- No identity hygiene enforcement. Doesn't require MFA, doesn't rotate keys.
- No vulnerability management. No CVE scanning.
- No compliance reporting. No SOC 2 or PCI evidence.
- Single-account, single-region only (us-east-1). No organization or multi-region support.
- No ML or behavioral analytics. Every detection is deterministic pattern matching.

Each of those is a real product category served by mature commercial tools. TripWire stays small and sharp: five detections, two remediations, one region, zero ongoing cost.

## Future Work

- **Detection #6: GuardDuty findings.** Originally in scope but deferred during the build. The AWS account threw `SubscriptionRequiredException` and needs a one-time Console click at the GuardDuty console to subscribe before the API will respond. The Lambda is about 30 lines and the EventBridge rule pattern is `{"source": ["aws.guardduty"], "detail-type": ["GuardDuty Finding"]}`. The implementation plan in [`docs/superpowers/plans/2026-05-11-tripwire.md`](docs/superpowers/plans/2026-05-11-tripwire.md) (Task 11) has the full handler code ready to drop in.
- **Multi-region via CloudFormation StackSets.** Today's stack deploys to us-east-1 only. A StackSet would replicate the detection Lambdas to every region the account uses.
- **A lightweight dashboard.** A CloudWatch dashboard or a simple S3-hosted static page summarizing the last N alerts and the auto-remediation success rate, built on top of the existing CloudWatch Logs.

## License

All rights reserved. This repository is published as portfolio material. Please contact the author before reusing in your own work.

## Author

**Abrar Tahir Sarwar**

- GitHub: [@abrar-sarwar](https://github.com/abrar-sarwar)
- LinkedIn: [linkedin.com/in/abrar-sarwar](https://www.linkedin.com/in/abrar-sarwar)
- Related project: [GLINT](https://github.com/abrar-sarwar/glint)
