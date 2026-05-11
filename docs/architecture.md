# TripWire Architecture

## Data flow

1. A user (or attacker) calls an AWS API.
2. CloudTrail captures the call and emits an event onto the EventBridge default bus.
3. Each of five EventBridge rules pattern-matches a specific high-risk event shape.
4. The matched rule invokes its dedicated Lambda within ~1 minute of the original API call.
5. The Lambda parses the event, formats a human-readable alert, and publishes to SNS.
6. For Detections #3 and #4 only, the Lambda also calls boto3 directly to undo the dangerous change before publishing.
7. SNS delivers the alert to the subscribed email address.

```
                       ┌──────────────────┐
                       │  AWS API events  │
                       │  (user actions)  │
                       └────────┬─────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │   CloudTrail     │
                       │ (mgmt trail, MR) │
                       └────────┬─────────┘
                                │ events
                                ▼
                  ┌──────────────────────────┐
                  │ EventBridge default bus  │
                  │  (5 pattern-match rules) │
                  └─┬─┬─┬─┬─┬────────────────┘
                    │ │ │ │ │
   ┌────────────────┘ │ │ │ └────────────────────┐
   │  ┌───────────────┘ │ └──────────┐           │
   │  │  ┌──────────────┘            │           │
   ▼  ▼  ▼                           ▼           ▼
 root iam s3_public ─► auto-revert  sg_open ─► auto-revoke   cloudtrail_disabled
 login key                                                   (alert only)
   │  │     │   (s3:DeleteBucketPolicy           │
   │  │     │    + s3:PutPublicAccessBlock)      │ (ec2:RevokeSecurityGroupIngress)
   │  │     │                                    │
   └──┴─────┴─────────────────┬──────────────────┘
                              ▼
                         ┌────────┐         ┌────────────────────┐
                         │  SNS:  │────────▶│   email inbox      │
                         │tripwire│         │ your-email@…     │
                         │-alerts │         └────────────────────┘
                         └────────┘
```

## Why these six (now five) detections?

Empirically, the actions an attacker takes immediately after gaining initial AWS access fall into a small set:

| ATT&CK technique | What the attacker does | TripWire detects |
| --- | --- | --- |
| T1078.004 (Valid Cloud Accounts) | Logs in as root to take quiet stock of the account | #1 Root console login |
| T1098.001 (Additional Cloud Credentials) | Creates an IAM access key to persist beyond MFA/session expiry | #2 IAM access key created |
| T1530 (Data from Cloud Storage) | Makes a target S3 bucket public to exfiltrate via direct URL | #3 S3 public (alert + auto-remediate) |
| T1190 (Exploit Public-Facing Application) | Opens SSH/RDP to the internet for command-and-control | #4 SG opens 22/3389 (alert + auto-revoke) |
| T1562.008 (Impair Defenses: Disable Cloud Logs) | Stops or deletes CloudTrail to hide subsequent activity | #5 CloudTrail disabled |
| (Various) | Generates GuardDuty findings via behavior anomalies | #6 — DROPPED in this build (account-level activation pending) |

The pattern repeats across documented incidents: Capital One (2019), Scattered Spider (2023–24), UNC5537/Snowflake (2024), Salesloft Drift / Salesforce (2025), and ongoing ShinyHunters campaigns into 2026. The pattern: legitimate-looking control-plane changes performed with stolen credentials, often at night, that disappear into CloudTrail noise unless something specifically watches for them.

## Free-tier accounting

| Service | Usage on a quiet account | Free tier | Result |
| --- | --- | --- | --- |
| CloudTrail mgmt trail | 1 trail | First mgmt trail free | $0 |
| S3 (trail logs) | <1 GB/mo | 5 GB | $0 |
| EventBridge default bus | AWS events only | Free | $0 |
| Lambda | <1000 invocations/mo expected | 1M/mo | $0 |
| SNS email | <100 emails/mo expected | 1000/mo | $0 |
| CloudWatch Logs | <50 MB/mo | 5 GB | $0 |
| GuardDuty | DROPPED | — | $0 |

**Total ongoing cost: $0/mo.**

## Why some detections auto-remediate and others don't

| Detection | Auto-remediate? | Reasoning |
| --- | --- | --- |
| #1 Root login | No | Cannot un-login. Blocking root is too risky (lockout). |
| #2 IAM key created | No | Auto-disabling could lock out a legitimate operator's new key. |
| #3 S3 public | **Yes** | Reversal is one API call. Cost of remaining public for 10 minutes far exceeds cost of reverting a legitimate exposure (which can be re-applied). |
| #4 SG open SSH/RDP | **Yes** | Same logic. Re-adding a rule scoped to office IP is trivial. |
| #5 CloudTrail disabled | No | Auto-restart could fight a legitimate maintenance change. Better to page a human. |

The remediation Lambdas have a `PROTECTED_BUCKETS` allowlist baked in via env var so TripWire's own CloudTrail log bucket and deployment bucket are never auto-remediated even if something else manages to make them public.

## What's outside the CloudFormation stack (and why)

| Resource | Why bootstrapped manually | Risk if removed |
| --- | --- | --- |
| CloudTrail trail | If `teardown.sh` blew it away, you'd silently lose all audit history. | Catastrophic — the upstream data source disappears. |
| CloudTrail S3 bucket | Same. | Same. |
| SNS topic | Confirmed email subscriptions are not easy to recreate without user action. | Alerts stop delivering. |
| CFN deployment bucket | Needed before the stack itself can be packaged. | First deploy fails. |

The CloudFormation stack contains *only* the parts that are safe to tear down and rebuild: the Lambdas, IAM roles, EventBridge rules, and their permissions.
