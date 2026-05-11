"""TripWire Detection #4 — Security Group exposes SSH/RDP to the internet.

ATT&CK: T1190 Exploit Public-Facing Application (initial-access setup).
Trigger: ec2:AuthorizeSecurityGroupIngress where any rule has 0.0.0.0/0 or ::/0
covering port 22 or 3389.
Action: ALERT and AUTO-REMEDIATE via ec2:RevokeSecurityGroupIngress for the
exact offending rule.
"""
import os
import boto3

TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
ATTACK_ID = "T1190"
DETECTION_NAME = "Security Group Opened to Internet (SSH/RDP)"
SEVERITY = "CRITICAL"
DANGER_PORTS = (22, 3389)


def _ranges_v4(perm):
    r = perm.get("ipRanges")
    if isinstance(r, dict):
        return r.get("items", [])
    return r or []


def _ranges_v6(perm):
    r = perm.get("ipv6Ranges")
    if isinstance(r, dict):
        return r.get("items", [])
    return r or []


def _range_covers_dangerous_port(perm):
    proto = perm.get("ipProtocol")
    if proto == "-1":
        return True
    if proto != "tcp":
        return False
    try:
        lo = int(perm.get("fromPort", -1))
        hi = int(perm.get("toPort", -1))
    except (TypeError, ValueError):
        return False
    return any(lo <= p <= hi for p in DANGER_PORTS)


def _is_world_open(perm):
    return (
        any(r.get("cidrIp") == "0.0.0.0/0" for r in _ranges_v4(perm))
        or any(r.get("cidrIpv6") == "::/0" for r in _ranges_v6(perm))
    )


def _normalize_perms(perms_root):
    """CloudTrail may serialize ipPermissions as {'items': [...]} or as a bare list."""
    if isinstance(perms_root, dict):
        return perms_root.get("items", [])
    return perms_root or []


def _revoke(group_id, perm):
    ec2 = boto3.client("ec2")
    ec2.revoke_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{
            "IpProtocol": perm.get("ipProtocol"),
            "FromPort": perm.get("fromPort"),
            "ToPort": perm.get("toPort"),
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}] if any(r.get("cidrIp") == "0.0.0.0/0" for r in _ranges_v4(perm)) else [],
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}] if any(r.get("cidrIpv6") == "::/0" for r in _ranges_v6(perm)) else [],
        }],
    )


def lambda_handler(event, _context):
    detail = event.get("detail", {})
    if detail.get("eventName") != "AuthorizeSecurityGroupIngress":
        return {"status": "ignored"}
    rp = detail.get("requestParameters", {}) or {}
    group_id = rp.get("groupId") or rp.get("groupName", "unknown")
    perms = _normalize_perms(rp.get("ipPermissions"))

    offenders = [p for p in perms if _is_world_open(p) and _range_covers_dangerous_port(p)]
    if not offenders:
        return {"status": "ignored"}

    actor = detail.get("userIdentity", {}).get("arn", "unknown")
    src_ip = detail.get("sourceIPAddress", "unknown")
    ua = detail.get("userAgent", "unknown")
    when = detail.get("eventTime", "unknown")
    event_id = detail.get("eventID", "unknown")

    revoked = []
    for perm in offenders:
        try:
            _revoke(group_id, perm)
            revoked.append(f"{perm.get('ipProtocol')}/{perm.get('fromPort')}-{perm.get('toPort')}")
        except Exception as e:
            revoked.append(f"FAILED({e.__class__.__name__})")

    subject = f"[TripWire] CRITICAL - SG {group_id} opened SSH/RDP to internet"
    message = (
        f"[TripWire] {SEVERITY} - {DETECTION_NAME}\n\n"
        f"WHO:    {actor} via {ua} from {src_ip}\n"
        f"WHAT:   ec2:AuthorizeSecurityGroupIngress on {group_id}\n"
        f"WHERE:  region={detail.get('awsRegion', 'unknown')}  sg={group_id}\n"
        f"WHEN:   {when}\n"
        f"ATT&CK: {ATTACK_ID}\n\n"
        f"AUTO-REMEDIATION: REMEDIATED - revoked offending rules: {', '.join(revoked)}\n\n"
        f"RECOMMENDED ACTION:\n"
        f"If this exposure was intentional (e.g. legitimate bastion), re-add the rule "
        f"scoped to your office IP, not 0.0.0.0/0. Otherwise investigate why {actor} "
        f"attempted to open management ports to the internet.\n\n"
        f"Raw event ID: {event_id}\n"
    )
    boto3.client("sns").publish(TopicArn=TOPIC_ARN, Subject=subject[:99], Message=message)
    return {"status": "alerted", "remediated": revoked, "sg": group_id}
