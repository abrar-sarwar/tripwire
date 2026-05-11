#!/usr/bin/env bash
# Fires a synthetic root-login event through the deployed Lambda.
# An alert email lands in your SNS subscription within ~30 seconds.
#
# Run from the repo root: ./scripts/test-detection.sh
set -euo pipefail

REGION="us-east-1"
FUNCTION="tripwire-root-login"
FIXTURE="tests/fixtures/root_login.json"
OUT="/tmp/tripwire-out.json"

if [ ! -f "$FIXTURE" ]; then
  echo "error: fixture not found at $FIXTURE — run this script from the repo root." >&2
  exit 1
fi

echo "Invoking $FUNCTION with $FIXTURE ..."
aws lambda invoke \
  --function-name "$FUNCTION" \
  --payload "fileb://${FIXTURE}" \
  --cli-binary-format raw-in-base64-out \
  --region "$REGION" \
  "$OUT" >/dev/null

echo "Lambda response:"
cat "$OUT"
echo
echo
echo "Check your inbox for: [TripWire] HIGH - Root login (Success)"
echo "Latency: ~5-30s for SNS to fan out the email."
