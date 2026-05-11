#!/usr/bin/env bash
set -euo pipefail

REGION="us-east-1"
STACK_NAME="tripwire"

echo "This will delete the '$STACK_NAME' CloudFormation stack."
echo "It will NOT delete: CloudTrail, SNS topic, CloudTrail S3 bucket, CFN deployment bucket."
read -p "Continue? [y/N] " ans
[[ "$ans" =~ ^[yY]$ ]] || exit 0

aws cloudformation delete-stack --stack-name "$STACK_NAME" --region "$REGION"
aws cloudformation wait stack-delete-complete --stack-name "$STACK_NAME" --region "$REGION"
echo "Stack deleted."
