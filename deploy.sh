#!/usr/bin/env bash
set -euo pipefail

REGION="us-east-1"
ACCOUNT_ID="123456789012"
STACK_NAME="tripwire"
DEPLOY_BUCKET="tripwire-cfn-${ACCOUNT_ID}-${REGION}"
SNS_TOPIC_ARN="arn:aws:sns:${REGION}:${ACCOUNT_ID}:tripwire-alerts"

aws cloudformation package \
  --template-file template.yaml \
  --s3-bucket "$DEPLOY_BUCKET" \
  --output-template-file packaged.yaml \
  --region "$REGION"

aws cloudformation deploy \
  --template-file packaged.yaml \
  --stack-name "$STACK_NAME" \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides "SnsTopicArn=$SNS_TOPIC_ARN" \
  --region "$REGION"

aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --query 'Stacks[0].StackStatus' --output text
