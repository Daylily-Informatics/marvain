#!/usr/bin/env bash
set -euo pipefail

STACK=""
REGION=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stack) STACK="$2"; shift 2;;
    --region) REGION="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 1;;
  esac
done

if [[ -z "$STACK" ]]; then
  echo "Usage: $0 --stack <stack-name> --region <region>" >&2
  exit 1
fi

if [[ -z "$REGION" ]]; then
  REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
fi

OUTPUTS_JSON=$(aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK" --query 'Stacks[0].Outputs' --output json)

DB_RESOURCE_ARN=$(python3 - <<'PY'
import json, os, sys
outs=json.loads(os.environ['OUTPUTS_JSON'])
print(next(o['OutputValue'] for o in outs if o['OutputKey']=='DbClusterArn'))
PY
)

DB_SECRET_ARN=$(python3 - <<'PY'
import json, os, sys
outs=json.loads(os.environ['OUTPUTS_JSON'])
print(next(o['OutputValue'] for o in outs if o['OutputKey']=='DbSecretArn'))
PY
)

DB_NAME=$(python3 - <<'PY'
import json, os, sys
outs=json.loads(os.environ['OUTPUTS_JSON'])
print(next(o['OutputValue'] for o in outs if o['OutputKey']=='DbName'))
PY
)

export OUTPUTS_JSON

echo "Using DB: $DB_NAME"
python3 "$(dirname "$0")/db_init.py" \
  --resource-arn "$DB_RESOURCE_ARN" \
  --secret-arn "$DB_SECRET_ARN" \
  --database "$DB_NAME" \
  --region "$REGION"
