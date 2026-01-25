#!/usr/bin/env sh
# Complete cleanup script for marvain dev deployment
# This script will:
# 1. Delete the CloudFormation stack
# 2. Delete retained S3 buckets (artifact + audit)
# 3. Remove local config files
# 4. Remove build artifacts
# 5. Remove conda environment
# 6. Remove venv (if exists)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
  printf "${GREEN}[INFO]${NC} %s\n" "$1"
}

log_warn() {
  printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

log_error() {
  printf "${RED}[ERROR]${NC} %s\n" "$1"
}

# Configuration
AWS_PROFILE="${AWS_PROFILE:-daylily}"
AWS_REGION="${AWS_REGION:-us-west-2}"
STACK_NAME="marvain-major-john-major-dev"

log_info "Starting complete cleanup of marvain dev deployment"
log_warn "This will delete AWS resources, local config, and environments"
echo ""

# Step 1: Get bucket names before deleting stack
log_info "Step 1: Capturing bucket names from stack outputs..."
ARTIFACT_BUCKET=""
AUDIT_BUCKET=""

if aws cloudformation describe-stacks \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  --stack-name "$STACK_NAME" >/dev/null 2>&1; then
  
  OUTPUTS=$(aws cloudformation describe-stacks \
    --profile "$AWS_PROFILE" \
    --region "$AWS_REGION" \
    --stack-name "$STACK_NAME" \
    --query 'Stacks[0].Outputs' \
    --output json 2>/dev/null || echo "[]")
  
  ARTIFACT_BUCKET=$(echo "$OUTPUTS" | python3 -c "import json, sys; outs=json.load(sys.stdin); print(next((o['OutputValue'] for o in outs if o['OutputKey']=='ArtifactBucketName'), ''))")
  AUDIT_BUCKET=$(echo "$OUTPUTS" | python3 -c "import json, sys; outs=json.load(sys.stdin); print(next((o['OutputValue'] for o in outs if o['OutputKey']=='AuditBucketName'), ''))")
  
  log_info "Found ArtifactBucket: ${ARTIFACT_BUCKET:-<none>}"
  log_info "Found AuditBucket: ${AUDIT_BUCKET:-<none>}"
else
  log_warn "Stack not found or already deleted"
fi
echo ""

# Step 2: Delete CloudFormation stack
log_info "Step 2: Deleting CloudFormation stack: $STACK_NAME"
if aws cloudformation describe-stacks \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  --stack-name "$STACK_NAME" >/dev/null 2>&1; then
  
  aws cloudformation delete-stack \
    --profile "$AWS_PROFILE" \
    --region "$AWS_REGION" \
    --stack-name "$STACK_NAME"
  
  log_info "Waiting for stack deletion to complete (this may take several minutes)..."
  aws cloudformation wait stack-delete-complete \
    --profile "$AWS_PROFILE" \
    --region "$AWS_REGION" \
    --stack-name "$STACK_NAME" || log_warn "Stack deletion wait timed out or failed"
  
  log_info "Stack deleted successfully"
else
  log_warn "Stack not found, skipping deletion"
fi
echo ""

# Step 3: Delete S3 buckets
log_info "Step 3: Deleting retained S3 buckets..."

if [ -n "$ARTIFACT_BUCKET" ]; then
  log_info "Emptying and deleting ArtifactBucket: $ARTIFACT_BUCKET"
  aws s3 rm "s3://$ARTIFACT_BUCKET" --recursive --profile "$AWS_PROFILE" --region "$AWS_REGION" 2>/dev/null || log_warn "Failed to empty artifact bucket"
  aws s3 rb "s3://$ARTIFACT_BUCKET" --profile "$AWS_PROFILE" --region "$AWS_REGION" 2>/dev/null && log_info "ArtifactBucket deleted" || log_warn "Failed to delete artifact bucket"
fi

if [ -n "$AUDIT_BUCKET" ]; then
  log_warn "Attempting to delete AuditBucket: $AUDIT_BUCKET (may fail due to Object Lock)"
  aws s3 rm "s3://$AUDIT_BUCKET" --recursive --profile "$AWS_PROFILE" --region "$AWS_REGION" 2>/dev/null || log_warn "Failed to empty audit bucket (Object Lock may be enabled)"
  aws s3 rb "s3://$AUDIT_BUCKET" --profile "$AWS_PROFILE" --region "$AWS_REGION" 2>/dev/null && log_info "AuditBucket deleted" || log_warn "Failed to delete audit bucket (Object Lock retention may prevent deletion)"
fi
echo ""

# Step 4: Delete local config files
log_info "Step 4: Removing local config files..."
CONFIG_PATHS=(
  "${XDG_CONFIG_HOME:-$HOME/.config}/marvain/marvain.yaml"
  "${XDG_CONFIG_HOME:-$HOME/.config}/marvain/config.yaml"
  "$HOME/.marvain/config.yaml"
  "./marvain.yaml"
)

for config_path in "${CONFIG_PATHS[@]}"; do
  if [ -f "$config_path" ]; then
    log_info "Removing: $config_path"
    rm -f "$config_path"
  fi
done
echo ""

# Step 5: Remove build artifacts
log_info "Step 5: Removing build artifacts..."
rm -rf .aws-sam .aws-* 2>/dev/null && log_info "Build artifacts removed" || log_warn "No build artifacts found"
echo ""

# Step 6: Remove conda environment
log_info "Step 6: Removing conda environment: marvain"
if conda env list | grep -q "^marvain "; then
  conda env remove -n marvain -y && log_info "Conda environment removed" || log_error "Failed to remove conda environment"
else
  log_warn "Conda environment 'marvain' not found"
fi
echo ""

# Step 7: Remove venv (if exists)
log_info "Step 7: Checking for venv..."
if [ -d "venv" ]; then
  log_info "Removing venv directory"
  rm -rf venv
else
  log_warn "No venv directory found"
fi
echo ""

log_info "✓ Cleanup complete!"
log_info ""
log_info "Next steps to start fresh:"
log_info "  1. conda env create -f config/marvain_conda.yaml"
log_info "  2. . ./marvain_activate"
log_info "  3. ./bin/marvain config init --profile $AWS_PROFILE --region $AWS_REGION --env dev"
log_info "  4. ./bin/marvain build"
log_info "  5. ./bin/marvain deploy"

