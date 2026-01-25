#!/usr/bin/env sh
# Cleanup S3 buckets from marvain deployments
# This script deletes the buckets that were retained after stack deletion

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

# Buckets to delete (from your list)
BUCKETS_TO_DELETE="
agent-hub-dev-artifactbucket-naaa6frqlxuv
agent-hub-dev-auditbucket-ywuqer80nlmq
marvain-major-john-major-dev-artifactbucket-qjar8xgf2xr8
marvain-major-john-major-dev-auditbucket-moxul9cob9r0
aws-sam-cli-managed-default-samclisourcebucket-lmsmbydti0yg
"

log_info "Starting S3 bucket cleanup"
log_warn "This will delete the following buckets and all their contents:"
echo "$BUCKETS_TO_DELETE" | grep -v "^$"
echo ""

for bucket in $BUCKETS_TO_DELETE; do
  if [ -z "$bucket" ]; then
    continue
  fi
  
  log_info "Processing bucket: $bucket"
  
  # Check if bucket exists
  if aws s3 ls "s3://$bucket" --profile "$AWS_PROFILE" --region "$AWS_REGION" >/dev/null 2>&1; then
    log_info "  Bucket exists, attempting to empty and delete..."
    
    # Try to empty the bucket
    if aws s3 rm "s3://$bucket" --recursive --profile "$AWS_PROFILE" --region "$AWS_REGION" 2>&1; then
      log_info "  ✓ Bucket emptied"
    else
      log_warn "  ⚠ Failed to empty bucket (may have Object Lock)"
    fi
    
    # Try to delete the bucket
    if aws s3 rb "s3://$bucket" --profile "$AWS_PROFILE" --region "$AWS_REGION" 2>&1; then
      log_info "  ✓ Bucket deleted: $bucket"
    else
      log_error "  ✗ Failed to delete bucket: $bucket"
      log_warn "    This may be due to Object Lock retention policy"
      log_warn "    You may need to wait for retention period to expire or use AWS Console"
    fi
  else
    log_warn "  Bucket not found or already deleted: $bucket"
  fi
  echo ""
done

log_info "S3 bucket cleanup complete!"
log_info ""
log_info "If any audit buckets failed to delete due to Object Lock:"
log_info "  - They have a 10-year governance retention policy"
log_info "  - You can delete objects with bypass permissions in AWS Console"
log_info "  - Or wait for the retention period to expire"

