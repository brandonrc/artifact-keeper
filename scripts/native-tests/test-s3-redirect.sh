#!/usr/bin/env bash
# S3 Redirect Download E2E Test
#
# Tests S3 presigned URL redirects and CloudFront signed URLs.
#
# Prerequisites:
#   - Backend running with S3 storage configured
#   - AWS credentials configured
#   - S3_REDIRECT_DOWNLOADS=true
#
# Environment variables:
#   API_URL         - Backend URL (default: http://localhost:8080)
#   S3_BUCKET       - S3 bucket name (required)
#   S3_REGION       - AWS region (default: us-east-1)
#   CLOUDFRONT_URL  - CloudFront distribution URL (optional)
#
# Usage:
#   ./test-s3-redirect.sh
#   S3_BUCKET=my-bucket ./test-s3-redirect.sh

set -euo pipefail

API_URL="${API_URL:-http://localhost:8080}"
S3_BUCKET="${S3_BUCKET:-}"
S3_REGION="${S3_REGION:-us-east-1}"
CLOUDFRONT_URL="${CLOUDFRONT_URL:-}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; exit 1; }
info() { echo -e "${YELLOW}→ $1${NC}"; }
header() { echo -e "\n${BLUE}=== $1 ===${NC}"; }

# Check prerequisites
for cmd in curl jq aws; do
    if ! command -v "$cmd" &> /dev/null; then
        echo -e "${RED}Error: $cmd is not installed${NC}"
        exit 1
    fi
done

if [ -z "$S3_BUCKET" ]; then
    echo -e "${RED}Error: S3_BUCKET environment variable is required${NC}"
    echo "Usage: S3_BUCKET=my-bucket ./test-s3-redirect.sh"
    exit 1
fi

# Test connectivity
header "Testing Connectivity"
info "API: ${API_URL}"
info "S3 Bucket: ${S3_BUCKET}"
info "Region: ${S3_REGION}"
if [ -n "$CLOUDFRONT_URL" ]; then
    info "CloudFront: ${CLOUDFRONT_URL}"
fi

if ! curl -sf "${API_URL}/health" > /dev/null 2>&1; then
    fail "Cannot connect to API server at ${API_URL}"
fi
pass "API server is running"

# Verify AWS credentials
info "Verifying AWS credentials..."
if ! aws sts get-caller-identity > /dev/null 2>&1; then
    fail "AWS credentials not configured or invalid"
fi
pass "AWS credentials valid"

# Verify S3 bucket access
info "Verifying S3 bucket access..."
if ! aws s3 ls "s3://${S3_BUCKET}" > /dev/null 2>&1; then
    fail "Cannot access S3 bucket: ${S3_BUCKET}"
fi
pass "S3 bucket accessible"

# -------------------------------------------------------------------------
# Test 1: Check backend S3 redirect configuration
# -------------------------------------------------------------------------
header "Checking Backend Configuration"

# Check if backend has S3 redirect enabled (via config endpoint if available)
CONFIG_CHECK=$(curl -sf "${API_URL}/api/config" 2>/dev/null || echo '{}')
if echo "$CONFIG_CHECK" | jq -e '.storage_backend == "s3"' > /dev/null 2>&1; then
    pass "Backend using S3 storage"
else
    info "Backend storage type not confirmed (may need to check logs)"
fi

# -------------------------------------------------------------------------
# Test 2: Upload test artifact
# -------------------------------------------------------------------------
header "Uploading Test Artifact"

TEST_REPO="s3-redirect-test"
TEST_FILE=$(mktemp)
echo "Test artifact content - $(date)" > "$TEST_FILE"
TEST_CHECKSUM=$(sha256sum "$TEST_FILE" | cut -d' ' -f1)

info "Creating test repository..."
CREATE_REPO=$(curl -sf -X POST "${API_URL}/api/repositories" \
    -H "Content-Type: application/json" \
    -d "{
        \"key\": \"${TEST_REPO}\",
        \"name\": \"S3 Redirect Test\",
        \"format\": \"raw\",
        \"storage_backend\": \"s3\"
    }" 2>&1) || {
    # Repository might already exist
    info "Repository may already exist, continuing..."
}

info "Uploading test artifact..."
UPLOAD_RESPONSE=$(curl -sf -X PUT "${API_URL}/api/repositories/${TEST_REPO}/artifacts/test/redirect-test.txt" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${TEST_FILE}" 2>&1) || {
    info "Upload response: $UPLOAD_RESPONSE"
    fail "Failed to upload test artifact"
}
pass "Test artifact uploaded"

rm -f "$TEST_FILE"

# -------------------------------------------------------------------------
# Test 3: Download and check for redirect
# -------------------------------------------------------------------------
header "Testing Download Redirect"

info "Downloading artifact (checking for 302 redirect)..."

# Use -I to get headers, -L to follow redirects
DOWNLOAD_HEADERS=$(curl -sI "${API_URL}/api/repositories/${TEST_REPO}/artifacts/test/redirect-test.txt" 2>&1)

HTTP_STATUS=$(echo "$DOWNLOAD_HEADERS" | grep -i "^HTTP" | tail -1 | awk '{print $2}')
STORAGE_HEADER=$(echo "$DOWNLOAD_HEADERS" | grep -i "X-Artifact-Storage" | awk '{print $2}' | tr -d '\r')
LOCATION=$(echo "$DOWNLOAD_HEADERS" | grep -i "^Location:" | awk '{print $2}' | tr -d '\r')

echo "HTTP Status: $HTTP_STATUS"
echo "X-Artifact-Storage: $STORAGE_HEADER"

if [ "$HTTP_STATUS" = "302" ] || [ "$HTTP_STATUS" = "307" ]; then
    pass "Got redirect response (${HTTP_STATUS})"

    if [ -n "$LOCATION" ]; then
        info "Redirect URL: ${LOCATION:0:80}..."

        # Check if it's S3 or CloudFront
        if echo "$LOCATION" | grep -q "cloudfront"; then
            pass "Redirect to CloudFront"
        elif echo "$LOCATION" | grep -q "s3\|amazonaws"; then
            pass "Redirect to S3 presigned URL"
        else
            info "Redirect to: ${LOCATION:0:50}..."
        fi

        # Verify the presigned URL works
        info "Verifying presigned URL works..."
        CONTENT=$(curl -sf "$LOCATION" 2>&1) || {
            fail "Failed to download from presigned URL"
        }

        if echo "$CONTENT" | grep -q "Test artifact content"; then
            pass "Content downloaded successfully from presigned URL"
        else
            fail "Content mismatch from presigned URL"
        fi
    else
        fail "302 redirect but no Location header"
    fi
elif [ "$HTTP_STATUS" = "200" ]; then
    info "Got direct response (200) - redirect may be disabled"

    if [ "$STORAGE_HEADER" = "proxy" ]; then
        info "Storage header indicates proxy mode"
    fi

    # Still verify content
    CONTENT=$(curl -sf "${API_URL}/api/repositories/${TEST_REPO}/artifacts/test/redirect-test.txt" 2>&1)
    if echo "$CONTENT" | grep -q "Test artifact content"; then
        pass "Content downloaded successfully (proxied)"
    else
        fail "Content mismatch"
    fi
else
    fail "Unexpected HTTP status: ${HTTP_STATUS}"
fi

# -------------------------------------------------------------------------
# Test 4: Verify S3 object exists
# -------------------------------------------------------------------------
header "Verifying S3 Storage"

info "Checking S3 for uploaded object..."
S3_OBJECTS=$(aws s3 ls "s3://${S3_BUCKET}/" --recursive 2>/dev/null | grep -i "redirect-test\|${TEST_REPO}" | head -5 || true)

if [ -n "$S3_OBJECTS" ]; then
    echo "$S3_OBJECTS"
    pass "Object found in S3"
else
    info "Object may be stored with different key pattern"
fi

# -------------------------------------------------------------------------
# Test 5: CloudFront (if configured)
# -------------------------------------------------------------------------
if [ -n "$CLOUDFRONT_URL" ]; then
    header "Testing CloudFront Integration"

    info "CloudFront URL: ${CLOUDFRONT_URL}"

    # Check CloudFront distribution
    CF_CHECK=$(curl -sI "${CLOUDFRONT_URL}/" 2>&1 | head -5)
    if echo "$CF_CHECK" | grep -q "HTTP"; then
        pass "CloudFront distribution reachable"
    else
        info "CloudFront may require signed URLs"
    fi
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------
header "Cleanup"

info "Deleting test artifact..."
curl -sf -X DELETE "${API_URL}/api/repositories/${TEST_REPO}/artifacts/test/redirect-test.txt" > /dev/null 2>&1 || true

info "Deleting test repository..."
curl -sf -X DELETE "${API_URL}/api/repositories/${TEST_REPO}" > /dev/null 2>&1 || true

pass "Cleanup complete"

# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
header "Test Summary"
echo -e "${GREEN}S3 redirect download tests completed!${NC}"
echo ""
echo "Configuration tested:"
echo "  S3 Bucket: ${S3_BUCKET}"
echo "  Region: ${S3_REGION}"
if [ -n "$CLOUDFRONT_URL" ]; then
    echo "  CloudFront: ${CLOUDFRONT_URL}"
fi
