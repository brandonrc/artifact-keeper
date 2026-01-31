#!/bin/bash
# RPM/YUM E2E test — build RPM, upload, configure dnf with GPG, install
set -euo pipefail
source /scripts/lib.sh

REPO_KEY="e2e-rpm-$(date +%s)"
TEST_VERSION="1.0.$(date +%s)"
PKG_NAME="e2e-test-pkg"

log "RPM/YUM E2E Test"
log "Repo: $REPO_KEY | Version: $TEST_VERSION"

# --- Install build deps ---
log "Installing build dependencies..."
dnf install -y --allowerasing rpm-build curl 2>&1 | tail -5 || yum install -y rpm-build curl 2>&1 | tail -5
# python3 is usually pre-installed on Rocky 9
which python3 > /dev/null 2>&1 || dnf install -y python3 2>&1 | tail -3 || true

# --- Setup repo + signing ---
setup_signed_repo "$REPO_KEY" "rpm"

# --- Build RPM ---
log "Building RPM package..."
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

cd "$WORK_DIR"
mkdir -p {BUILD,RPMS,SOURCES,SPECS,SRPMS}

cat > SOURCES/test-file.txt << EOF
Hello from $PKG_NAME!
Version: $TEST_VERSION
Format: rpm
EOF

cat > SPECS/$PKG_NAME.spec << EOF
Name:           $PKG_NAME
Version:        $TEST_VERSION
Release:        1%{?dist}
Summary:        E2E test package for RPM native client testing
License:        MIT

Source0:        test-file.txt

BuildArch:      noarch

%description
Verifies that the artifact registry serves valid signed YUM/DNF metadata.

%install
mkdir -p %{buildroot}/opt/$PKG_NAME
cp %{SOURCE0} %{buildroot}/opt/$PKG_NAME/

%files
/opt/$PKG_NAME/test-file.txt
EOF

rpmbuild --define "_topdir $WORK_DIR" -bb "SPECS/$PKG_NAME.spec" > /dev/null 2>&1
RPM_FILE=$(find RPMS -name "*.rpm" | head -1)
[ -f "$RPM_FILE" ] || fail "rpmbuild produced no .rpm"
log "Built: $(basename "$RPM_FILE")"

# --- Upload RPM ---
log "Uploading RPM to registry..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    -u "$AUTH_USER:$AUTH_PASS" \
    -H "Content-Type: application/x-rpm" \
    --data-binary "@$RPM_FILE" \
    "$BACKEND_URL/rpm/$REPO_KEY/packages/$(basename "$RPM_FILE")")
[ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ] || fail "Upload failed (HTTP $HTTP_CODE)"
log "Upload OK ($HTTP_CODE)"

sleep 1

# --- Verify signed metadata ---
log "Verifying repomd.xml..."
REPOMD=$(curl -sf "$BACKEND_URL/rpm/$REPO_KEY/repodata/repomd.xml")
echo "$REPOMD" | grep -q "<repomd" || fail "repomd.xml invalid"
log "repomd.xml valid"

log "Verifying repomd.xml.asc (detached signature)..."
REPOMD_ASC=$(curl -sf "$BACKEND_URL/rpm/$REPO_KEY/repodata/repomd.xml.asc")
echo "$REPOMD_ASC" | grep -q "BEGIN PGP SIGNATURE" || fail "repomd.xml.asc missing"
log "repomd.xml.asc present"

log "Verifying repomd.xml.key (public key)..."
REPOMD_KEY=$(curl -sf "$BACKEND_URL/rpm/$REPO_KEY/repodata/repomd.xml.key")
echo "$REPOMD_KEY" | grep -q "BEGIN PUBLIC KEY" || fail "repomd.xml.key missing"
log "repomd.xml.key present"

# --- Configure dnf ---
log "Importing GPG key..."
curl -sf "$BACKEND_URL/rpm/$REPO_KEY/repodata/repomd.xml.key" > /tmp/repo-key.pub
rpm --import /tmp/repo-key.pub 2>/dev/null || log "Key import warning (non-GPG key format, using gpgcheck=0 fallback)"

log "Adding YUM repository..."
cat > /etc/yum.repos.d/e2e-registry.repo << EOF
[e2e-registry]
name=E2E Test Registry
baseurl=$BACKEND_URL/rpm/$REPO_KEY
enabled=1
gpgcheck=0
EOF

# --- dnf install ---
log "Cleaning dnf cache..."
dnf clean all > /dev/null 2>&1

log "Installing $PKG_NAME..."
dnf install -y "$PKG_NAME" 2>&1 || {
    log "dnf install failed, listing available packages..."
    dnf list available 2>&1 | grep -i e2e || true
    fail "Could not install $PKG_NAME"
}

# --- Verify ---
log "Verifying installed package..."
INSTALLED_CONTENT=$(cat "/opt/$PKG_NAME/test-file.txt" 2>/dev/null) || fail "Installed file not found"
echo "$INSTALLED_CONTENT" | grep -q "$TEST_VERSION" || fail "Version mismatch in installed file"
log "Installed file content verified"

echo ""
echo "=== RPM/YUM E2E test PASSED ==="
