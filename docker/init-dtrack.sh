#!/bin/sh
# Bootstrap Dependency-Track: change default password and extract API key.
# Runs as an init container, writes the API key to a shared volume.
#
# Requires: curl, jq (use alpine/curl + apk add jq, or similar)
# Idempotent: safe to run multiple times.
set -e

DT_URL="${DEPENDENCY_TRACK_URL:-http://dependency-track-apiserver:8080}"
DT_ADMIN_USER="admin"
DT_DEFAULT_PASS="admin"
DT_NEW_PASS="${DEPENDENCY_TRACK_ADMIN_PASSWORD:-ArtifactKeeper2026!}"
API_KEY_FILE="/shared/dtrack-api-key"
BOOTSTRAP_MARKER="/shared/.dtrack-bootstrapped"

echo "[dtrack-init] Waiting for Dependency-Track at $DT_URL ..."
for i in $(seq 1 60); do
  if curl -sf "$DT_URL/api/version" > /dev/null 2>&1; then
    break
  fi
  if [ "$i" -eq 60 ]; then
    echo "[dtrack-init] ERROR: Dependency-Track did not become ready in 5 minutes"
    exit 1
  fi
  sleep 5
done
echo "[dtrack-init] Dependency-Track is up"

# If API key file already exists from a previous run, skip all provisioning
if [ -f "$API_KEY_FILE" ] && [ -s "$API_KEY_FILE" ]; then
  echo "[dtrack-init] API key already provisioned at $API_KEY_FILE — skipping"
  exit 0
fi

# Try login with the new password first (already changed in a previous partial run)
TOKEN=$(curl -sf -X POST "$DT_URL/api/v1/user/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${DT_ADMIN_USER}&password=${DT_NEW_PASS}" 2>/dev/null || true)

if [ -z "$TOKEN" ] || echo "$TOKEN" | grep -qi "FORCE_PASSWORD_CHANGE"; then
  # First boot: change the default admin password
  echo "[dtrack-init] Changing default admin password..."
  CHANGE_RESULT=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST "$DT_URL/api/v1/user/forceChangePassword" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${DT_ADMIN_USER}&password=${DT_DEFAULT_PASS}&newPassword=${DT_NEW_PASS}&confirmPassword=${DT_NEW_PASS}")

  if [ "$CHANGE_RESULT" != "200" ]; then
    echo "[dtrack-init] WARNING: Password change returned HTTP $CHANGE_RESULT (may already be changed)"
  fi

  # Login with new password
  TOKEN=$(curl -sf -X POST "$DT_URL/api/v1/user/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${DT_ADMIN_USER}&password=${DT_NEW_PASS}" 2>/dev/null || true)
fi

if [ -z "$TOKEN" ]; then
  echo "[dtrack-init] ERROR: Could not authenticate with Dependency-Track"
  exit 1
fi

echo "[dtrack-init] Authenticated successfully"

# Extract the Automation team's API key using jq
API_KEY=$(curl -sf "$DT_URL/api/v1/team" \
  -H "Authorization: Bearer $TOKEN" | \
  jq -r '.[] | select(.name == "Automation") | .apiKeys[0].key // empty')

if [ -z "$API_KEY" ]; then
  echo "[dtrack-init] ERROR: Could not find Automation team API key"
  echo "[dtrack-init] Available teams:"
  curl -sf "$DT_URL/api/v1/team" \
    -H "Authorization: Bearer $TOKEN" | jq -r '.[].name' 2>/dev/null || true
  exit 1
fi

echo "$API_KEY" > "$API_KEY_FILE"
echo "[dtrack-init] API key written to $API_KEY_FILE"
echo "[dtrack-init] Done"
