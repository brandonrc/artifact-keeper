#!/bin/bash
# Run system package E2E tests against the local Docker Compose stack.
#
# Usage:
#   ./scripts/e2e-syspkg/run.sh [all|debian|rpm|alpine|conda|maven]
#
# Prerequisites:
#   docker compose up -d   (backend + postgres must be running)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$PROJECT_DIR/docker-compose.e2e-syspkg.yml"

PROFILE="${1:-all}"
ALL_FORMATS=(debian rpm alpine conda maven)

case "$PROFILE" in
    all)    FORMATS=("${ALL_FORMATS[@]}") ;;
    debian|rpm|alpine|conda|maven) FORMATS=("$PROFILE") ;;
    *)
        echo "Usage: $0 [all|debian|rpm|alpine|conda|maven]"
        exit 1
        ;;
esac

echo "=============================================="
echo "System Package E2E Tests"
echo "Profile: $PROFILE"
echo "Formats: ${FORMATS[*]}"
echo "=============================================="
echo ""

# Verify backend is reachable
echo "Checking backend health..."
if ! curl -sf http://localhost:30080/health > /dev/null 2>&1; then
    echo "ERROR: Backend not reachable at localhost:30080"
    echo "Run 'docker compose up -d' first."
    exit 1
fi
echo "Backend is healthy."
echo ""

PASSED=()
FAILED=()

for fmt in "${FORMATS[@]}"; do
    echo ""
    echo ">>> Running $fmt E2E test..."
    echo "----------------------------------------------"

    if docker compose -f "$COMPOSE_FILE" --profile "$fmt" up \
        --abort-on-container-exit --exit-code-from "${fmt}-e2e" 2>&1; then
        PASSED+=("$fmt")
        echo ">>> $fmt: PASSED"
    else
        FAILED+=("$fmt")
        echo ">>> $fmt: FAILED"
    fi

    # Clean up containers for this profile
    docker compose -f "$COMPOSE_FILE" --profile "$fmt" down --remove-orphans 2>/dev/null || true
done

echo ""
echo "=============================================="
echo "Results Summary"
echo "=============================================="
echo ""

echo "Passed (${#PASSED[@]}):"
for t in "${PASSED[@]}"; do
    echo "  + $t"
done

if [ ${#FAILED[@]} -gt 0 ]; then
    echo ""
    echo "Failed (${#FAILED[@]}):"
    for t in "${FAILED[@]}"; do
        echo "  x $t"
    done
    echo ""
    echo "SOME TESTS FAILED"
    exit 1
fi

echo ""
echo "ALL TESTS PASSED"
