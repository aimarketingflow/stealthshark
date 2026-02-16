#!/bin/bash
# ============================================================
# StealthShark Integrity Verification Script
# Checks SHA-256 hashes of all tracked source files against
# the signed manifest to detect tampering.
# ============================================================
set -euo pipefail

MANIFEST="INTEGRITY_HASHES.sha256"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f "$MANIFEST" ]; then
    echo "❌ ERROR: $MANIFEST not found in $(pwd)"
    echo "   Cannot verify integrity without the hash manifest."
    exit 1
fi

TOTAL=0
PASSED=0
FAILED=0
MISSING=0
TAMPERED_FILES=""

echo "🦈 StealthShark Integrity Verification"
echo "========================================"
echo "Manifest: $MANIFEST"
echo "Commit:   $(tail -1 "$MANIFEST" | grep -o 'git commit: .*' || echo 'unknown')"
echo "Checking: $(grep -c '  \.' "$MANIFEST" 2>/dev/null || echo '?') files"
echo "----------------------------------------"
echo ""

# Read each line of the manifest (skip the timestamp/commit footer)
while IFS= read -r line; do
    # Skip empty lines and the footer timestamp line
    [[ -z "$line" ]] && continue
    [[ "$line" == 20* && "$line" == *"git commit"* ]] && continue

    EXPECTED_HASH=$(echo "$line" | awk '{print $1}')
    FILE_PATH=$(echo "$line" | awk '{$1=""; print substr($0,2)}')

    # Skip if not a valid hash line
    [[ ${#EXPECTED_HASH} -ne 64 ]] && continue

    TOTAL=$((TOTAL + 1))

    if [ ! -f "$FILE_PATH" ]; then
        echo "⚠️  MISSING: $FILE_PATH"
        MISSING=$((MISSING + 1))
        TAMPERED_FILES="$TAMPERED_FILES\n  ⚠️  MISSING: $FILE_PATH"
        continue
    fi

    ACTUAL_HASH=$(shasum -a 256 "$FILE_PATH" | awk '{print $1}')

    if [ "$EXPECTED_HASH" = "$ACTUAL_HASH" ]; then
        PASSED=$((PASSED + 1))
        # Verbose progress
        PCT=$((PASSED * 100 / TOTAL))
        printf "\r  ✅ Verified: %d/%d (%d%%)" "$PASSED" "$TOTAL" "$PCT"
    else
        FAILED=$((FAILED + 1))
        echo ""
        echo "  🚨 TAMPERED: $FILE_PATH"
        echo "     Expected: $EXPECTED_HASH"
        echo "     Actual:   $ACTUAL_HASH"
        TAMPERED_FILES="$TAMPERED_FILES\n  🚨 TAMPERED: $FILE_PATH"
    fi
done < "$MANIFEST"

echo ""
echo ""
echo "========================================"
echo "Results:"
echo "  Total files:  $TOTAL"
echo "  Passed:       $PASSED"
echo "  Failed:       $FAILED"
echo "  Missing:      $MISSING"
echo "========================================"

if [ "$FAILED" -eq 0 ] && [ "$MISSING" -eq 0 ]; then
    echo "✅ INTEGRITY CHECK PASSED — no tampering detected."
    exit 0
else
    echo "🚨 INTEGRITY CHECK FAILED — possible tampering detected!"
    echo -e "$TAMPERED_FILES"
    echo ""
    echo "Run 'git diff' to inspect changes or 'git log' to check commit history."
    exit 1
fi
