#!/bin/bash
#
# Post-Quantum Code Signature Verification Shell Script
#
# Usage:
#   ./verify.sh --key <public_key> --file <file_to_verify> [options]
#
# Examples:
#   ./verify.sh --key keys/release_public.key --file dist/release.tar.gz
#   ./verify.sh -k keys/signing.key -f app.exe --json
#
# Exit codes:
#   0 - Signature valid
#   1 - Signature invalid
#   2 - Input error
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Default values
KEY=""
FILE=""
SIGNATURE=""
QUIET=false
JSON=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

usage() {
    cat << EOF
Post-Quantum Code Signature Verification Tool

Usage: $(basename "$0") [OPTIONS]

Required:
  -k, --key FILE       Public key file for verification
  -f, --file FILE      File to verify

Options:
  -s, --signature FILE Signature file (default: <file>.sig)
  -q, --quiet          Suppress output, use exit code only
  --json               Output result as JSON
  -h, --help           Show this help

Exit Codes:
  0 - Signature valid
  1 - Signature invalid
  2 - Input error

Examples:
  # Verify a release
  $(basename "$0") -k keys/release_public.key -f dist/myapp-1.0.0.tar.gz

  # Verify with explicit signature file
  $(basename "$0") -k keys/signing.key -f app.exe -s app.exe.pqsig

  # JSON output for scripting
  $(basename "$0") -k keys/signing.key -f release.tar.gz --json
EOF
}

error() {
    echo -e "${RED}Error: $1${NC}" >&2
    exit 2
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -k|--key)
            KEY="$2"
            shift 2
            ;;
        -f|--file)
            FILE="$2"
            shift 2
            ;;
        -s|--signature)
            SIGNATURE="$2"
            shift 2
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        --json)
            JSON=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            ;;
    esac
done

# Validate required arguments
[ -z "$KEY" ] && error "Public key is required (-k/--key)"
[ -z "$FILE" ] && error "File to verify is required (-f/--file)"
[ ! -f "$KEY" ] && error "Public key not found: $KEY"
[ ! -f "$FILE" ] && error "File not found: $FILE"

# Default signature path
if [ -z "$SIGNATURE" ]; then
    SIGNATURE="${FILE}.sig"
fi
[ ! -f "$SIGNATURE" ] && error "Signature file not found: $SIGNATURE"

# Get directories for mounting
KEY_DIR="$(cd "$(dirname "$KEY")" && pwd)"
FILE_DIR="$(cd "$(dirname "$FILE")" && pwd)"
SIG_DIR="$(cd "$(dirname "$SIGNATURE")" && pwd)"

# Build extra args
EXTRA_ARGS=""
[ "$QUIET" = true ] && EXTRA_ARGS="$EXTRA_ARGS --quiet"
[ "$JSON" = true ] && EXTRA_ARGS="$EXTRA_ARGS --json"

# Run verification
docker run --rm \
    -v "$KEY_DIR:/keys:ro" \
    -v "$FILE_DIR:/work:ro" \
    -v "$SIG_DIR:/sigs:ro" \
    -v "$SCRIPT_DIR:/app/tools:ro" \
    dsa-py python /app/tools/verify_release.py \
        --key "/keys/$(basename "$KEY")" \
        --file "/work/$(basename "$FILE")" \
        --signature "/sigs/$(basename "$SIGNATURE")" \
        $EXTRA_ARGS

exit $?
