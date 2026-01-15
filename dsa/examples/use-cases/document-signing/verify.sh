#!/bin/bash
#
# Post-Quantum Document Signature Verification Shell Script
#
# Usage:
#   ./verify.sh --key <public_key> --document <document> [options]
#
# Examples:
#   ./verify.sh --key keys/signer_public.key --document contract.pdf
#   ./verify.sh -k keys/signer_public.key -d agreement.pdf --json
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
DOCUMENT=""
SIGNATURE=""
QUIET=false
JSON=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

usage() {
    cat << EOF
Post-Quantum Document Signature Verification Tool

Usage: $(basename "$0") [OPTIONS]

Required:
  -k, --key FILE           Public key file for verification
  -d, --document FILE      Document to verify

Options:
  -s, --signature FILE     Signature file (default: <document>.docsig)
  -q, --quiet              Suppress output, use exit code only
  --json                   Output result as JSON
  -h, --help               Show this help

Exit Codes:
  0 - Signature valid
  1 - Signature invalid
  2 - Input error

Examples:
  # Verify a document
  $(basename "$0") -k keys/signer_public.key -d contract.pdf

  # JSON output for scripting
  $(basename "$0") -k keys/signer_public.key -d contract.pdf --json
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
        -d|--document)
            DOCUMENT="$2"
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
[ -z "$DOCUMENT" ] && error "Document is required (-d/--document)"
[ ! -f "$KEY" ] && error "Public key not found: $KEY"
[ ! -f "$DOCUMENT" ] && error "Document not found: $DOCUMENT"

# Default signature path
if [ -z "$SIGNATURE" ]; then
    SIGNATURE="${DOCUMENT}.docsig"
fi
[ ! -f "$SIGNATURE" ] && error "Signature file not found: $SIGNATURE"

# Get directories for mounting
KEY_DIR="$(cd "$(dirname "$KEY")" && pwd)"
DOC_DIR="$(cd "$(dirname "$DOCUMENT")" && pwd)"
SIG_DIR="$(cd "$(dirname "$SIGNATURE")" && pwd)"

# Build extra args
EXTRA_ARGS=""
[ "$QUIET" = true ] && EXTRA_ARGS="$EXTRA_ARGS --quiet"
[ "$JSON" = true ] && EXTRA_ARGS="$EXTRA_ARGS --json"

# Run verification
docker run --rm \
    -v "$KEY_DIR:/keys:ro" \
    -v "$DOC_DIR:/work:ro" \
    -v "$SIG_DIR:/sigs:ro" \
    -v "$SCRIPT_DIR:/app/tools:ro" \
    dsa-py python /app/tools/verify_document.py \
        --key "/keys/$(basename "$KEY")" \
        --document "/work/$(basename "$DOCUMENT")" \
        --signature "/sigs/$(basename "$SIGNATURE")" \
        $EXTRA_ARGS

exit $?
