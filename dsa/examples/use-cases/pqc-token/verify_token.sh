#!/bin/bash
#
# Post-Quantum Token Verification Shell Script
#
# Usage:
#   ./verify_token.sh --key <public_key> --token <token_string>
#
# Exit codes:
#   0 - Token valid
#   1 - Token invalid
#   2 - Input error
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Default values
KEY=""
TOKEN=""
ALGORITHM=""
NO_EXP=false
NO_NBF=false
LEEWAY=""
JSON_OUTPUT=false
QUIET=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

usage() {
    cat << EOF
Post-Quantum Token Verification Tool

Usage: $(basename "$0") [OPTIONS]

Required:
  -k, --key FILE          Public key file for verification
  -t, --token STRING      Token to verify

Options:
  -a, --algorithm ALG     Expected algorithm (auto-detected from key)
  --no-exp                Skip expiration verification
  --no-nbf                Skip not-before verification
  --leeway SECONDS        Clock skew allowance in seconds
  --json                  Output as JSON
  -q, --quiet             Exit code only
  -h, --help              Show this help

Exit Codes:
  0 - Token valid
  1 - Token invalid (signature, expired, etc.)
  2 - Input error

Examples:
  # Verify a token
  $(basename "$0") -k keys/token_public.key -t "eyJhbGciOi..."

  # Verify with clock skew tolerance
  $(basename "$0") -k keys/token_public.key -t "eyJhbGciOi..." --leeway 60

  # Skip expiration check (for testing)
  $(basename "$0") -k keys/token_public.key -t "eyJhbGciOi..." --no-exp
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
        -t|--token)
            TOKEN="$2"
            shift 2
            ;;
        -a|--algorithm)
            ALGORITHM="$2"
            shift 2
            ;;
        --no-exp)
            NO_EXP=true
            shift
            ;;
        --no-nbf)
            NO_NBF=true
            shift
            ;;
        --leeway)
            LEEWAY="$2"
            shift 2
            ;;
        --json)
            JSON_OUTPUT=true
            shift
            ;;
        -q|--quiet)
            QUIET=true
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
[ -z "$TOKEN" ] && error "Token is required (-t/--token)"
[ ! -f "$KEY" ] && error "Public key not found: $KEY"

# Get key directory for mounting
KEY_DIR="$(cd "$(dirname "$KEY")" && pwd)"
KEY_NAME="$(basename "$KEY")"

# Build command arguments
CMD_ARGS="verify --key /keys/$KEY_NAME --token '$TOKEN'"

[ -n "$ALGORITHM" ] && CMD_ARGS="$CMD_ARGS --algorithm $ALGORITHM"
[ "$NO_EXP" = true ] && CMD_ARGS="$CMD_ARGS --no-exp"
[ "$NO_NBF" = true ] && CMD_ARGS="$CMD_ARGS --no-nbf"
[ -n "$LEEWAY" ] && CMD_ARGS="$CMD_ARGS --leeway $LEEWAY"
[ "$JSON_OUTPUT" = true ] && CMD_ARGS="$CMD_ARGS --json"
[ "$QUIET" = true ] && CMD_ARGS="$CMD_ARGS --quiet"

# Run token verification
docker run --rm \
    -v "$KEY_DIR:/keys:ro" \
    -v "$SCRIPT_DIR:/app/tools:ro" \
    dsa-py bash -c "python /app/tools/pqc_token.py $CMD_ARGS"
