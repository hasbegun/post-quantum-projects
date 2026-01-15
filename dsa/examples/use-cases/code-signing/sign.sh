#!/bin/bash
#
# Post-Quantum Code Signing Shell Script
#
# Usage:
#   ./sign.sh --key <secret_key> --file <file_to_sign> [options]
#
# Examples:
#   ./sign.sh --key keys/release_secret.key --file dist/release.tar.gz
#   ./sign.sh -k keys/signing.key -f app.exe -a mldsa87
#
# This script wraps the Python implementation for easy command-line use.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Default values
KEY=""
FILE=""
ALGORITHM=""
OUTPUT=""
CONTEXT=""
SIGNER_NAME=""
SIGNER_EMAIL=""
QUIET=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    cat << EOF
Post-Quantum Code Signing Tool

Usage: $(basename "$0") [OPTIONS]

Required:
  -k, --key FILE       Secret key file for signing
  -f, --file FILE      File to sign

Options:
  -a, --algorithm ALG  Signing algorithm (mldsa44, mldsa65, mldsa87, slh-shake-*)
  -o, --output FILE    Output signature file (default: <file>.sig)
  -c, --context STR    Context string for domain separation
  --signer-name NAME   Signer name
  --signer-email EMAIL Signer email
  -q, --quiet          Suppress output
  -h, --help           Show this help

Examples:
  # Sign a release tarball
  $(basename "$0") -k keys/release_secret.key -f dist/myapp-1.0.0.tar.gz

  # Sign with specific algorithm
  $(basename "$0") -k keys/signing.key -f app.exe -a mldsa87

  # Sign with context
  $(basename "$0") -k keys/signing.key -f firmware.bin -c "firmware-v2"
EOF
}

error() {
    echo -e "${RED}Error: $1${NC}" >&2
    exit 1
}

info() {
    if [ "$QUIET" = false ]; then
        echo -e "${GREEN}$1${NC}"
    fi
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
        -a|--algorithm)
            ALGORITHM="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT="$2"
            shift 2
            ;;
        -c|--context)
            CONTEXT="$2"
            shift 2
            ;;
        --signer-name)
            SIGNER_NAME="$2"
            shift 2
            ;;
        --signer-email)
            SIGNER_EMAIL="$2"
            shift 2
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
[ -z "$KEY" ] && error "Secret key is required (-k/--key)"
[ -z "$FILE" ] && error "File to sign is required (-f/--file)"
[ ! -f "$KEY" ] && error "Secret key not found: $KEY"
[ ! -f "$FILE" ] && error "File not found: $FILE"

# Build command arguments
CMD_ARGS="--key /work/$(basename "$KEY") --file /work/$(basename "$FILE")"

[ -n "$ALGORITHM" ] && CMD_ARGS="$CMD_ARGS --algorithm $ALGORITHM"
[ -n "$OUTPUT" ] && CMD_ARGS="$CMD_ARGS --output /work/$(basename "$OUTPUT")"
[ -n "$CONTEXT" ] && CMD_ARGS="$CMD_ARGS --context $CONTEXT"
[ -n "$SIGNER_NAME" ] && CMD_ARGS="$CMD_ARGS --signer-name \"$SIGNER_NAME\""
[ -n "$SIGNER_EMAIL" ] && CMD_ARGS="$CMD_ARGS --signer-email \"$SIGNER_EMAIL\""
[ "$QUIET" = true ] && CMD_ARGS="$CMD_ARGS --quiet"

# Run in Docker
info "Signing file: $FILE"

# Get directories for mounting
KEY_DIR="$(cd "$(dirname "$KEY")" && pwd)"
FILE_DIR="$(cd "$(dirname "$FILE")" && pwd)"

docker run --rm \
    -v "$KEY_DIR:/keys:ro" \
    -v "$FILE_DIR:/work" \
    -v "$SCRIPT_DIR:/app/tools:ro" \
    dsa-py python /app/tools/sign_release.py \
        --key "/keys/$(basename "$KEY")" \
        --file "/work/$(basename "$FILE")" \
        ${ALGORITHM:+--algorithm "$ALGORITHM"} \
        ${OUTPUT:+--output "/work/$(basename "$OUTPUT")"} \
        ${CONTEXT:+--context "$CONTEXT"} \
        ${SIGNER_NAME:+--signer-name "$SIGNER_NAME"} \
        ${SIGNER_EMAIL:+--signer-email "$SIGNER_EMAIL"} \
        ${QUIET:+--quiet}

info "Signature created successfully!"
