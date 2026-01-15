#!/bin/bash
#
# Post-Quantum Document Signing Shell Script
#
# Usage:
#   ./sign.sh --key <secret_key> --document <document> [options]
#
# Examples:
#   ./sign.sh --key keys/signer_secret.key --document contract.pdf
#   ./sign.sh -k keys/signer_secret.key -d agreement.pdf --signer-name "John Doe"
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Default values
KEY=""
DOCUMENT=""
ALGORITHM=""
OUTPUT=""
SIGNER_NAME=""
SIGNER_EMAIL=""
SIGNER_ORG=""
REASON=""
LOCATION=""
CONTEXT=""
QUIET=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

usage() {
    cat << EOF
Post-Quantum Document Signing Tool

Usage: $(basename "$0") [OPTIONS]

Required:
  -k, --key FILE           Secret key file for signing
  -d, --document FILE      Document to sign

Options:
  -a, --algorithm ALG      Signing algorithm (mldsa44, mldsa65, mldsa87, slh-shake-*)
  -o, --output FILE        Output signature file (default: <document>.docsig)
  --signer-name NAME       Name of the signer
  --signer-email EMAIL     Email of the signer
  --signer-org ORG         Organization of the signer
  --reason REASON          Reason for signing
  --location LOCATION      Location where signed
  -c, --context STR        Context string for domain separation
  -q, --quiet              Suppress output
  -h, --help               Show this help

Examples:
  # Sign a document
  $(basename "$0") -k keys/signer_secret.key -d contract.pdf

  # Sign with identity and reason
  $(basename "$0") -k keys/signer_secret.key -d agreement.pdf \\
      --signer-name "John Doe" --reason "Contract approval"
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
        -d|--document)
            DOCUMENT="$2"
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
        --signer-name)
            SIGNER_NAME="$2"
            shift 2
            ;;
        --signer-email)
            SIGNER_EMAIL="$2"
            shift 2
            ;;
        --signer-org)
            SIGNER_ORG="$2"
            shift 2
            ;;
        --reason)
            REASON="$2"
            shift 2
            ;;
        --location)
            LOCATION="$2"
            shift 2
            ;;
        -c|--context)
            CONTEXT="$2"
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
[ -z "$DOCUMENT" ] && error "Document is required (-d/--document)"
[ ! -f "$KEY" ] && error "Secret key not found: $KEY"
[ ! -f "$DOCUMENT" ] && error "Document not found: $DOCUMENT"

# Get directories for mounting
KEY_DIR="$(cd "$(dirname "$KEY")" && pwd)"
DOC_DIR="$(cd "$(dirname "$DOCUMENT")" && pwd)"

info "Signing document: $DOCUMENT"

docker run --rm \
    -v "$KEY_DIR:/keys:ro" \
    -v "$DOC_DIR:/work" \
    -v "$SCRIPT_DIR:/app/tools:ro" \
    dsa-py python /app/tools/sign_document.py \
        --key "/keys/$(basename "$KEY")" \
        --document "/work/$(basename "$DOCUMENT")" \
        ${ALGORITHM:+--algorithm "$ALGORITHM"} \
        ${OUTPUT:+--output "/work/$(basename "$OUTPUT")"} \
        ${SIGNER_NAME:+--signer-name "$SIGNER_NAME"} \
        ${SIGNER_EMAIL:+--signer-email "$SIGNER_EMAIL"} \
        ${SIGNER_ORG:+--signer-org "$SIGNER_ORG"} \
        ${REASON:+--reason "$REASON"} \
        ${LOCATION:+--location "$LOCATION"} \
        ${CONTEXT:+--context "$CONTEXT"} \
        ${QUIET:+--quiet}

info "Document signed successfully!"
