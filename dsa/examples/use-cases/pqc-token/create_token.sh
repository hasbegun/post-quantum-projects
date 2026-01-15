#!/bin/bash
#
# Post-Quantum Token Creation Shell Script
#
# Usage:
#   ./create_token.sh --key <secret_key> --payload '{"sub": "user"}'
#
# Examples:
#   ./create_token.sh --key keys/token_secret.key --payload '{"sub": "user123"}'
#   ./create_token.sh --key keys/token_secret.key --payload '{"role": "admin"}' --expires 3600
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Default values
KEY=""
PAYLOAD=""
ALGORITHM=""
EXPIRES=""
NBF=""
ISSUER=""
SUBJECT=""
AUDIENCE=""
TOKEN_ID=""
JSON_OUTPUT=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

usage() {
    cat << EOF
Post-Quantum Token Creation Tool

Usage: $(basename "$0") [OPTIONS]

Required:
  -k, --key FILE          Secret key file for signing
  -p, --payload JSON      Token payload as JSON string

Options:
  -a, --algorithm ALG     Signing algorithm (auto-detected from key)
  --expires SECONDS       Token expiration time in seconds
  --nbf TIMESTAMP         Not valid before (Unix timestamp)
  --issuer STRING         Token issuer (iss claim)
  --subject STRING        Token subject (sub claim)
  --audience STRING       Token audience (aud claim)
  --token-id STRING       Unique token ID (jti claim)
  --json                  Output as JSON
  -h, --help              Show this help

Examples:
  # Create a simple token
  $(basename "$0") -k keys/token_secret.key -p '{"sub": "user123"}'

  # Create token with 1 hour expiration
  $(basename "$0") -k keys/token_secret.key -p '{"role": "admin"}' --expires 3600

  # Create token with issuer and subject
  $(basename "$0") -k keys/token_secret.key -p '{"scope": "read"}' \\
      --issuer "auth.example.com" --subject "user@example.com"
EOF
}

error() {
    echo -e "${RED}Error: $1${NC}" >&2
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -k|--key)
            KEY="$2"
            shift 2
            ;;
        -p|--payload)
            PAYLOAD="$2"
            shift 2
            ;;
        -a|--algorithm)
            ALGORITHM="$2"
            shift 2
            ;;
        --expires)
            EXPIRES="$2"
            shift 2
            ;;
        --nbf)
            NBF="$2"
            shift 2
            ;;
        --issuer)
            ISSUER="$2"
            shift 2
            ;;
        --subject)
            SUBJECT="$2"
            shift 2
            ;;
        --audience)
            AUDIENCE="$2"
            shift 2
            ;;
        --token-id)
            TOKEN_ID="$2"
            shift 2
            ;;
        --json)
            JSON_OUTPUT=true
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
[ -z "$PAYLOAD" ] && error "Payload is required (-p/--payload)"
[ ! -f "$KEY" ] && error "Secret key not found: $KEY"

# Get key directory for mounting
KEY_DIR="$(cd "$(dirname "$KEY")" && pwd)"
KEY_NAME="$(basename "$KEY")"

# Build command arguments
CMD_ARGS="create --key /keys/$KEY_NAME --payload '$PAYLOAD'"

[ -n "$ALGORITHM" ] && CMD_ARGS="$CMD_ARGS --algorithm $ALGORITHM"
[ -n "$EXPIRES" ] && CMD_ARGS="$CMD_ARGS --expires $EXPIRES"
[ -n "$NBF" ] && CMD_ARGS="$CMD_ARGS --nbf $NBF"
[ -n "$ISSUER" ] && CMD_ARGS="$CMD_ARGS --issuer '$ISSUER'"
[ -n "$SUBJECT" ] && CMD_ARGS="$CMD_ARGS --subject '$SUBJECT'"
[ -n "$AUDIENCE" ] && CMD_ARGS="$CMD_ARGS --audience '$AUDIENCE'"
[ -n "$TOKEN_ID" ] && CMD_ARGS="$CMD_ARGS --token-id '$TOKEN_ID'"
[ "$JSON_OUTPUT" = true ] && CMD_ARGS="$CMD_ARGS --json"

# Run token creation
docker run --rm \
    -v "$KEY_DIR:/keys:ro" \
    -v "$SCRIPT_DIR:/app/tools:ro" \
    dsa-py bash -c "python /app/tools/pqc_token.py $CMD_ARGS"
