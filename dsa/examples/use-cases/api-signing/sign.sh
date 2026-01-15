#!/bin/bash
#
# Post-Quantum API Request Signing Shell Script
#
# Usage:
#   ./sign.sh --key <secret_key> --method <method> --path <path> [options]
#
# Examples:
#   ./sign.sh --key keys/api_secret.key --method GET --path /api/v1/users
#   ./sign.sh --key keys/api_secret.key --method POST --path /api/v1/orders \
#       --header "Content-Type: application/json" --body '{"item": "widget"}'
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Default values
KEY=""
METHOD=""
REQUEST_PATH=""
HEADERS=()
QUERY_PARAMS=()
BODY=""
HOST=""
ALGORITHM=""
KEY_ID="default"
JSON_OUTPUT=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

usage() {
    cat << EOF
Post-Quantum API Request Signing Tool

Usage: $(basename "$0") [OPTIONS]

Required:
  -k, --key FILE          Secret key file for signing
  -m, --method METHOD     HTTP method (GET, POST, PUT, DELETE, etc.)
  -p, --path PATH         Request path (e.g., /api/v1/resource)

Options:
  --header "Name: Value"  Header to include (can be repeated)
  --query "key=value"     Query parameter (can be repeated)
  --body JSON             Request body (JSON string)
  --host HOST             Host header value
  -a, --algorithm ALG     Signing algorithm (auto-detected)
  --key-id ID             Key identifier (default: "default")
  --json                  Output as JSON
  -h, --help              Show this help

Examples:
  # Sign a GET request
  $(basename "$0") -k keys/api_secret.key -m GET -p /api/v1/users

  # Sign a POST with body
  $(basename "$0") -k keys/api_secret.key -m POST -p /api/v1/orders \\
      --header "Content-Type: application/json" --body '{"item": "widget"}'
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
        -m|--method)
            METHOD="$2"
            shift 2
            ;;
        -p|--path)
            REQUEST_PATH="$2"
            shift 2
            ;;
        --header)
            HEADERS+=("$2")
            shift 2
            ;;
        --query)
            QUERY_PARAMS+=("$2")
            shift 2
            ;;
        --body)
            BODY="$2"
            shift 2
            ;;
        --host)
            HOST="$2"
            shift 2
            ;;
        -a|--algorithm)
            ALGORITHM="$2"
            shift 2
            ;;
        --key-id)
            KEY_ID="$2"
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
[ -z "$METHOD" ] && error "HTTP method is required (-m/--method)"
[ -z "$REQUEST_PATH" ] && error "Request path is required (-p/--path)"
[ ! -f "$KEY" ] && error "Secret key not found: $KEY"

# Get key directory for mounting
KEY_DIR="$(cd "$(dirname "$KEY")" && pwd)"

# Build header args
HEADER_ARGS=""
for h in "${HEADERS[@]}"; do
    HEADER_ARGS="$HEADER_ARGS --header \"$h\""
done

# Build query args
QUERY_ARGS=""
for q in "${QUERY_PARAMS[@]}"; do
    QUERY_ARGS="$QUERY_ARGS --query \"$q\""
done

# Run signing
docker run --rm \
    -v "$KEY_DIR:/keys:ro" \
    -v "$SCRIPT_DIR:/app/tools:ro" \
    dsa-py python /app/tools/sign_request.py \
        --key "/keys/$(basename "$KEY")" \
        --method "$METHOD" \
        --path "$REQUEST_PATH" \
        ${ALGORITHM:+--algorithm "$ALGORITHM"} \
        --key-id "$KEY_ID" \
        ${HOST:+--host "$HOST"} \
        ${BODY:+--body "$BODY"} \
        ${JSON_OUTPUT:+--json} \
        $(for h in "${HEADERS[@]}"; do echo "--header \"$h\""; done) \
        $(for q in "${QUERY_PARAMS[@]}"; do echo "--query \"$q\""; done)
