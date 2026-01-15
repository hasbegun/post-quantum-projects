#!/bin/bash
#
# Post-Quantum Firmware Verification Shell Script
#
# Usage:
#   ./verify.sh --key <public_key> --firmware <firmware.bin> [options]
#
# Examples:
#   ./verify.sh --key keys/fw_public.key --firmware build/firmware.bin
#   ./verify.sh -k keys/fw_public.key -f firmware.bin --device-type "IoT-Sensor"
#
# Exit codes:
#   0 - Verification successful, safe to install
#   1 - Signature or integrity verification failed
#   2 - Input error
#   3 - Rollback protection triggered
#   4 - Device compatibility error
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Default values
KEY=""
FIRMWARE=""
MANIFEST=""
CURRENT_VERSION=""
DEVICE_TYPE=""
DEVICE_MODEL=""
QUIET=false
JSON=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

usage() {
    cat << EOF
Post-Quantum Firmware Verification Tool

Usage: $(basename "$0") [OPTIONS]

Required:
  -k, --key FILE           Public key file for verification
  -f, --firmware FILE      Firmware binary to verify

Options:
  -m, --manifest FILE      Manifest file (default: <firmware>.fwsig)
  --current-version CODE   Current version code for rollback check
  --device-type TYPE       Device type for compatibility check
  --device-model MODEL     Device model for compatibility check
  -q, --quiet              Suppress output, use exit code only
  --json                   Output result as JSON
  -h, --help               Show this help

Exit Codes:
  0 - Verification successful, safe to install
  1 - Signature or integrity verification failed
  2 - Input error
  3 - Rollback protection triggered
  4 - Device compatibility error

Examples:
  # Basic verification
  $(basename "$0") -k keys/fw_public.key -f build/firmware.bin

  # With rollback protection
  $(basename "$0") -k keys/fw_public.key -f update.bin --current-version 2000000

  # With device compatibility check
  $(basename "$0") -k keys/fw_public.key -f firmware.bin \
      --device-type "Sensor-v2" --device-model "Model-A"

  # JSON output for scripting
  $(basename "$0") -k keys/fw_public.key -f firmware.bin --json
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
        -f|--firmware)
            FIRMWARE="$2"
            shift 2
            ;;
        -m|--manifest)
            MANIFEST="$2"
            shift 2
            ;;
        --current-version)
            CURRENT_VERSION="$2"
            shift 2
            ;;
        --device-type)
            DEVICE_TYPE="$2"
            shift 2
            ;;
        --device-model)
            DEVICE_MODEL="$2"
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
[ -z "$FIRMWARE" ] && error "Firmware file is required (-f/--firmware)"
[ ! -f "$KEY" ] && error "Public key not found: $KEY"
[ ! -f "$FIRMWARE" ] && error "Firmware file not found: $FIRMWARE"

# Default manifest path
if [ -z "$MANIFEST" ]; then
    MANIFEST="${FIRMWARE}.fwsig"
fi
[ ! -f "$MANIFEST" ] && error "Manifest file not found: $MANIFEST"

# Get directories for mounting
KEY_DIR="$(cd "$(dirname "$KEY")" && pwd)"
FW_DIR="$(cd "$(dirname "$FIRMWARE")" && pwd)"
MANIFEST_DIR="$(cd "$(dirname "$MANIFEST")" && pwd)"

# Build extra args
EXTRA_ARGS=""
[ "$QUIET" = true ] && EXTRA_ARGS="$EXTRA_ARGS --quiet"
[ "$JSON" = true ] && EXTRA_ARGS="$EXTRA_ARGS --json"
[ -n "$CURRENT_VERSION" ] && EXTRA_ARGS="$EXTRA_ARGS --current-version $CURRENT_VERSION"
[ -n "$DEVICE_TYPE" ] && EXTRA_ARGS="$EXTRA_ARGS --device-type \"$DEVICE_TYPE\""
[ -n "$DEVICE_MODEL" ] && EXTRA_ARGS="$EXTRA_ARGS --device-model \"$DEVICE_MODEL\""

# Run verification
docker run --rm \
    -v "$KEY_DIR:/keys:ro" \
    -v "$FW_DIR:/work:ro" \
    -v "$MANIFEST_DIR:/manifests:ro" \
    -v "$SCRIPT_DIR:/app/tools:ro" \
    dsa-py python /app/tools/verify_firmware.py \
        --key "/keys/$(basename "$KEY")" \
        --firmware "/work/$(basename "$FIRMWARE")" \
        --manifest "/manifests/$(basename "$MANIFEST")" \
        ${CURRENT_VERSION:+--current-version "$CURRENT_VERSION"} \
        ${DEVICE_TYPE:+--device-type "$DEVICE_TYPE"} \
        ${DEVICE_MODEL:+--device-model "$DEVICE_MODEL"} \
        ${QUIET:+--quiet} \
        ${JSON:+--json}

exit $?
