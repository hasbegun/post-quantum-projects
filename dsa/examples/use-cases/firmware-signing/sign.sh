#!/bin/bash
#
# Post-Quantum Firmware Signing Shell Script
#
# Usage:
#   ./sign.sh --key <secret_key> --firmware <firmware.bin> --version <version> --device-type <type> [options]
#
# Examples:
#   ./sign.sh --key keys/fw_secret.key --firmware build/firmware.bin --version 2.1.0 --device-type "IoT-Sensor"
#
# This script wraps the Python implementation for easy command-line use.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Default values
KEY=""
FIRMWARE=""
VERSION=""
DEVICE_TYPE=""
ALGORITHM=""
OUTPUT=""
HARDWARE_REV=""
BUILD_ID=""
DESCRIPTION=""
MIN_BOOTLOADER=""
COMPATIBLE=()
SIGNER_NAME=""
SIGNER_ORG=""
QUIET=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

usage() {
    cat << EOF
Post-Quantum Firmware Signing Tool

Usage: $(basename "$0") [OPTIONS]

Required:
  -k, --key FILE           Secret key file for signing
  -f, --firmware FILE      Firmware binary to sign
  -v, --version VERSION    Firmware version (e.g., 2.1.0)
  -d, --device-type TYPE   Device type identifier

Options:
  -a, --algorithm ALG      Signing algorithm (mldsa44, mldsa65, mldsa87, slh-shake-*)
  -o, --output FILE        Output manifest file (default: <firmware>.fwsig)
  --hardware-rev REV       Hardware revision
  --build-id ID            Build identifier
  --description DESC       Firmware description
  --min-bootloader VER     Minimum bootloader version
  --compatible MODEL       Compatible device model (repeatable)
  --signer-name NAME       Signer name
  --signer-org ORG         Signer organization
  -q, --quiet              Suppress output
  -h, --help               Show this help

Examples:
  # Sign firmware with minimal info
  $(basename "$0") -k keys/fw_secret.key -f firmware.bin -v 2.1.0 -d "Sensor-v1"

  # Sign with full metadata
  $(basename "$0") -k keys/fw_secret.key -f update.bin -v 3.0.0 -d "Gateway" \\
      --hardware-rev "rev-c" --build-id "build-12345" \\
      --description "Security update" --compatible "Model-A" --compatible "Model-B"
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
        -f|--firmware)
            FIRMWARE="$2"
            shift 2
            ;;
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -d|--device-type)
            DEVICE_TYPE="$2"
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
        --hardware-rev)
            HARDWARE_REV="$2"
            shift 2
            ;;
        --build-id)
            BUILD_ID="$2"
            shift 2
            ;;
        --description)
            DESCRIPTION="$2"
            shift 2
            ;;
        --min-bootloader)
            MIN_BOOTLOADER="$2"
            shift 2
            ;;
        --compatible)
            COMPATIBLE+=("$2")
            shift 2
            ;;
        --signer-name)
            SIGNER_NAME="$2"
            shift 2
            ;;
        --signer-org)
            SIGNER_ORG="$2"
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
[ -z "$FIRMWARE" ] && error "Firmware file is required (-f/--firmware)"
[ -z "$VERSION" ] && error "Version is required (-v/--version)"
[ -z "$DEVICE_TYPE" ] && error "Device type is required (-d/--device-type)"
[ ! -f "$KEY" ] && error "Secret key not found: $KEY"
[ ! -f "$FIRMWARE" ] && error "Firmware file not found: $FIRMWARE"

# Get directories for mounting
KEY_DIR="$(cd "$(dirname "$KEY")" && pwd)"
FW_DIR="$(cd "$(dirname "$FIRMWARE")" && pwd)"

# Build compatible args
COMPATIBLE_ARGS=""
for model in "${COMPATIBLE[@]}"; do
    COMPATIBLE_ARGS="$COMPATIBLE_ARGS --compatible \"$model\""
done

info "Signing firmware: $FIRMWARE"

docker run --rm \
    -v "$KEY_DIR:/keys:ro" \
    -v "$FW_DIR:/work" \
    -v "$SCRIPT_DIR:/app/tools:ro" \
    dsa-py python /app/tools/sign_firmware.py \
        --key "/keys/$(basename "$KEY")" \
        --firmware "/work/$(basename "$FIRMWARE")" \
        --version "$VERSION" \
        --device-type "$DEVICE_TYPE" \
        ${ALGORITHM:+--algorithm "$ALGORITHM"} \
        ${OUTPUT:+--output "/work/$(basename "$OUTPUT")"} \
        ${HARDWARE_REV:+--hardware-rev "$HARDWARE_REV"} \
        ${BUILD_ID:+--build-id "$BUILD_ID"} \
        ${DESCRIPTION:+--description "$DESCRIPTION"} \
        ${MIN_BOOTLOADER:+--min-bootloader "$MIN_BOOTLOADER"} \
        ${SIGNER_NAME:+--signer-name "$SIGNER_NAME"} \
        ${SIGNER_ORG:+--signer-org "$SIGNER_ORG"} \
        ${QUIET:+--quiet}

info "Firmware signed successfully!"
