#!/bin/bash
# Download NIST ACVP KAT vectors for ML-DSA and SLH-DSA

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KAT_DIR="${SCRIPT_DIR}/../tests/kat"

echo "Creating KAT directory..."
mkdir -p "${KAT_DIR}/mldsa"
mkdir -p "${KAT_DIR}/slhdsa"

ACVP_BASE="https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files"

echo "Downloading ML-DSA KAT vectors..."

# ML-DSA keyGen
curl -sL "${ACVP_BASE}/ML-DSA-keyGen-FIPS204/prompt.json" -o "${KAT_DIR}/mldsa/keyGen_prompt.json"
curl -sL "${ACVP_BASE}/ML-DSA-keyGen-FIPS204/expectedResults.json" -o "${KAT_DIR}/mldsa/keyGen_expected.json"

# ML-DSA sigGen
curl -sL "${ACVP_BASE}/ML-DSA-sigGen-FIPS204/prompt.json" -o "${KAT_DIR}/mldsa/sigGen_prompt.json"
curl -sL "${ACVP_BASE}/ML-DSA-sigGen-FIPS204/expectedResults.json" -o "${KAT_DIR}/mldsa/sigGen_expected.json"

# ML-DSA sigVer
curl -sL "${ACVP_BASE}/ML-DSA-sigVer-FIPS204/prompt.json" -o "${KAT_DIR}/mldsa/sigVer_prompt.json"
curl -sL "${ACVP_BASE}/ML-DSA-sigVer-FIPS204/expectedResults.json" -o "${KAT_DIR}/mldsa/sigVer_expected.json"

echo "Downloading SLH-DSA KAT vectors..."

# SLH-DSA keyGen
curl -sL "${ACVP_BASE}/SLH-DSA-keyGen-FIPS205/prompt.json" -o "${KAT_DIR}/slhdsa/keyGen_prompt.json"
curl -sL "${ACVP_BASE}/SLH-DSA-keyGen-FIPS205/expectedResults.json" -o "${KAT_DIR}/slhdsa/keyGen_expected.json"

# SLH-DSA sigGen
curl -sL "${ACVP_BASE}/SLH-DSA-sigGen-FIPS205/prompt.json" -o "${KAT_DIR}/slhdsa/sigGen_prompt.json"
curl -sL "${ACVP_BASE}/SLH-DSA-sigGen-FIPS205/expectedResults.json" -o "${KAT_DIR}/slhdsa/sigGen_expected.json"

# SLH-DSA sigVer
curl -sL "${ACVP_BASE}/SLH-DSA-sigVer-FIPS205/prompt.json" -o "${KAT_DIR}/slhdsa/sigVer_prompt.json"
curl -sL "${ACVP_BASE}/SLH-DSA-sigVer-FIPS205/expectedResults.json" -o "${KAT_DIR}/slhdsa/sigVer_expected.json"

echo "KAT vectors downloaded to ${KAT_DIR}"
echo ""
echo "Files downloaded:"
find "${KAT_DIR}" -name "*.json" -exec ls -lh {} \;
