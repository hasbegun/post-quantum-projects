# Post-Quantum Document Signing

Sign and verify documents (PDFs, contracts, legal documents) using post-quantum cryptographic signatures with signer identity and timestamping.

## Overview

This example demonstrates document signing with:

- **Signer Identity**: Name, email, organization
- **Signing Details**: Reason for signing, location
- **Timestamping**: ISO 8601 timestamps
- **Dual Hashing**: SHA-256 and SHA-512 for integrity
- **Long-Term Validity**: Post-quantum signatures resistant to future quantum attacks

### Features

| Feature | Description |
|---------|-------------|
| Post-Quantum Signatures | ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) |
| Signer Identity | Name, email, organization embedded in signature |
| Signing Reason | Purpose of signature (e.g., "Contract approval") |
| Location | Where the document was signed |
| Timestamping | Cryptographic timestamp for signing time |
| Dual Hash | SHA-256 and SHA-512 for redundancy |

### Algorithm Recommendations

| Use Case | Algorithm | Rationale |
|----------|-----------|-----------|
| Standard documents | **ML-DSA-65** | Balanced security/performance |
| Legal contracts | **ML-DSA-87** | Maximum security |
| Long-term archival | **SLH-DSA-SHAKE-256f** | Conservative, hash-based |
| High-volume signing | **ML-DSA-44** | Fastest signing |

## Quick Start (Docker)

### 1. Generate Signing Keys

```bash
# From project root
make keygen-cpp ALG=mldsa65 OUT=doc-signing \
    CN="Document Signing Key" ORG="Legal Department"
```

### 2. Sign a Document

```bash
docker run --rm \
  -v $(pwd)/keys:/keys:ro \
  -v $(pwd):/work \
  -w /work \
  dsa-py python examples/use-cases/document-signing/sign_document.py \
    --key /keys/doc-signing_secret.key \
    --document contracts/agreement.pdf \
    --signer-name "Jane Smith" \
    --signer-email "jane.smith@example.com" \
    --reason "Contract approval"
```

Output: `contracts/agreement.pdf.docsig`

### 3. Verify a Document

```bash
docker run --rm \
  -v $(pwd)/keys:/keys:ro \
  -v $(pwd):/work \
  -w /work \
  dsa-py python examples/use-cases/document-signing/verify_document.py \
    --key /keys/doc-signing_public.key \
    --document contracts/agreement.pdf
```

## Shell Script Usage

For convenience, shell script wrappers are provided:

### Sign a Document

```bash
./sign.sh --key keys/signer_secret.key --document contract.pdf \
    --signer-name "John Doe" --reason "Approval"
```

### Verify a Document

```bash
./verify.sh --key keys/signer_public.key --document contract.pdf
```

## Detailed Usage

### Signing Options

```bash
python sign_document.py [OPTIONS]

Required:
  --key, -k PATH         Secret key file
  --document, -d PATH    Document to sign

Optional:
  --algorithm, -a ALG    Signing algorithm (auto-detected)
  --output, -o PATH      Output signature (default: <document>.docsig)
  --signer-name NAME     Signer's name
  --signer-email EMAIL   Signer's email
  --signer-org ORG       Signer's organization
  --reason REASON        Reason for signing
  --location LOCATION    Signing location
  --context, -c STR      Context for domain separation
  --quiet, -q            Suppress output
```

### Verification Options

```bash
python verify_document.py [OPTIONS]

Required:
  --key, -k PATH         Public key file
  --document, -d PATH    Document to verify

Optional:
  --signature, -s PATH   Signature file (default: <document>.docsig)
  --quiet, -q            Exit code only
  --json                 JSON output
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Signature valid |
| 1 | Signature invalid or verification failed |
| 2 | Input error (file not found) |

## Signature Manifest Format

The `.docsig` file contains:

```json
{
  "manifest_version": "1.0",
  "type": "document-signature",
  "algorithm": {
    "id": "mldsa65",
    "name": "ML-DSA-65",
    "security_level": "NIST Level 3",
    "standard": "FIPS 204"
  },
  "document": {
    "name": "contract.pdf",
    "size": 125430,
    "hashes": {
      "sha256": "abc123...",
      "sha512": "def456..."
    }
  },
  "signature": {
    "value": "...",
    "encoding": "hex",
    "context": "646f63756d656e74"
  },
  "timestamp": "2024-01-15T10:30:00+00:00",
  "signer": {
    "name": "Jane Smith",
    "email": "jane.smith@example.com",
    "organization": "Legal Department"
  },
  "signing_details": {
    "reason": "Contract approval",
    "location": "New York, NY"
  }
}
```

## Integration Examples

### Document Management System (Python)

```python
from pathlib import Path
import subprocess
import json

def sign_document(doc_path: str, key_path: str, signer_info: dict) -> dict:
    """Sign a document and return the signature info."""
    cmd = [
        'python', 'sign_document.py',
        '--key', key_path,
        '--document', doc_path,
        '--signer-name', signer_info.get('name', ''),
        '--signer-email', signer_info.get('email', ''),
        '--reason', signer_info.get('reason', 'Document approved'),
    ]
    subprocess.run(cmd, check=True)

    # Read the generated signature
    sig_path = Path(doc_path + '.docsig')
    return json.loads(sig_path.read_text())

def verify_document(doc_path: str, key_path: str) -> bool:
    """Verify a document signature."""
    cmd = [
        'python', 'verify_document.py',
        '--key', key_path,
        '--document', doc_path,
        '--quiet'
    ]
    result = subprocess.run(cmd)
    return result.returncode == 0
```

### Workflow Automation

```python
class DocumentWorkflow:
    def __init__(self, signing_key: str, verify_key: str):
        self.signing_key = signing_key
        self.verify_key = verify_key

    def submit_for_approval(self, doc_path: str, approver: dict):
        """Queue document for approval."""
        # Store document and approver info
        pass

    def approve(self, doc_path: str, approver: dict, reason: str):
        """Sign document as approved."""
        sign_document(
            doc_path=doc_path,
            key_path=self.signing_key,
            signer_info={
                'name': approver['name'],
                'email': approver['email'],
                'reason': reason,
            }
        )

    def verify_approval(self, doc_path: str) -> dict:
        """Verify document was properly approved."""
        sig_path = Path(doc_path + '.docsig')
        if not sig_path.exists():
            return {'approved': False, 'error': 'No signature found'}

        is_valid = verify_document(doc_path, self.verify_key)

        if is_valid:
            sig_data = json.loads(sig_path.read_text())
            return {
                'approved': True,
                'signer': sig_data.get('signer', {}),
                'timestamp': sig_data.get('timestamp'),
                'reason': sig_data.get('signing_details', {}).get('reason'),
            }
        return {'approved': False, 'error': 'Invalid signature'}
```

### Multi-Signer Workflow

For documents requiring multiple signatures:

```python
def multi_sign_document(doc_path: str, signers: list) -> list:
    """Collect multiple signatures on a document."""
    signatures = []

    for signer in signers:
        # Each signer creates their own signature file
        output = f"{doc_path}.{signer['id']}.docsig"

        sign_document(
            doc_path=doc_path,
            key_path=signer['key_path'],
            signer_info=signer,
            output=output,
        )

        signatures.append({
            'signer_id': signer['id'],
            'signature_file': output,
        })

    return signatures

def verify_all_signatures(doc_path: str, signers: list) -> dict:
    """Verify all required signatures are present and valid."""
    results = {}

    for signer in signers:
        sig_file = f"{doc_path}.{signer['id']}.docsig"
        is_valid = verify_document(doc_path, signer['verify_key'], sig_file)
        results[signer['id']] = is_valid

    return {
        'all_valid': all(results.values()),
        'signatures': results,
    }
```

## Security Considerations

### Signer Authentication

1. **Key Protection**: Keep signing keys secure (HSM, encrypted storage)
2. **Identity Verification**: Verify signer identity before issuing keys
3. **Key Revocation**: Maintain revocation lists for compromised keys

### Document Integrity

1. **Hash Verification**: Both SHA-256 and SHA-512 are verified
2. **No Modification**: Any change to the document invalidates the signature
3. **Timestamp Validity**: Check signature timestamp for freshness

### Audit Trail

```python
def log_signing_event(doc_path: str, sig_data: dict):
    """Log document signing for audit purposes."""
    audit_entry = {
        'event': 'document_signed',
        'document': doc_path,
        'document_hash': sig_data['document']['hashes']['sha256'],
        'signer': sig_data.get('signer', {}),
        'timestamp': sig_data['timestamp'],
        'reason': sig_data.get('signing_details', {}).get('reason'),
        'algorithm': sig_data['algorithm']['id'],
    }
    # Write to secure audit log
    audit_log.append(audit_entry)
```

## Testing

Run the test suite:

```bash
make test-examples-document-signing
```

## Related Examples

- [Code Signing](../code-signing/) - Sign software releases
- [Firmware Signing](../firmware-signing/) - Sign firmware with rollback protection
- [API Request Signing](../api-signing/) - Authenticate API requests
