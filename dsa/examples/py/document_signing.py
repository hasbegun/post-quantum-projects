#!/usr/bin/env python3
"""
Post-Quantum Document Signing Service

Demonstrates SLH-DSA for long-term document signing.
SLH-DSA provides conservative hash-based security for critical documents.
"""

import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional

from dsa import slh_keygen, slh_sign, slh_verify, SLH_DSA_SHAKE_128f, SLH_DSA_SHAKE_256s


@dataclass
class SignedDocument:
    """A digitally signed document."""
    document_hash: str
    filename: str
    signer_id: str
    timestamp: str
    signature: str
    algorithm: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


class DocumentSigner:
    """Post-Quantum Document Signing Service using SLH-DSA."""

    def __init__(self, signer_id: str, security_level: str = "standard"):
        self.signer_id = signer_id
        self.params = SLH_DSA_SHAKE_256s if security_level == "high" else SLH_DSA_SHAKE_128f
        self.algorithm = self.params.name
        self._sk, self._pk = slh_keygen(self.params)

    @property
    def public_key(self) -> bytes:
        return self._pk

    def sign_document(self, document: bytes, filename: str = "document") -> SignedDocument:
        doc_hash = hashlib.sha256(document).hexdigest()
        timestamp = datetime.now(timezone.utc).isoformat()
        context = f"{self.signer_id}:{timestamp}:{filename}".encode()[:255]
        signature = slh_sign(self.params, document, self._sk, ctx=context)
        return SignedDocument(doc_hash, filename, self.signer_id, timestamp, signature.hex(), self.algorithm)

    @staticmethod
    def verify_document(document: bytes, signed_doc: SignedDocument, public_key: bytes) -> bool:
        from dsa.slhdsa.parameters import PARAMETER_SETS
        params = PARAMETER_SETS.get(signed_doc.algorithm)
        if not params:
            return False
        context = f"{signed_doc.signer_id}:{signed_doc.timestamp}:{signed_doc.filename}".encode()[:255]
        signature = bytes.fromhex(signed_doc.signature)
        return slh_verify(params, document, signature, public_key, ctx=context)


def main():
    print("=" * 60)
    print("Post-Quantum Document Signing (SLH-DSA)")
    print("=" * 60)

    contract = b"""
    EMPLOYMENT CONTRACT

    This agreement between Quantum Corp and Alice Smith.
    Position: Senior Cryptographer
    Start: January 1, 2025

    This document is protected by post-quantum signatures
    to ensure validity for 20+ years.
    """

    print("\n[1] Creating document signer...")
    signer = DocumentSigner("legal@quantumcorp.com")
    print(f"    Algorithm: {signer.algorithm}")
    print(f"    Public key: {len(signer.public_key)} bytes")

    print("\n[2] Signing document...")
    signed_doc = signer.sign_document(contract, "employment_contract.txt")
    print(f"    Hash: {signed_doc.document_hash[:32]}...")
    print(f"    Signature: {len(signed_doc.signature)//2} bytes")

    print("\n[3] Verifying signature...")
    valid = DocumentSigner.verify_document(contract, signed_doc, signer.public_key)
    print(f"    Valid: {valid}")

    print("\n[4] Tamper detection...")
    tampered = contract.replace(b"Alice Smith", b"Eve Hacker")
    tamper_valid = DocumentSigner.verify_document(tampered, signed_doc, signer.public_key)
    print(f"    Tampered document rejected: {not tamper_valid}")

    print("\n" + "=" * 60)
    print("SLH-DSA: Hash-based security for long-term documents")
    print("=" * 60)


if __name__ == "__main__":
    main()
