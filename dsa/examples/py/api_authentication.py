#!/usr/bin/env python3
"""
Post-Quantum API Authentication System

Demonstrates ML-DSA for high-volume API request signing.
ML-DSA is ideal for APIs due to fast signing and smaller signatures.
"""

import hashlib
import json
import time
import os
from dataclasses import dataclass
from typing import Optional, Dict
from datetime import datetime, timezone

from dsa import MLDSA44


@dataclass
class SignedAPIRequest:
    """A digitally signed API request."""
    method: str
    endpoint: str
    body_hash: str
    timestamp: str
    nonce: str
    client_id: str
    signature: str

    def to_headers(self) -> Dict[str, str]:
        return {
            "X-Signature": self.signature,
            "X-Timestamp": self.timestamp,
            "X-Nonce": self.nonce,
            "X-Client-ID": self.client_id,
        }


class APIClient:
    """API Client with Post-Quantum Request Signing."""

    def __init__(self, client_id: str):
        self.client_id = client_id
        self.dsa = MLDSA44()
        self.pk, self.sk = self.dsa.keygen()

    @property
    def public_key(self) -> bytes:
        return self.pk

    def sign_request(self, method: str, endpoint: str, body: Optional[bytes] = None) -> SignedAPIRequest:
        timestamp = datetime.now(timezone.utc).isoformat()
        nonce = os.urandom(16).hex()
        body_hash = hashlib.sha256(body or b"").hexdigest()
        canonical = f"{method}\n{endpoint}\n{body_hash}\n{timestamp}\n{nonce}"
        signature = self.dsa.sign(self.sk, canonical.encode())
        return SignedAPIRequest(method, endpoint, body_hash, timestamp, nonce, self.client_id, signature.hex())


class APIServer:
    """API Server with Post-Quantum Signature Verification."""

    def __init__(self):
        self.dsa = MLDSA44()
        self.registered_clients: Dict[str, bytes] = {}
        self.used_nonces: set = set()

    def register_client(self, client_id: str, public_key: bytes):
        self.registered_clients[client_id] = public_key

    def verify_request(self, signed_req: SignedAPIRequest, body: Optional[bytes] = None) -> tuple[bool, str]:
        if signed_req.client_id not in self.registered_clients:
            return False, "Unknown client"
        if signed_req.nonce in self.used_nonces:
            return False, "Replay attack detected"
        body_hash = hashlib.sha256(body or b"").hexdigest()
        if body_hash != signed_req.body_hash:
            return False, "Body tampering detected"
        canonical = f"{signed_req.method}\n{signed_req.endpoint}\n{signed_req.body_hash}\n{signed_req.timestamp}\n{signed_req.nonce}"
        pk = self.registered_clients[signed_req.client_id]
        signature = bytes.fromhex(signed_req.signature)
        is_valid = self.dsa.verify(pk, canonical.encode(), signature)
        if is_valid:
            self.used_nonces.add(signed_req.nonce)
            return True, "OK"
        return False, "Invalid signature"


def main():
    print("=" * 60)
    print("Post-Quantum API Authentication (ML-DSA)")
    print("=" * 60)

    client = APIClient("client-001")
    server = APIServer()
    server.register_client(client.client_id, client.public_key)

    print(f"\nClient: {client.client_id}")
    print(f"Algorithm: ML-DSA-44")
    print(f"Signature size: ~2,420 bytes")

    print("\n[1] Signing API requests...")
    req1 = client.sign_request("GET", "/api/users/123")
    valid1, msg1 = server.verify_request(req1)
    print(f"    GET /api/users/123 -> {msg1}")

    req2 = client.sign_request("POST", "/api/orders", b'{"item": "widget"}')
    valid2, msg2 = server.verify_request(req2, b'{"item": "widget"}')
    print(f"    POST /api/orders -> {msg2}")

    print("\n[2] Attack prevention...")
    # Replay attack
    _, replay_msg = server.verify_request(req1)
    print(f"    Replay attack: {replay_msg}")

    # Tampering
    _, tamper_msg = server.verify_request(req2, b'{"item": "HACKED"}')
    print(f"    Tampering: {tamper_msg}")

    print("\n[3] Performance benchmark (100 requests)...")
    start = time.time()
    for i in range(100):
        req = client.sign_request("GET", f"/api/test/{i}")
        server.verify_request(req)
    print(f"    {100/(time.time()-start):.0f} requests/sec")

    print("\n" + "=" * 60)
    print("ML-DSA: Fast, quantum-resistant API authentication")
    print("=" * 60)


if __name__ == "__main__":
    main()
