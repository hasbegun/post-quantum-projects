#!/usr/bin/env python3
"""
Post-Quantum Signature Client

This client holds a private key and signs messages.
It sends signatures to verification servers to demonstrate the workflow.

Usage:
    python client.py --algorithm <alg> --servers <server1:port1,server2:port2>
"""

import argparse
import json
import os
import sys
import socket
import time
from datetime import datetime

# Add the src directory to the path
sys.path.insert(0, '/app/src/py')

from mldsa import MLDSA44, MLDSA65, MLDSA87
from slhdsa import SLHDSA_SHAKE_128f, SLHDSA_SHAKE_128s


class SigningClient:
    """Client that signs messages using a private key."""

    def __init__(self, algorithm: str):
        self.algorithm = algorithm
        self.public_key = None
        self.secret_key = None
        self.dsa = None

        self._setup_algorithm()

    def _setup_algorithm(self):
        """Initialize the DSA algorithm."""
        algorithms = {
            "mldsa44": MLDSA44,
            "mldsa65": MLDSA65,
            "mldsa87": MLDSA87,
            "slh-shake-128f": SLHDSA_SHAKE_128f,
            "slh-shake-128s": SLHDSA_SHAKE_128s,
        }
        if self.algorithm in algorithms:
            self.dsa = algorithms[self.algorithm]()
        else:
            raise ValueError(f"Unknown algorithm: {self.algorithm}")

    def generate_keys(self):
        """Generate a new key pair."""
        print(f"[Client] Generating {self.algorithm.upper()} key pair...")
        start = time.time()

        self.public_key, self.secret_key = self.dsa.keygen()

        elapsed = time.time() - start
        print(f"[Client] Key generation completed in {elapsed*1000:.0f} ms")
        print(f"[Client] Public key:  {len(self.public_key)} bytes")
        print(f"[Client] Secret key:  {len(self.secret_key)} bytes")

    def load_keys(self, public_key_path: str, secret_key_path: str):
        """Load keys from files."""
        with open(public_key_path, 'rb') as f:
            self.public_key = f.read()
        with open(secret_key_path, 'rb') as f:
            self.secret_key = f.read()
        print(f"[Client] Loaded keys from files")

    def sign_message(self, message: bytes) -> bytes:
        """Sign a message."""
        return self.dsa.sign(self.secret_key, message)

    def send_to_server(self, host: str, port: int, request: dict) -> dict:
        """Send a request to a server."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((host, port))
            sock.send((json.dumps(request) + "\n\n").encode())

            response = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                response += chunk
                if b"\n" in response:
                    break

            sock.close()
            return json.loads(response.decode().strip())
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def register_with_server(self, host: str, port: int) -> bool:
        """Register public key with a server."""
        request = {
            "action": "register_key",
            "public_key": self.public_key.hex()
        }
        response = self.send_to_server(host, port, request)
        return response.get("status") == "ok"

    def verify_with_server(self, host: str, port: int, message: str, signature: bytes) -> dict:
        """Send a message and signature to a server for verification."""
        request = {
            "action": "verify",
            "message": message,
            "signature": signature.hex()
        }
        return self.send_to_server(host, port, request)


def wait_for_servers(servers: list, timeout: int = 30):
    """Wait for servers to be ready."""
    print("[Client] Waiting for servers to be ready...")
    start = time.time()

    for host, port in servers:
        while time.time() - start < timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((host, port))
                sock.send((json.dumps({"action": "ping"}) + "\n\n").encode())
                response = sock.recv(1024)
                sock.close()
                if response:
                    print(f"[Client] Server {host}:{port} is ready")
                    break
            except:
                time.sleep(1)
        else:
            print(f"[Client] Warning: Server {host}:{port} not responding")


def main():
    parser = argparse.ArgumentParser(description='Post-Quantum Signing Client')
    parser.add_argument('--algorithm', default='mldsa44',
                        help='Algorithm (mldsa44, mldsa65, slh-shake-128f)')
    parser.add_argument('--servers', default='server1:5001,server2:5002',
                        help='Comma-separated list of servers (host:port)')
    parser.add_argument('--messages', type=int, default=3,
                        help='Number of test messages to send')

    args = parser.parse_args()

    # Parse servers
    servers = []
    for server_str in args.servers.split(','):
        host, port = server_str.strip().split(':')
        servers.append((host, int(port)))

    print("=" * 60)
    print("  Post-Quantum Digital Signature Demo")
    print("=" * 60)
    print(f"\nAlgorithm: {args.algorithm.upper()}")
    print(f"Servers: {args.servers}")
    print()

    # Create client and generate keys
    client = SigningClient(args.algorithm)
    client.generate_keys()

    # Wait for servers
    wait_for_servers(servers)

    # Register public key with all servers
    print("\n" + "-" * 60)
    print("Step 1: Registering public key with servers")
    print("-" * 60)

    for host, port in servers:
        success = client.register_with_server(host, port)
        status = "OK" if success else "FAILED"
        print(f"  -> {host}:{port}: {status}")

    # Sign and verify messages
    print("\n" + "-" * 60)
    print("Step 2: Signing and verifying messages")
    print("-" * 60)

    test_messages = [
        "Hello, Post-Quantum World!",
        f"Transaction: Transfer $1000 to Alice at {datetime.now().isoformat()}",
        "This message is signed with quantum-resistant cryptography.",
    ]

    for i, message in enumerate(test_messages[:args.messages], 1):
        print(f"\n[Message {i}]")
        print(f"  Content: {message[:50]}{'...' if len(message) > 50 else ''}")

        # Sign the message
        start = time.time()
        signature = client.sign_message(message.encode())
        sign_time = (time.time() - start) * 1000
        print(f"  Signature: {len(signature)} bytes (signed in {sign_time:.1f} ms)")

        # Verify with each server
        for host, port in servers:
            start = time.time()
            result = client.verify_with_server(host, port, message, signature)
            verify_time = (time.time() - start) * 1000

            if result.get("status") == "ok":
                valid = result.get("valid", False)
                status = "VALID" if valid else "INVALID"
                server_name = result.get("server", f"{host}:{port}")
                print(f"  -> {server_name}: {status} ({verify_time:.1f} ms)")
            else:
                print(f"  -> {host}:{port}: ERROR - {result.get('message', 'Unknown error')}")

    # Test tampered message
    print("\n" + "-" * 60)
    print("Step 3: Testing tamper detection")
    print("-" * 60)

    original_message = "Send $100 to Bob"
    tampered_message = "Send $999 to Eve"

    print(f"\n  Original: {original_message}")
    print(f"  Tampered: {tampered_message}")

    # Sign original message
    signature = client.sign_message(original_message.encode())
    print(f"  Signature of original: {len(signature)} bytes")

    # Try to verify tampered message with original signature
    for host, port in servers:
        result = client.verify_with_server(host, port, tampered_message, signature)
        if result.get("status") == "ok":
            valid = result.get("valid", False)
            status = "REJECTED (Correct!)" if not valid else "ACCEPTED (Wrong!)"
            server_name = result.get("server", f"{host}:{port}")
            print(f"  -> {server_name}: Tampered message {status}")

    print("\n" + "=" * 60)
    print("  Demo completed successfully!")
    print("=" * 60)
    print("\nKey takeaways:")
    print("  - Client holds the SECRET key (for signing)")
    print("  - Servers hold the PUBLIC key (for verification)")
    print("  - Signatures are quantum-resistant")
    print("  - Tampered messages are detected")
    print()


if __name__ == "__main__":
    main()
