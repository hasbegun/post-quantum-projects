#!/usr/bin/env python3
"""
Post-Quantum Signature Verification Server

This server holds a public key and verifies signatures from clients.
Demonstrates the verification side of post-quantum digital signatures.

Usage:
    python server.py --name <server_name> --port <port> --algorithm <alg>
"""

import argparse
import json
import os
import signal
import sys
import socket
import threading
from datetime import datetime

# Add the src directory to the path
sys.path.insert(0, '/app/src/py')

from mldsa import MLDSA44, MLDSA65, MLDSA87
from slhdsa import SLHDSA_SHAKE_128f, SLHDSA_SHAKE_128s


class VerificationServer:
    """Server that verifies signatures using a public key."""

    def __init__(self, name: str, port: int, algorithm: str):
        self.name = name
        self.port = port
        self.algorithm = algorithm
        self.public_key = None
        self.dsa = None
        self.running = False

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

    def load_public_key(self, key_path: str):
        """Load public key from file."""
        with open(key_path, 'rb') as f:
            self.public_key = f.read()
        print(f"[{self.name}] Loaded public key: {len(self.public_key)} bytes")

    def verify_signature(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature."""
        try:
            return self.dsa.verify(self.public_key, message, signature)
        except Exception as e:
            print(f"[{self.name}] Verification error: {e}")
            return False

    def handle_client(self, conn, addr):
        """Handle incoming client connection."""
        print(f"[{self.name}] Connection from {addr}")
        try:
            # Receive data
            data = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
                # Check for end marker
                if b"\n\n" in data:
                    break

            if not data:
                return

            # Parse request
            try:
                request = json.loads(data.decode().strip())
            except json.JSONDecodeError:
                conn.send(b'{"error": "Invalid JSON"}\n')
                return

            action = request.get("action")

            if action == "register_key":
                # Client is registering their public key
                key_hex = request.get("public_key")
                if key_hex:
                    self.public_key = bytes.fromhex(key_hex)
                    response = {
                        "status": "ok",
                        "message": f"Public key registered ({len(self.public_key)} bytes)"
                    }
                    print(f"[{self.name}] Registered public key from client")
                else:
                    response = {"status": "error", "message": "No public key provided"}

            elif action == "verify":
                # Verify a signature
                message = request.get("message", "").encode()
                signature = bytes.fromhex(request.get("signature", ""))

                if not self.public_key:
                    response = {"status": "error", "message": "No public key registered"}
                else:
                    valid = self.verify_signature(message, signature)
                    response = {
                        "status": "ok",
                        "valid": valid,
                        "server": self.name,
                        "algorithm": self.algorithm,
                        "message_preview": request.get("message", "")[:50]
                    }
                    status = "VALID" if valid else "INVALID"
                    print(f"[{self.name}] Signature verification: {status}")

            elif action == "ping":
                response = {
                    "status": "ok",
                    "server": self.name,
                    "algorithm": self.algorithm,
                    "has_public_key": self.public_key is not None
                }

            else:
                response = {"status": "error", "message": f"Unknown action: {action}"}

            conn.send((json.dumps(response) + "\n").encode())

        except Exception as e:
            print(f"[{self.name}] Error handling client: {e}")
        finally:
            conn.close()

    def start(self):
        """Start the server."""
        self.running = True
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', self.port))
        server_socket.listen(5)
        server_socket.settimeout(1.0)

        print(f"[{self.name}] Server started on port {self.port}")
        print(f"[{self.name}] Algorithm: {self.algorithm}")
        print(f"[{self.name}] Waiting for connections...")

        while self.running:
            try:
                conn, addr = server_socket.accept()
                thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                thread.daemon = True
                thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[{self.name}] Error: {e}")

        server_socket.close()


def main():
    parser = argparse.ArgumentParser(description='Post-Quantum Verification Server')
    parser.add_argument('--name', default='Server', help='Server name')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on')
    parser.add_argument('--algorithm', default='mldsa44', help='Algorithm (mldsa44, mldsa65, slh-shake-128f)')
    parser.add_argument('--public-key', help='Path to public key file')

    args = parser.parse_args()

    server = VerificationServer(args.name, args.port, args.algorithm)

    if args.public_key and os.path.exists(args.public_key):
        server.load_public_key(args.public_key)

    def shutdown_handler(signum, frame):
        """Handle shutdown signals gracefully."""
        print(f"\n[{args.name}] Received shutdown signal, stopping...")
        server.running = False

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    try:
        server.start()
    except KeyboardInterrupt:
        pass

    print(f"[{args.name}] Server stopped.")


if __name__ == "__main__":
    main()
