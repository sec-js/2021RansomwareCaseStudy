#!/usr/bin/env python3
"""Simple password-based file encryption/decryption utility.

This uses only Python standard-library primitives:
- PBKDF2-HMAC-SHA256 key derivation
- HMAC-SHA256 based keystream for XOR encryption
- HMAC-SHA256 authentication tag

File format (all bytes):
MAGIC(8) | SALT(16) | NONCE(16) | CIPHERTEXT(n) | TAG(32)
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import secrets
from pathlib import Path

MAGIC = b"FENCv1\x00\x00"
SALT_LEN = 16
NONCE_LEN = 16
TAG_LEN = 32
PBKDF2_ROUNDS = 200_000


class EncryptionError(Exception):
    pass


def _derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    master = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS, dklen=64)
    return master[:32], master[32:]


def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    blocks = []
    counter = 0
    while len(b"".join(blocks)) < length:
        block = hmac.new(enc_key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        blocks.append(block)
        counter += 1
    return b"".join(blocks)[:length]


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_bytes(data: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    enc_key, mac_key = _derive_keys(password, salt)

    stream = _keystream(enc_key, nonce, len(data))
    ciphertext = _xor_bytes(data, stream)

    header = MAGIC + salt + nonce
    tag = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()
    return header + ciphertext + tag


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    min_len = len(MAGIC) + SALT_LEN + NONCE_LEN + TAG_LEN
    if len(blob) < min_len:
        raise EncryptionError("Input is too short to be a valid encrypted file")

    if blob[: len(MAGIC)] != MAGIC:
        raise EncryptionError("Invalid file header/magic")

    salt_start = len(MAGIC)
    nonce_start = salt_start + SALT_LEN
    body_start = nonce_start + NONCE_LEN

    salt = blob[salt_start:nonce_start]
    nonce = blob[nonce_start:body_start]
    ciphertext = blob[body_start:-TAG_LEN]
    tag = blob[-TAG_LEN:]

    enc_key, mac_key = _derive_keys(password, salt)

    expected = hmac.new(mac_key, blob[:body_start] + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise EncryptionError("Authentication failed (wrong password or modified file)")

    stream = _keystream(enc_key, nonce, len(ciphertext))
    return _xor_bytes(ciphertext, stream)


def encrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    data = input_path.read_bytes()
    output_path.write_bytes(encrypt_bytes(data, password))


def decrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    blob = input_path.read_bytes()
    output_path.write_bytes(decrypt_bytes(blob, password))


def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypt/decrypt files with a password")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Operation to perform")
    parser.add_argument("input", type=Path, help="Input file path")
    parser.add_argument("output", type=Path, help="Output file path")
    parser.add_argument("--password", required=True, help="Password used for encryption/decryption")
    args = parser.parse_args()

    try:
        if args.mode == "encrypt":
            encrypt_file(args.input, args.output, args.password)
        else:
            decrypt_file(args.input, args.output, args.password)
    except EncryptionError as exc:
        raise SystemExit(f"Error: {exc}")


if __name__ == "__main__":
    main()
