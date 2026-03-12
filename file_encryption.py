#!/usr/bin/env python3
"""Defensive file encryption/decryption utility using GnuPG.

This tool wraps GnuPG symmetric encryption with strong defaults:
- AES-256 cipher
- Iterated+salted S2K with SHA-256
- Integrity protection enabled

Requires: gpg (GnuPG 2.x)
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path


class EncryptionError(Exception):
    """Raised when encryption/decryption fails."""


def _require_gpg() -> None:
    if shutil.which("gpg") is None:
        raise EncryptionError("gpg is not installed or not available in PATH")


def _run_gpg(args: list[str]) -> None:
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        details = proc.stderr.strip() or proc.stdout.strip() or "unknown gpg error"
        raise EncryptionError(details)


def encrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    _require_gpg()
    cmd = [
        "gpg",
        "--batch",
        "--yes",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        password,
        "--symmetric",
        "--cipher-algo",
        "AES256",
        "--s2k-digest-algo",
        "SHA256",
        "--compress-algo",
        "none",
        "--output",
        str(output_path),
        str(input_path),
    ]
    _run_gpg(cmd)


def decrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    _require_gpg()
    cmd = [
        "gpg",
        "--batch",
        "--yes",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        password,
        "--decrypt",
        "--output",
        str(output_path),
        str(input_path),
    ]
    _run_gpg(cmd)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Encrypt/decrypt files with password-based AES-256 using GnuPG"
    )
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
