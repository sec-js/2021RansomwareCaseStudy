# 2021RansomwareCaseStudy

## Related resources

- [SynthAPT](https://github.com/sec-js/SynthAPT): a synthetic APT/ransomware simulation project that can complement this case study with reproducible attack data and scenarios.

## Clarification

- **Does SynthAPT provide an encryption key?** No. It is intended for simulation/research workflows and does not provide real ransomware encryption keys or decryption keys.

## File encryption utility

This repository includes `file_encryption.py`, a defensive file encryption/decryption CLI that uses **GnuPG symmetric encryption with AES-256**.

### Requirements

- `gpg` (GnuPG 2.x) installed and available in `PATH`.

### Encrypt a file

```bash
python3 file_encryption.py encrypt <input_file> <output_file.gpg> --password "your-password"
```

### Decrypt a file

```bash
python3 file_encryption.py decrypt <output_file.gpg> <decrypted_file> --password "your-password"
```
