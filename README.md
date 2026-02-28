# 2021RansomwareCaseStudy

## Related resources

- [SynthAPT](https://github.com/sec-js/SynthAPT): a synthetic APT/ransomware simulation project that can complement this case study with reproducible attack data and scenarios.

## Clarification

- **Does SynthAPT provide an encryption key?** No. It is intended for simulation/research workflows and does not provide real ransomware encryption keys or decryption keys.

## File encryption utility

This repository now includes `file_encryption.py`, a simple password-based file encryption/decryption CLI.

### Encrypt a file

```bash
python3 file_encryption.py encrypt <input_file> <output_file> --password "your-password"
```

### Decrypt a file

```bash
python3 file_encryption.py decrypt <encrypted_file> <output_file> --password "your-password"
```
