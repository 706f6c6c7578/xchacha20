#!/usr/bin/env python3
# Requiremnets: pip install pycryptodome

import sys
import os
from Crypto.Cipher import ChaCha20

def read_hex_file(filename):
    with open(filename, 'r') as f:
        hex_string = f.read().strip()
    return bytes.fromhex(hex_string)

def print_usage():
    print(f"""Usage: {sys.argv[0]} <keyfile> <noncefile> < infile > outfile

XChaCha20 encryption/decryption tool

Arguments:
  keyfile    Path to the file containing the key in hexadecimal format
  noncefile  Path to the file containing the nonce in hexadecimal format

The program reads from stdin and writes to stdout. Use input/output redirection for files.

Examples:
  Encryption: {sys.argv[0]} key.hex nonce.hex < plaintext.txt > encrypted.bin
  Decryption: {sys.argv[0]} key.hex nonce.hex < encrypted.bin > decrypted.txt

Note: The key should be 32 hex bytes (64 characters) long.
      The nonce should be 24 hex bytes (48 characters) long.
""", file=sys.stderr)

def main():
    if len(sys.argv) != 3:
        print("Error: Incorrect number of arguments", file=sys.stderr)
        print_usage()
        sys.exit(1)

    key_file = sys.argv[1]
    nonce_file = sys.argv[2]

    try:
        key = read_hex_file(key_file)
    except Exception as e:
        print(f"Error reading key file: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        nonce = read_hex_file(nonce_file)
    except Exception as e:
        print(f"Error reading nonce file: {e}", file=sys.stderr)
        sys.exit(1)

    if len(key) != 32:
        print(f"Error: Invalid key size. Expected 32 hex bytes, got {len(key)} bytes", file=sys.stderr)
        sys.exit(1)

    if len(nonce) != 24:
        print(f"Error: Invalid nonce size. Expected 24 hex bytes, got {len(nonce)} bytes", file=sys.stderr)
        sys.exit(1)

    cipher = ChaCha20.new(key=key, nonce=nonce)

    while True:
        chunk = sys.stdin.buffer.read(8192)
        if not chunk:
            break
        sys.stdout.buffer.write(cipher.encrypt(chunk))

if __name__ == "__main__":
    main()
