#!/usr/bin/env python3
import base64
import os
import sys
import getpass
from cryptography.hazmat.primitives import hashes # pip install cryptography

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


# Remember to use a strong encryption password, default password is 20eka. Name is your odi name short 1 time.

# --- Helper functions ---

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(filename: str):
    if not os.path.exists(filename):
        print(f"File not found: {filename}")
        return

    password = getpass.getpass("Enter password to encrypt: ")
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(filename, "rb") as f:
        data = f.read()

    encrypted = fernet.encrypt(data)

    with open(filename + ".enc", "wb") as f:
        f.write(salt + encrypted)

    print(f"✅ Encrypted -> {filename}.enc")

def decrypt_file(filename: str):
    if not os.path.exists(filename):
        print(f"File not found: {filename}")
        return

    password = getpass.getpass("Enter password to decrypt: ")

    with open(filename, "rb") as f:
        salt = f.read(16)
        encrypted = f.read()

    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(encrypted)
    except Exception:
        print("❌ Wrong password or corrupt file.")
        return

    out_file = filename.replace(".enc", ".dec")
    with open(out_file, "wb") as f:
        f.write(decrypted)

    print(f"✅ Decrypted -> {out_file}")

# --- Main CLI ---

def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("encrypt", "decrypt"):
        print("Usage:")
        print("  otp_encryptor.py encrypt <filename>")
        print("  otp_encryptor.py decrypt <filename>")
        sys.exit(1)

    action, filename = sys.argv[1], sys.argv[2]
    if action == "encrypt":
        encrypt_file(filename)
    else:
        decrypt_file(filename)

if __name__ == "__main__":
    main()
