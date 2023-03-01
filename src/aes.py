import binascii
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 100000
KEY_LENGTH = 32
SALT_LENGTH = 16


def encrypt(data, passphrase):
    # Derive a secure key from the passphrase
    salt = os.urandom(SALT_LENGTH)
    key = derive_key(passphrase.encode(), salt)

    # Init fernet class
    f = Fernet(key)

    # Encrypt plaintext
    ciphertext = f.encrypt(data)

    # Return the salt and ciphertext
    return {
        "data": ciphertext.decode(),
        "salt": binascii.b2a_base64(salt).decode().rstrip("\n")
    }


def decrypt(data, salt, passphrase):
    # Use the passphrase and salt to derive a key
    key = derive_key(passphrase.encode(), binascii.a2b_base64(salt.encode()))

    # Init fernet class
    f = Fernet(key)

    # Decrypt ciphertext
    plaintext = f.decrypt(data)

    # Return the plaintext of the decrypted file
    return plaintext


def derive_key(passphrase, salt):
    # Use the passphrase and salt to derive a key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=ITERATIONS,
        salt=salt,
        length=KEY_LENGTH,
    )
    # Return key and salt used (salt is needed to reconstruct key)
    return binascii.b2a_base64(kdf.derive(passphrase))
