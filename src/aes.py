from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

ITERATIONS = 100000
KEY_LENGTH = 32
SALT_LENGTH = 16


def encrypt_file(fd, passphrase):
    # Derive a secure key from the passphrase
    salt = os.urandom(SALT_LENGTH)
    key = derive_key(passphrase.encode(), salt)

    # Read the plaintext from the file
    plaintext = fd.read()

    # Init fernet class
    f = Fernet(key)

    # Encrypt plaintext
    ciphertext = f.encrypt(plaintext)

    # Return the salt and ciphertext 
    return salt + ciphertext


def decrypt_file(fd, passphrase):
    # Read the salt and ciphertext from the encrypted file
    salt = fd.read(SALT_LENGTH)
    ciphertext = fd.read()

    # Use the passphrase and salt to derive a key
    key = derive_key(passphrase.encode(), salt)

    # Init fernet class
    f = Fernet(key)

    # Decrypt ciphertext
    plaintext = f.decrypt(ciphertext)

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
    return base64.urlsafe_b64encode(kdf.derive(passphrase))
