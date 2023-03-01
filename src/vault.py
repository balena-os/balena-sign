import connexion
import os
import tarfile
import logging
import tempfile

from cryptography.fernet import InvalidToken
from connexion import ProblemException
from flask import make_response

from aes import decrypt, encrypt
from utils import VAULT_DIR

LOG = logging.getLogger("vault")


def import_secrets(body, user):
    try:
        tar_bytes = decrypt(body["data"], body["salt"], body["key"])
        # Write tar bytes to a tmp file
        with tempfile.NamedTemporaryFile(delete=True) as tmp_tar:
            tmp_tar.write(tar_bytes)
            # Untar decrypted files to VAULT_DIR
            with tarfile.open(tmp_tar.name, "r:gz") as tar:
                tar.extractall(path=VAULT_DIR)
                tar.close()
    except InvalidToken:
        raise ProblemException(
            title="Invalid Decryption Token",
            detail="Passphrase failed to decrypt provided secrets file",
            status=401,
        )
    except tarfile.ReadError as ex:
        if str(ex) == "empty file":
            raise ProblemException(
                title="Invalid Import",
                detail="Encrypted file provided is empty",
                status=401,
            )
        else:
            raise ex

    LOG.info("%s imported new signing material", user)


def export_secrets(body, user):
    tmp_tar = tempfile.NamedTemporaryFile(delete=False)

    try:
        # Create a compressed tar of the VAULT_DIR
        with tarfile.open(tmp_tar.name, "w:gz") as tar:
            for item in os.listdir(VAULT_DIR):
                item_path = os.path.join(VAULT_DIR, item)
                tar.add(item_path, arcname=os.path.basename(item_path))
            tar.close()
        # Encrypt tar file containing signing material
        with open(tmp_tar.name, "rb") as f:
            # Cap to 256MB for sanity
            encrypted_file_data = encrypt(f.read(1 << 28), body["key"])
    finally:
        # The removes can fail as well, let that not crash the app
        try:
            os.remove(tmp_tar.name)
        except Exception as _:
            LOG.warning("Failed to remove file '%s'", tmp_tar.name)

    LOG.info("%s exported signing material", user)

    # Material successfully exported
    return encrypted_file_data
