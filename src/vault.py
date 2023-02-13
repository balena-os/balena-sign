import connexion
import os
import tarfile
import logging
import tempfile

from cryptography.fernet import InvalidToken
from connexion import ProblemException
from flask import make_response

from aes import decrypt_file, encrypt_file
from utils import VAULT_DIR

LOG = logging.getLogger("vault")


def import_secrets(body, user):
    symmetric_key = body["symmetricKey"]
    encrypted_file = connexion.request.files.get("encryptedSecrets")  # type: ignore

    if not encrypted_file:
        raise ProblemException(
            title="Missing required parameter",
            detail="'encryptedSecrets' is expected to be a file",
            status=400,
        )

    # Save encrypted file
    enc_file = tempfile.NamedTemporaryFile(delete=False)
    encrypted_file.save(enc_file.name)

    try:
        # Decrypt file
        tar_bytes = decrypt_file(
            enc_file, symmetric_key
        )
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
    finally:
        # The removes can fail as well, let that not crash the app
        try:
            os.remove(enc_file.name)
        except Exception as _:
            LOG.warning("Failed to remove file '%s'", enc_file.name)

    LOG.info("%s imported new signing material", user)

    # Material successfully imported
    return


def export_secrets(body, user):
    symmetric_key = body["symmetricKey"]

    tmp_tar = tempfile.NamedTemporaryFile(delete=False)

    try:
        # Create a compressed tar of the VAULT_DIR
        with tarfile.open(tmp_tar.name, "w:gz") as tar:
            for item in os.listdir(VAULT_DIR):
                item_path = os.path.join(VAULT_DIR, item)
                tar.add(item_path, arcname=os.path.basename(item_path))
            tar.close()
        # Encrypt tar file containing signing material
        encrypted_file_data = encrypt_file(tmp_tar, symmetric_key)
    finally:
        # The removes can fail as well, let that not crash the app
        try:
            os.remove(tmp_tar.name)
        except Exception as _:
            LOG.warning("Failed to remove file '%s'", tmp_tar.name)

    # Create a binary response with the encrypted file data
    response = make_response(encrypted_file_data)
    response.headers["Content-Type"] = "application/octet-stream"
    response.headers[
        "Content-Disposition"
    ] = f"attachment; filename={tmp_tar.name + '.crypt'}"

    LOG.info("%s exported signing material", user)

    # Material successfully exported
    return response
