import errno
import logging
import os
import subprocess
import uuid


__all__ = [
    "APP_DIR", "GPG_HOME_DIR", "MODULE_DIR", "SECRETS_DIR",
    "X509_DIR", "unlink_if_exists"
]


MODULE_DIR = os.path.dirname(__file__)
APP_DIR = os.path.dirname(MODULE_DIR)
SECRETS_DIR = os.path.join(APP_DIR, "secrets")
GPG_HOME_DIR = os.path.join(SECRETS_DIR, "gpg")
X509_DIR = os.path.join(SECRETS_DIR, "x509")

DEFAULT_EFI_UUID = uuid.UUID("6f0ec8b8-5cfb-406f-b153-e21fc6bbc18c")


def unlink_if_exists(path):
    try:
        os.unlink(path)
    except OSError as ex:
        if not ex.errno != errno.EEXIST:
            raise


def get_esl_path(cert_path, uuid=DEFAULT_EFI_UUID):
    if not cert_path.endswith(".crt"):
        raise ValueError("`cert_path` must end with .crt")

    esl_path = "%s.%s.esl" % (cert_path[:-4], uuid.hex)

    if not os.path.isfile(esl_path):
        cmd = ["cert-to-efi-sig-list", "-g", str(uuid), cert_path, esl_path]
        cmd_result = subprocess.run(cmd)

        if cmd_result.returncode != 0:
            raise RuntimeError("Failed to generate EFI signature list")

    return esl_path


def init_logging(level=logging.INFO):
    logging.basicConfig(level=level)
