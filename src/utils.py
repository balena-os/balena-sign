import errno
import logging
import os
import subprocess
import uuid


__all__ = [
    "APP_DIR",
    "GPG_HOME_DIR",
    "MODULE_DIR",
    "VAULT_DIR",
    "X509_DIR",
    "unlink_if_exists",
]


MODULE_DIR = os.path.dirname(__file__)
APP_DIR = os.path.dirname(MODULE_DIR)
VAULT_DIR = os.path.join(APP_DIR, "secrets")
GPG_HOME_DIR = os.path.join(VAULT_DIR, "gpg")
X509_DIR = os.path.join(VAULT_DIR, "x509")


def unlink_if_exists(path):
    try:
        os.unlink(path)
    except OSError as ex:
        if not ex.errno != errno.EEXIST:
            raise


def get_esl_path(cert_path, efi_uuid=None):
    if not cert_path.endswith(".crt"):
        raise ValueError("`cert_path` must end with .crt")

    if efi_uuid is None:
        efi_uuid = uuid.uuid4()

    esl_path = "%s.esl" % (cert_path[:-4])

    if not os.path.isfile(esl_path):
        cmd = ["cert-to-efi-sig-list", "-g", str(efi_uuid), cert_path, esl_path]
        cmd_result = subprocess.run(cmd)

        if cmd_result.returncode != 0:
            raise RuntimeError("Failed to generate EFI signature list")

    return esl_path


def get_der_path(cert_path):
    if not cert_path.endswith(".crt"):
        raise ValueError("`cert_path` must end with .crt")

    der_path = "%s.der" % (cert_path[:-4])

    if not os.path.isfile(der_path):
        cmd = ["openssl", "x509", "-in", cert_path, "-outform", "der", "-out", der_path]
        cmd_result = subprocess.run(cmd)

        if cmd_result.returncode != 0:
            raise RuntimeError("Failed to generate DER version of the certificate")

    return der_path
