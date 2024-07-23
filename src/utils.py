import errno
import hashlib
import logging
import os
import shutil
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
RSA_DIR = os.path.join(VAULT_DIR, "rsa")
PKI_DIR = os.path.join(VAULT_DIR, "pki")


def unlink_if_exists(path):
    try:
        os.unlink(path)
    except OSError as ex:
        if not ex.errno != errno.EEXIST:
            raise


def get_certlist_name(cert_ids):
    # In order to uniquely and reproducibly identify a certificate list, this
    # 1. Removes duplicit cert_ids.
    # 2. Sorts the cert_ids.
    # 3. Joins the list of cert_ids together using the NULL byte as the glue.
    #    Since the NULL byte can not be a part of a cert_id (or in general
    #    a file name), this ensures cert_ids won't be able to cause conflicts.
    # 4. Hashes the result for a constant output length, there are no crypto
    #    requirements on the hash.
    hasher = hashlib.sha3_256()
    hasher.update(b"\x00".join(cid.encode() for cid in sorted(set(cert_ids))))
    return hasher.hexdigest()


def get_esl_path(cert_paths, efi_uuid=None):
    # This only operates on lists, even if the list length is 1
    if isinstance(cert_paths, str):
        cert_paths = [cert_paths]

    if not isinstance(cert_paths, list):
        raise ValueError("`cert_paths` must be a list")

    # First turn the individual certs into esl
    cert_ids = set()
    cert_esl_paths = []
    esl_errors = []
    for cert_path in cert_paths:
        if not cert_path.endswith(".crt"):
            raise ValueError("`cert_path` must end with .crt")

        cert_id = os.path.basename(cert_path)[:-4]
        cert_ids.add(cert_id)

        if efi_uuid is None:
            efi_uuid = uuid.uuid4()

        cert_esl_path = "%s.esl" % (cert_path[:-4])

        if os.path.isfile(cert_esl_path):
            continue

        cmd = ["cert-to-efi-sig-list", "-g", str(efi_uuid), cert_path, cert_esl_path]
        cmd_result = subprocess.run(cmd)

        if cmd_result.returncode != 0:
            esl_errors.append(
                "Failed to generate EFI signature list for %s" % cert_id
            )
            continue

        cert_esl_paths.append(cert_esl_path)

    # Bail out if at least one esl failed to generate
    if esl_errors:
        raise RuntimeError("; ".join(esl_errors))

    certlist_name = get_certlist_name(cert_ids)
    esl_path = os.path.join(X509_DIR, "%s.esl" % certlist_name)

    # If the esl file exists, perform no additional checks
    if os.path.isfile(esl_path):
        return esl_path

    # Concatenate the individual esls into the single resulting esl
    with open(esl_path, "wb") as esl_file:
        for cert_esl_path in cert_esl_paths:
            with open(cert_esl_path, "rb") as cert_esl_file:
                shutil.copyfileobj(cert_esl_file, esl_file)

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
