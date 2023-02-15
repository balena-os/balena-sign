import binascii
import logging
import os
import subprocess
import tempfile

from utils import X509_DIR, get_certlist_name
from utils import get_der_path, get_esl_path, unlink_if_exists


LOG = logging.getLogger("secureboot")


ALLOWED_VARS = {"PK", "KEK", "db", "dbx"}


def _get_signed_esl(cert_ids, var):
    if isinstance(cert_ids, str):
        cert_ids = [cert_ids]

    if not isinstance(cert_ids, list):
        raise ValueError(
            "`cert_id` must either be a single ID or a list of IDs"
        )

    if var not in ALLOWED_VARS:
        raise ValueError("`var` must be one of %s" % ALLOWED_VARS)

    certlist_name = get_certlist_name(cert_ids)
    auth_filename = "%s.%s.auth" % (certlist_name, var)
    auth_path = os.path.join(X509_DIR, auth_filename)
    if not os.path.isfile(auth_path):
        return {
            "error": "%s not found for given certificate list" % var
        }, 404

    with open(auth_path, "rb") as f:
        auth_data = f.read()

    response = {
        var.lower(): binascii.b2a_base64(auth_data).decode().rstrip("\n")
    }

    # This does not call get_esl_path as that has potential side-effects
    esl_path = os.path.join(X509_DIR, "%s.esl" % certlist_name)
    if os.path.isfile(esl_path):
        with open(esl_path, "rb") as f:
            esl_data = f.read()

        response["esl"] = binascii.b2a_base64(esl_data).decode().rstrip("\n")

    response["der"] = []
    for cert_id in sorted(set(cert_ids)):
        cert_path = os.path.join(X509_DIR, "%s.crt" % cert_id)
        der_path = get_der_path(cert_path)
        if os.path.isfile(der_path):
            with open(der_path, "rb") as f:
                der_data = f.read()

            response["der"].append(
                binascii.b2a_base64(der_data).decode().rstrip("\n")
            )

    return response


def _sign_esl(signing_cert_id, var, cert_ids=None, esl_data=None, append=False):
    if var not in ALLOWED_VARS:
        raise ValueError("`var` must be one of %s" % ALLOWED_VARS)

    signing_cert_filename = "%s.crt" % signing_cert_id
    signing_cert_path = os.path.join(X509_DIR, signing_cert_filename)
    if not os.path.isfile(signing_cert_path):
        return {
            "error": "Certificate '%s' does not exist" % signing_cert_id
        }, 404

    signing_key_filename = "%s.key" % signing_cert_id
    signing_key_path = os.path.join(X509_DIR, signing_key_filename)
    if not os.path.isfile(signing_key_path):
        return {
            "error": "Private key '%s' does not exist" % signing_cert_id
        }, 404

    if cert_ids is not None:
        # This only operates on lists even if the list length is 1
        if isinstance(cert_ids, str):
            cert_ids = [cert_ids]

        if not isinstance(cert_ids, list):
            raise ValueError(
                "`cert_id` must either be a single ID or a list of IDs"
            )

        # Check whether the individual certificates exist
        cert_errors = []
        cert_paths = []
        for cert_id in cert_ids:
            cert_filename = "%s.crt" % cert_id
            cert_path = os.path.join(X509_DIR, cert_filename)

            if not os.path.isfile(cert_path):
                cert_errors.append("Certificate '%s' does not exist" % cert_id)
                continue

            cert_paths.append(cert_path)

        # Bail out on error - a single missing cert means the list is invalid
        if cert_errors:
            return {"error": "; ".join(cert_errors)}, 404

        esl_path = get_esl_path(cert_paths)
        auth_path = "%s.%s.auth" % (esl_path[:-4], var)
        if os.path.isfile(auth_path):
            return {
                "error": "%s for '%s' has already been signed" % (var, cert_id)
            }, 409

    elif esl_data is not None:
        with tempfile.NamedTemporaryFile(delete=False) as esl_file:
            esl_path = esl_file.name
            esl_file.write(esl_data)

        auth_path = "%s.auth" % esl_path

    else:
        return {"error": "Either 'cert_id' or 'esl' must be defined"}, 400

    cmd = ["sign-efi-sig-list"]
    if append:
        cmd.append("-a")
    cmd.extend([
        "-k", signing_key_path, "-c", signing_cert_path,
        var, esl_path, auth_path
    ])
    cmd_result = subprocess.run(cmd)
    if cmd_result.returncode != 0:
        return {"error": "Failed to sign EFI signature list"}, 500

    response = {}
    if esl_data is not None:
        with open(auth_path, "rb") as auth_file:
            auth_data = auth_file.read(1 << 28)

        os.unlink(auth_path)
        os.unlink(esl_path)

        response = {
            "auth": binascii.b2a_base64(auth_data).decode().rstrip("\n")
        }

    return response


def get_pk(cert_id):
    return _get_signed_esl(cert_id, "PK")


def get_kek(cert_id):
    return _get_signed_esl(cert_id, "KEK")


def get_db(cert_id):
    return _get_signed_esl(cert_id, "db")


def sign_pk(body, user):
    cert_id = body["key_id"]
    signing_cert_id = body.get("signing_key_id", cert_id)

    return _sign_esl(signing_cert_id, "PK", cert_id=cert_id)


def sign_kek(body, user):
    cert_id = body["key_id"]
    signing_cert_id = body.get("signing_key_id", cert_id)

    return _sign_esl(signing_cert_id, "KEK", cert_id=cert_id)


def _sign_db(body, user, dbx=False):
    var = "dbx" if dbx else "db"

    append = body.get("append", False)

    # Internal ESL
    if "key_id" in body:
        cert_id = body["key_id"]
        signing_cert_id = body.get("signing_key_id", cert_id)

        return _sign_esl(signing_cert_id, var, cert_id=cert_id, append=append)

    # External ESL
    signing_cert_id = body["signing_key_id"]
    try:
        esl_data = binascii.a2b_base64(body["esl"])
    except Exception as ex:
        return {"error": "Failed to base64-decode esl: %s" % ex}, 400

    return _sign_esl(signing_cert_id, var, esl_data=esl_data, append=append)


def sign_db(body, user):
    return _sign_db(body, user, dbx=False)


def sign_dbx(body, user):
    return _sign_db(body, user, dbx=True)


def sign_efi(body, user):
    key_id = body["key_id"]
    key_file = os.path.join(X509_DIR, "%s.key" % key_id)
    if not os.path.isfile(key_file):
        return {"error": "Private key '%s' does not exist" % key_id}, 404

    cert_file = os.path.join(X509_DIR, "%s.crt" % key_id)
    if not os.path.isfile(cert_file):
        return {"error": "Certificate '%s' does not exist" % key_id}, 404

    try:
        payload = binascii.a2b_base64(body["payload"])
    except Exception as ex:
        return {"error": "Failed to base64-decode payload: %s" % ex}, 400

    with tempfile.NamedTemporaryFile(delete=False) as payload_file:
        payload_filename = payload_file.name
        payload_file.write(payload)

    signed_filename = "%s.signed" % payload_filename

    cmd = [
        "sbsign", "--key", key_file, "--cert", cert_file,
        "--output", signed_filename, payload_filename
    ]
    cmd_result = subprocess.run(cmd)

    if cmd_result.returncode != 0:
        unlink_if_exists(signed_filename)
        return {"error": "Signature failed"}, 500

    with open(signed_filename, "rb") as signed_file:
        signed_payload = signed_file.read(1 << 26)
        response = {
            "signed": binascii.b2a_base64(signed_payload).decode().rstrip("\n")
        }

    os.unlink(signed_filename)

    LOG.info(
        "%s successfully signed a payload using '%s' certificate", user, key_id
    )

    return response
