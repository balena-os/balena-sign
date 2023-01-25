import binascii
import logging
import os
import subprocess
import tempfile

from utils import X509_DIR, get_esl_path, unlink_if_exists


LOG = logging.getLogger("secureboot")


ALLOWED_VARS = {"PK", "KEK", "db"}


def _get_signed_esl(cert_id, var):
    if var not in ALLOWED_VARS:
        raise ValueError("`var` must be one of %s" % ALLOWED_VARS)

    cert_filename = "%s.crt" % cert_id
    cert_path = os.path.join(X509_DIR, cert_filename)

    if not os.path.isfile(cert_path):
        return {"error": "Certificate '%s' does not exist" % cert_id}, 404

    auth_path = "%s.%s.auth" % (cert_path[:-4], var)
    if not os.path.isfile(auth_path):
        return {
            "error": "%s not found for certificate '%s'" % (var, cert_id)
        }, 404

    with open(auth_path, "rb") as f:
        auth_data = f.read()

    response = {
        var.lower(): binascii.b2a_base64(auth_data).decode().rstrip("\n")
    }

    esl_path = get_esl_path(cert_path)
    if os.path.isfile(esl_path):
        with open(esl_path, "rb") as f:
            esl_data = f.read()

        response["esl"] = binascii.b2a_base64(esl_data).decode().rstrip("\n")

    return response


def _sign_esl(cert_id, signing_cert_id, var):
    if var not in ALLOWED_VARS:
        raise ValueError("`var` must be one of %s" % ALLOWED_VARS)

    cert_filename = "%s.crt" % cert_id
    cert_path = os.path.join(X509_DIR, cert_filename)

    if not os.path.isfile(cert_path):
        return {"error": "Certificate '%s' does not exist" % cert_id}, 404

    signing_cert_filename = "%s.crt" % signing_cert_id
    signing_cert_path = os.path.join(X509_DIR, signing_cert_filename)

    if not os.path.isfile(signing_cert_path):
        return {
            "error": "Certificate '%s' does not exist" % signing_cert_id
        }, 404

    auth_path = "%s.%s.auth" % (cert_path[:-4], var)
    if os.path.isfile(auth_path):
        return {
            "error": "%s for '%s' has already been signed" % (var, cert_id)
        }, 409

    signing_key_filename = "%s.key" % signing_cert_id
    signing_key_path = os.path.join(X509_DIR, signing_key_filename)

    if not os.path.isfile(signing_key_path):
        return {
            "error": "Private key '%s' does not exist" % signing_cert_id
        }, 404

    esl_path = get_esl_path(cert_path)
    cmd = [
        "sign-efi-sig-list", "-k", signing_key_path, "-c", signing_cert_path,
        var, esl_path, auth_path
    ]
    cmd_result = subprocess.run(cmd)
    if cmd_result.returncode != 0:
        return {"error": "Failed to sign EFI signature list"}, 500

    response = {}
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

    return _sign_esl(cert_id, signing_cert_id, "PK")


def sign_kek(body, user):
    cert_id = body["key_id"]
    signing_cert_id = body.get("signing_key_id", cert_id)

    return _sign_esl(cert_id, signing_cert_id, "KEK")


def sign_db(body, user):
    cert_id = body["key_id"]
    signing_cert_id = body.get("signing_key_id", cert_id)

    return _sign_esl(cert_id, signing_cert_id, "db")


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
