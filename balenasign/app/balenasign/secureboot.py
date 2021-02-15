import binascii
import logging
import os
import subprocess
import tempfile

from balenasign.utils import X509_DIR, get_esl_path, unlink_if_exists


LOG = logging.getLogger("secureboot")


def pk(cert_id):
    cert_filename = "%s.crt" % cert_id
    cert_path = os.path.join(X509_DIR, cert_filename)

    if not os.path.isfile(cert_path):
        return {"error": "Certificate '%s' does not exist" % cert_id}, 404

    pk_path = "%s.pk" % cert_path[:-4]
    if not os.path.isfile(pk_path):
        key_filename = "%s.key" % cert_id
        key_path = os.path.join(X509_DIR, key_filename)

        if not os.path.isfile(key_path):
            return {
                "error": "Private key '%s' does not exist" % cert_id}, 404

        esl_path = get_esl_path(cert_path)
        cmd = [
            "sign-efi-sig-list", "-k", key_path,
            "-c", cert_path, "PK", esl_path, pk_path
        ]
        retcode = subprocess.call(cmd)
        if retcode != 0:
            return {"error": "Failed to sign EFI signature list"}, 500

    with open(pk_path, "rb") as f:
        pk_data = f.read()

    response = {
        "pk": binascii.b2a_base64(pk_data).decode().rstrip("\n")
    }
    return response


def kek(cert_id):
    cert_filename = "%s.crt" % cert_id
    cert_path = os.path.join(X509_DIR, cert_filename)

    if not os.path.isfile(cert_path):
        return {"error": "Certificate '%s' does not exist" % cert_id}, 404

    kek_path = "%s.kek" % cert_path[:-4]
    if not os.path.isfile(kek_path):
        key_filename = "%s.key" % cert_id
        key_path = os.path.join(X509_DIR, key_filename)

        if not os.path.isfile(key_path):
            return {"error": "Private key '%s' does not exist" % cert_id}, 404

        esl_path = get_esl_path(cert_path)
        cmd = [
            "sign-efi-sig-list", "-k", key_path,
            "-c", cert_path, "KEK", esl_path, kek_path
        ]
        retcode = subprocess.call(cmd)
        if retcode != 0:
            return {"error": "Failed to sign EFI signature list"}, 500

    with open(kek_path, "rb") as f:
        kek_data = f.read()

    response = {
        "kek": binascii.b2a_base64(kek_data).decode().rstrip("\n")
    }
    return response


def db(cert_id):
    cert_filename = "%s.crt" % cert_id
    cert_path = os.path.join(X509_DIR, cert_filename)

    if not os.path.isfile(cert_path):
        return {"error": "Certificate '%s' does not exist" % cert_id}, 404

    db_path = "%s.db" % cert_path[:-4]
    if not os.path.isfile(db_path):
        key_filename = "%s.key" % cert_id
        key_path = os.path.join(X509_DIR, key_filename)

        if not os.path.isfile(key_path):
            return {"error": "Private key '%s' does not exist" % cert_id}, 404

        esl_path = get_esl_path(cert_path)
        cmd = [
            "sign-efi-sig-list", "-k", key_path,
            "-c", cert_path, "db", esl_path, db_path
        ]
        retcode = subprocess.call(cmd)
        if retcode != 0:
            return {"error": "Failed to sign EFI signature list"}, 500

    with open(db_path, "rb") as f:
        db_data = f.read()

    response = {
        "db": binascii.b2a_base64(db_data).decode().rstrip("\n")
    }
    return response


def sign(body, user):
    key_id = body["key_id"]
    key_file = os.path.join(X509_DIR, "%s.key" % key_id)
    if not os.path.isfile(key_file):
        return {"error": "Private key '%s' does not exist" % cert_id}, 404

    cert_file = os.path.join(X509_DIR, "%s.crt" % key_id)
    if not os.path.isfile(cert_file):
        return {"error": "Certificate '%s' does not exist" % cert_id}, 404

    try:
        payload = binascii.a2b_base64(body["payload"])
    except Exception as ex:
        return {"error": "Failed to base64-decode payload: %s" % ex}, 400

    with tempfile.NamedTemporaryFile(delete=False) as payload_file:
        payload_filename = payload_file.name
        payload_file.write(payload)

    signed_filename = "%s.signed" % payload_filename

    cmd_output = None
    sbsign_cmd = [
        "sbsign", "--key", key_file, "--cert", cert_file,
        "--output", signed_filename, payload_filename
    ]
    with tempfile.TemporaryFile() as tmp_file:
        retcode = subprocess.call(
            sbsign_cmd, stdout=tmp_file, stderr=subprocess.STDOUT
        )
        os.unlink(payload_filename)
        cmd_output_len = tmp_file.tell()
        if cmd_output_len > 0:
            tmp_file.seek(0)
            cmd_output = tmp_file.read(cmd_output_len)

    if retcode:
        unlink_if_exists(signed_filename)
        return {"error": "Signature failed"}, 500

    with open(signed_filename, "rb") as signed_file:
        signed_payload = signed_file.read(1 << 26)
        response = {
            "signed": binascii.b2a_base64(signed_payload).decode().rstrip("\n")
        }

    if cmd_output is not None:
        response["extra_output"] = cmd_output.decode()

    os.unlink(signed_filename)

    LOG.info(
        "%s successfully signed a payload using '%s' certificate", user, cert_id
    )

    return response
