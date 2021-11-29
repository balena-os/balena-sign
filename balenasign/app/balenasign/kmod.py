import binascii
import logging
import os
import subprocess
import tempfile

from balenasign.utils import X509_DIR, unlink_if_exists


LOG = logging.getLogger("kmod")


def cert(cert_id):
    cert_filename = "%s.crt" % cert_id
    cert_path = os.path.join(X509_DIR, cert_filename)

    if not os.path.isfile(cert_path):
        return {"error": "Certificate '%s' does not exist" % cert_id}, 404

    with open(cert_path, "r") as f:
        cert_data = f.read()

    response = {
        "cert": cert_data
    }

    return response


def sign(body, user):
    response = {}

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
    sign_cmd = [
        "/usr/local/bin/sign-file", "sha512", key_file, cert_file,
        payload_filename, signed_filename
    ]
    with tempfile.TemporaryFile() as tmp_file:
        cmd_result = subprocess.run(
            sign_cmd, stdout=tmp_file, stderr=subprocess.STDOUT
        )
        os.unlink(payload_filename)
        cmd_output_len = tmp_file.tell()
        if cmd_output_len > 0:
            tmp_file.seek(0)
            cmd_output = tmp_file.read(cmd_output_len)

    if cmd_result.returncode:
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
        "%s successfully signed a payload using '%s' key", user, key_id
    )

    return response
