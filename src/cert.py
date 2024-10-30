import binascii
import logging
import os
import subprocess

from utils import X509_DIR


LOG = logging.getLogger("cert")


def get(cert_id):
    cert_filename = "%s.crt" % cert_id
    cert_path = os.path.join(X509_DIR, cert_filename)
    if not os.path.isfile(cert_path):
        return {"error": "Certificate '%s' not found" % cert_id}, 404

    with open(cert_path, "r") as f:
        cert_data = f.read(1 << 26)

    response = {"cert": cert_data}
    return response


def new(body, user):
    cert_id = body["cert_id"]

    # The default 7305 means 20 years
    cert_days = body.get("days", 7305)

    cert_filename = "%s.crt" % cert_id
    cert_path = os.path.join(X509_DIR, cert_filename)
    if os.path.isfile(cert_path):
        return {"error": "Certificate '%s' already exists" % cert_id}, 409

    key_filename = "%s.key" % cert_id
    key_path = os.path.join(X509_DIR, key_filename)
    if os.path.isfile(key_path):
        # The error message is intentionally the same
        return {"error": "Certificate '%s' already exists" % cert_id}, 409

    key_length = body.get("key_length", 2048)

    cmd = [
        "openssl", "req", "-new", "-x509", "-newkey", "rsa:%d" % key_length,
        "-subj", body["subject"], "-keyout", key_path, "-out", cert_path,
        "-days", "%d" % cert_days, "-sha256", "-nodes"
    ]

    cmd_result = subprocess.run(cmd)
    if cmd_result.returncode != 0:
        return {"error": "Failed to generate certificate"}, 500

    with open(cert_path, "r") as f:
        cert_data = f.read(1 << 26)

    response = {"cert": cert_data}

    LOG.info("%s successfully generated a new certificate %s", user, cert_id)

    return response


def sign(body, user):
    cert_id = body["cert_id"]
    digest = bytes.fromhex(body["digest"])

    key_filename = "%s.key" % cert_id
    key_path = os.path.join(X509_DIR, key_filename)
    if not os.path.isfile(key_path):
        return {"error": "Certificate '%s' not found" % cert_id}, 404

    cmd = ["openssl", "pkeyutl", "-sign", "-inkey", key_path]
    cmd_result = subprocess.run(cmd, input=digest, capture_output=True)
    if cmd_result.returncode != 0:
        return {"error": "Failed to sign digest"}, 500

    response = {
        "signature": binascii.b2a_base64(cmd_result.stdout).decode().rstrip("\n")
    }

    LOG.info(
        "%s successfully signed a digest using certificate '%s'", user, cert_id
    )

    return response
