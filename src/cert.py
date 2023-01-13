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
        "-days", "3650", "-sha256", "-nodes"
    ]

    cmd_result = subprocess.run(cmd)
    if cmd_result.returncode != 0:
        return {"error": "Failed to generate certificate"}, 500

    with open(cert_path, "r") as f:
        cert_data = f.read(1 << 26)

    response = {"cert": cert_data}

    LOG.info("%s successfully generated a new certificate %s", user, cert_id)

    return response
