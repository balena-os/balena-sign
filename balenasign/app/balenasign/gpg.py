import binascii
import gnupg
import logging

from balenasign.utils import GPG_HOME_DIR


LOG = logging.getLogger("gpg")


def keys():
    gpg = gnupg.GPG(gnupghome=GPG_HOME_DIR)

    response = {
        "keys": [key["fingerprint"] for key in gpg.list_keys()],
    }
    return response


def key(key_id):
    gpg = gnupg.GPG(gnupghome=GPG_HOME_DIR)

    if not gpg.list_keys(keys=key_id):
        return {"error": "GPG key '%s' is unknown" % key_id}, 404

    response = {
        "key": gpg.export_keys(key_id),
    }
    return response


def sign(body, user):
    key_id = body["key_id"]

    try:
        payload = binascii.a2b_base64(body["payload"])
    except Exception as ex:
        return {"error": "Failed to base64-decode payload: %s" % ex}, 400

    gpg = gnupg.GPG(gnupghome=GPG_HOME_DIR)

    if not gpg.list_keys(secret=True, keys=key_id):
        return {"error": "GPG key '%s' is unknown" % key_id}, 404

    signature = gpg.sign(payload, keyid=key_id, detach=True, binary=True)

    response = {
        "signature": binascii.b2a_base64(signature.data).decode().rstrip("\n")
    }

    LOG.info("%s successfully signed a payload using '%s' key", user, key_id)

    return response
