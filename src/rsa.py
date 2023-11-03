import binascii
import logging
import subprocess
import os
import shutil
import tempfile
import hashlib
from datetime import datetime

from utils import RSA_DIR

LOG = logging.getLogger("rsa")


def keys():
    dirs = os.listdir(RSA_DIR)
    response = {
        "keys": [dirs],
    }
    return response


def new(body, user):
    tmpdir = tempfile.mkdtemp(prefix="rsa-")
    cmd = [ "openssl", "genrsa", "-out", os.path.join(tmpdir, "private.pem"), "2048" ]
    cmd_result = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, check=False)
    if cmd_result.returncode != 0:
        raise RuntimeError("Failed to generate RSA key pair")

    cmd = [ "openssl", "rsa", "-pubout", "-in", os.path.join(tmpdir, "private.pem"), "-out",
           os.path.join(tmpdir, "public.pem") ]
    cmd_result = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, check=False)
    if cmd_result.returncode != 0:
        raise RuntimeError("Failed to generate RSA key pair")

    with open(os.path.join(tmpdir, "private.pem"), "rb") as ifile:
        fingerprint = hashlib.md5(ifile.read()).hexdigest()
        shutil.move(tmpdir, os.path.join(RSA_DIR, fingerprint))

    response = {"fingerprint": fingerprint}
    LOG.info("%s successfully generated a new RSA key %s", user, fingerprint)

    return response


def key(key_id):
    if key_id in os.listdir(RSA_DIR):
        with open(os.path.join(RSA_DIR, key_id, 'public.pem'), 'r',
                  encoding='utf-8') as pubkey:
            response = {
                "key": pubkey.read(),
            }
            return response

    LOG.info("Failed to find key %s", key_id)
    return {"error": f"RSA key {key_id} is unknown"}, 404

def sha256sum(payload):
    sha256_hash = hashlib.sha256()
    with open(payload,"rb") as f:
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

# Based on https://github.com/raspberrypi/rsa-eeprom/blob/master/rsa-eeprom-digest

# sha256sum "${IMAGE}" | awk '{print $1}' > "${OUTPUT}"
# echo "ts: $(date -u +%s)" >> "${OUTPUT}"
# "${OPENSSL}" dgst -sign "${KEY}" -keyform PEM -sha256 -out "${SIG_TMP}" "${IMAGE}"
# echo "rsa2048: $(xxd -c 4096 -p < "${SIG_TMP}")" >> "${OUTPUT}"

def sign(body, user):
    key_id = body["key_id"]

    if key_id in os.listdir(RSA_DIR):
        try:
            payload = binascii.a2b_base64(body["payload"])
        except Exception as ex:
            return {"error": f"Failed to base64-decode payload: {ex}"}, 400

        tmpinput = tempfile.mkstemp(prefix="rsa-")[1]
        with open(tmpinput, 'wb') as ifile:
            ifile.write(payload)
            tmpfile = tempfile.mkstemp(prefix="rsa-")[1]
            cmd = [ "openssl", "dgst", "-sign",
                   os.path.join(RSA_DIR, key_id, "private.pem"),
                   "-keyform", "PEM",
                   "-sha256", "-out", tmpfile, tmpinput ]
            cmd_result = subprocess.run(cmd, check=False)
            if cmd_result.returncode != 0:
                raise RuntimeError("Failed to sign payload")
            tmpout = tempfile.mkstemp(prefix="rsa-")[1]
            with open(tmpout, 'a', encoding='utf-8') as output:
                output.write(sha256sum(tmpinput))
                output.write("\n")
                output.write("ts: " +
                             str(int(datetime.utcnow().timestamp())))
                output.write("\n")
                hex_string=""
                with open(tmpfile, 'rb') as ifile:
                    while True:
                        chunk = ifile.read(4096)
                        if not chunk:
                            break
                        hex_string += binascii.hexlify(chunk).decode('utf-8')
                output.write("rsa2048: " + hex_string)
                output.write("\n")

            with open(tmpout, 'rb') as signature:
                response = {
                    "signature": binascii.b2a_base64(signature.read()).decode().rstrip("\n")
                }

                LOG.info("%s successfully signed a payload using %s key", user, key_id)

        os.remove(tmpinput)
        os.remove(tmpout)
        os.remove(tmpfile)
        return response

    LOG.info("%s failed to find key %s", user, key_id)
    return {"error": f"RSA key {key_id} is unknown"}, 404
