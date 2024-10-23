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
    try:
        dirs = os.listdir(RSA_DIR)
    except FileNotFoundError:
        dirs = []
    response = {
        "keys": dirs,
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

        try:
            tmpinput_path = None
            tmpout_path = None
            tmpfile_path = None
            with tempfile.NamedTemporaryFile(prefix="rsa-", delete=False,
                                             mode='wb') as tmpinput:
                tmpinput.write(payload)
                tmpinput_path = tmpinput.name

            with tempfile.NamedTemporaryFile(prefix="rsa-", delete=False,
                                             mode='wb') as tmpfile:
                tmpfile_path = tmpfile.name

            cmd = [ "openssl", "dgst", "-sign",
                   os.path.join(RSA_DIR, key_id, "private.pem"),
                   "-keyform", "PEM",
                   "-sha256", "-out", tmpfile_path, tmpinput_path ]
            subprocess.run(cmd, check=True)

            with tempfile.NamedTemporaryFile(prefix="rsa-", delete=False,
                                             mode='w', encoding='utf-8') as tmpout:
                tmpout_path = tmpout.name
                tmpout.write(sha256sum(tmpinput_path))
                tmpout.write("\n")
                tmpout.write("ts: " +
                             str(int(datetime.utcnow().timestamp())))
                tmpout.write("\n")
                hex_string=""
                with open(tmpfile_path, 'rb') as ifile:
                    while True:
                        chunk = ifile.read(4096)
                        if not chunk:
                            break
                        hex_string += binascii.hexlify(chunk).decode('utf-8')
                tmpout.write("rsa2048: " + hex_string)
                tmpout.write("\n")

            with open(tmpout_path, 'rb') as signature:
                response = {
                    "signature": binascii.b2a_base64(signature.read()).decode().rstrip("\n")
                }

                LOG.info("%s successfully signed a payload using %s key", user, key_id)
                return response
        except subprocess.CalledProcessError as excp:
            LOG.error("Subprocess failed: %s", excp)
            return {"error": "Failed to sign payload"}, 500
        except Exception as excp:
            LOG.error("Unexpected error: %s", excp)
            return {"error": str(excp)}, 500
        finally:
            if tmpinput_path is not None:
                os.remove(tmpinput_path)
            if tmpout_path is not None:
                os.remove(tmpout_path)
            if tmpfile_path is not None:
                os.remove(tmpfile_path)

    LOG.info("%s failed to find key %s", user, key_id)
    return {"error": f"RSA key {key_id} is unknown"}, 404
