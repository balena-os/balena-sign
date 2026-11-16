import binascii
import hashlib
import logging
import os
import shutil
import subprocess
import tempfile

from utils import PKC_DIR

LOG = logging.getLogger("pkc")

# RSA key length for each supported key type, matching the NVIDIA Jetson
# secure boot PKC key generation (openssl genrsa -out rsa3k-0.pem 3072)
KEY_TYPES = {
    "rsa3072": 3072,
}


def keys():
    try:
        dirs = os.listdir(PKC_DIR)
    except FileNotFoundError:
        dirs = []
    response = {
        "keys": dirs,
    }
    return response


def new(body, user):
    key_type = body["key_type"]

    os.makedirs(PKC_DIR, exist_ok=True)
    tmpdir = tempfile.mkdtemp(prefix="pkc-")
    try:
        private_path = os.path.join(tmpdir, "private.pem")
        cmd = ["openssl", "genrsa", "-out", private_path, str(KEY_TYPES[key_type])]
        cmd_result = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, check=False)
        if cmd_result.returncode != 0:
            raise RuntimeError(f"Failed to generate {key_type} key pair")

        cmd = ["openssl", "rsa", "-pubout", "-in", private_path,
               "-out", os.path.join(tmpdir, "public.pem")]
        cmd_result = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, check=False)
        if cmd_result.returncode != 0:
            raise RuntimeError(f"Failed to generate {key_type} key pair")

        os.chmod(private_path, 0o600)
        with open(os.path.join(tmpdir, "type"), "w", encoding="utf-8") as ofile:
            ofile.write(key_type)

        with open(private_path, "rb") as ifile:
            fingerprint = hashlib.md5(ifile.read()).hexdigest()
        shutil.move(tmpdir, os.path.join(PKC_DIR, fingerprint))
    except Exception:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise

    response = {"fingerprint": fingerprint, "key_type": key_type}
    LOG.info("%s successfully generated a new %s key %s", user, key_type, fingerprint)

    return response


def key(key_id):
    if key_id in keys()["keys"]:
        key_dir = os.path.join(PKC_DIR, key_id)
        with open(os.path.join(key_dir, "type"), "r", encoding="utf-8") as ifile:
            key_type = ifile.read()
        with open(os.path.join(key_dir, "public.pem"), "r",
                  encoding="utf-8") as pubkey:
            response = {
                "key": pubkey.read(),
                "key_type": key_type,
            }
            return response

    LOG.info("Failed to find key %s", key_id)
    return {"error": f"PKC key {key_id} is unknown"}, 404


def sign(body, user):
    # RSA-PSS with a 32 byte salt, the scheme NVIDIA Jetson secure boot uses
    # for PKC signatures (do_rsa_pss_hsm() in the L4T tegrasign_v3_hsm.py).
    # The signature is returned in the standard big-endian byte order.
    key_id = body["key_id"]
    digest = body.get("digest", "sha512")

    if key_id not in keys()["keys"]:
        LOG.info("%s failed to find key %s", user, key_id)
        return {"error": f"PKC key {key_id} is unknown"}, 404

    try:
        payload = binascii.a2b_base64(body["payload"])
    except Exception as ex:
        return {"error": f"Failed to base64-decode payload: {ex}"}, 400

    workdir = tempfile.mkdtemp(prefix="pkc-sign-")
    try:
        data_path = os.path.join(workdir, "data.bin")
        hash_path = os.path.join(workdir, "data.hash")
        sig_path = os.path.join(workdir, "data.sig")
        with open(data_path, "wb") as ofile:
            ofile.write(payload)

        cmd = ["openssl", "dgst", f"-{digest}", "-binary", "-out", hash_path, data_path]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)

        cmd = ["openssl", "pkeyutl", "-sign", "-pkeyopt", "rsa_padding_mode:pss",
               "-pkeyopt", "rsa_pss_saltlen:32", "-pkeyopt", f"digest:{digest}",
               "-in", hash_path, "-out", sig_path,
               "-inkey", os.path.join(PKC_DIR, key_id, "private.pem")]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)

        with open(sig_path, "rb") as ifile:
            response = {
                "signature": binascii.b2a_base64(ifile.read()).decode().rstrip("\n")
            }

        LOG.info("%s successfully signed a payload using %s key", user, key_id)
        return response
    except subprocess.CalledProcessError as excp:
        LOG.error("Subprocess failed: %s %s", excp, excp.stderr)
        return {"error": "Failed to sign payload"}, 500
    except Exception as excp:
        LOG.error("Unexpected error: %s", excp)
        return {"error": str(excp)}, 500
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


