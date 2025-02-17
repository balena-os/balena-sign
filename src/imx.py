import base64
import binascii
from datetime import datetime
import glob
import hashlib
import logging
import os
import subprocess
import shutil
import tempfile
from utils import PKI_DIR

LOG = logging.getLogger("imx")

SRK_EFUSES = "SRK_efuses.bin"


def pkis():
    """
    Retrieve list of PKI trees
    """
    try:
        dirs = os.listdir(PKI_DIR)
        if 'ca' in dirs:
            dirs.remove('ca')
    except FileNotFoundError:
        dirs = []

    response = {
        "pkis": dirs,
    }
    return response


def generate_hab(hab_type, tree_dir):
    """
    Generates a PKI tree based of the provided type (hab4/ahab)
    """
    srks = "-num-srk 4"
    dig_algo = None
    script = "hab4_pki_tree.sh"
    if hab_type == "ahab":
        script = "ahab_pki_tree.sh"
        srks = None
        dig_algo = "-da sha512"

    # Prepare tree
    # Must be created new
    os.makedirs(f"{PKI_DIR}/crts", exist_ok=False)
    os.makedirs(f"{PKI_DIR}/keys", exist_ok=False)
    shutil.copy2(f"/usr/local/cst/keys/{script}", f"{tree_dir}/{script}")
    if not os.path.exists(f"{PKI_DIR}/ca"):
        shutil.copytree("/usr/local/cst/ca", f"{PKI_DIR}/ca")
    # Generate a serial number
    with open(f"{PKI_DIR}/keys/serial", 'w', encoding='utf-8') as file:
        file.write(datetime.now().strftime('%Y%m%d'))
    # Generate a random password file
    with open(f"{PKI_DIR}/keys/key_pass.txt", 'w', encoding='utf-8') as file:
        password = base64.b64encode(os.urandom(32)).decode('utf-8')
        file.write(f"{password}\n{password}")

    # Call key generation script
    cmd = [f"{tree_dir}/{script}",
           "-existing-ca", "n",
           "-kt", "rsa",
           "-kl", "4096",
           "-duration", "10",
           "-srk-ca", "y"]

    if srks:
        for word in srks.split():
            cmd.append(word)

    if dig_algo:
        for word in dig_algo.split():
            cmd.append(word)

    cmd_result = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, check=False)
    if cmd_result.returncode != 0:
        raise RuntimeError("Failed to generate PKI tree")

    # Organize
    shutil.move(f"{PKI_DIR}/crts", f"{tree_dir}/")
    shutil.move(f"{PKI_DIR}/keys", f"{tree_dir}/")
    # Cleanup
    os.remove(f"{tree_dir}/{script}")
    for ext in ['sh', 'old', 'attr', 'txt']:
        for file_path in glob.glob(f'{tree_dir}/crts/*.{ext}'):
            os.remove(file_path)


def generate_srks(hab_type, tree_dir):
    """
    Generates the SRK table and efuse hash
    """
    srk_table = "SRK_table.bin"
    hab_ver = "--hab_ver 4"
    srk_digest = "digest sha256"
    if hab_type == "ahab":
        hab_ver = "--ahab_ver"
        srk_digest = "sign_digest sha512"
    # Beware this sort will only work for up to 9 certicates as SRK10 will
    # be sortered after SRK1.
    csv_certs = ','.join(sorted(glob.glob(f"{tree_dir}/crts/SRK*crt.pem")))
    cmd = ["/usr/local/bin/srktool",
           "--table", f"{tree_dir}/{srk_table}",
           "--efuses", f"{tree_dir}/{SRK_EFUSES}",
           "--certs", csv_certs, ]
    for word in hab_ver.split():
        cmd.append(word)
    for word in f"--{srk_digest}".split():
        cmd.append(word)
    cmd_result = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, check=False)
    if cmd_result.returncode != 0:
        raise RuntimeError("Failed to generate SRK table and hashes")


# See `Code-Signing Tool User's Guide` inside CST release package for details
def new(body, user):
    """
    Generates a PKI tree based of the provided type (hab4/ahab) and returns the
    directory name as identifier.
    """
    root_dir = hashlib.md5(os.urandom(64)).hexdigest()
    tree_dir = os.path.join(PKI_DIR, root_dir)
    os.makedirs(tree_dir, exist_ok=False)
    try:
        generate_hab(body["hab_type"], tree_dir)
    except Exception as e:
        LOG.error("An error occured generating PKI tress for %s", body["hab_type"])
        raise RuntimeError(f"Failed to create new PKI tree: {e}")

    try:
        generate_srks(body["hab_type"], tree_dir)
    except Exception as e:
        LOG.error("An error occured generating SRK tables for %s", body["hab_type"])
        raise RuntimeError(f"Failed to create SRK tables: {e}")

    LOG.info("%s successfully generated a new %s PKI tree %s", user, body["hab_type"], root_dir)
    response = {"pki_id": root_dir}
    return response


def efuses(pki_id):
    """
    Retrieves efuses hash binary in base64 format for the given PKI id tree.
    """
    if pki_id in os.listdir(PKI_DIR):
        with open(os.path.join(PKI_DIR, pki_id, SRK_EFUSES), 'rb') as srkfuses:
            response = {
                "efuses": binascii.b2a_base64(srkfuses.read()).decode().rstrip("\n"),
            }
            return response

    LOG.info("Failed to find PKI tree %s", pki_id)
    return {"error": f"PKI tree {pki_id} is unknown"}, 404


def cst(body, user):
    """
    Generates and returns the compiled CSF base 64 binary using the specified
    PKI tree and CSF template and payload provided.
    """
    pki_id = body["pki_id"]
    LOG.info("Using PKI id %s", pki_id)

    if pki_id not in os.listdir(PKI_DIR):
        LOG.error("%s failed to find PKI tree %s", user, pki_id)
        return {"error": f"PKI tree {pki_id} is unknown"}, 404

    try:
        csf = binascii.a2b_base64(body["csf"])
        payload = binascii.a2b_base64(body["payload"])
    except Exception as ex:
        return {"error": f"Failed to base64-decode payload: {ex}"}, 400

    payload_path = None
    csf_path = None
    csf_bin_path = None
    try:
        payload_path = save_temp_file(payload, prefix="bin-")
        log_file_md5(payload_path, "payload")

        csf_path = save_temp_file(csf, prefix="csf-")
        csf_content = replace_placeholders(csf_path, pki_id, payload_path)
        save_temp_file(csf_content, file_path=csf_path, mode='w')
        csf_bin_path = generate_csf_binary(csf_path)
        response = {
            "csf_bin": read_and_encode_file(csf_bin_path)
        }
        LOG.info("%s successfully created a CSF binary using %s key", user, pki_id)
        return response
    except subprocess.CalledProcessError as excp:
        LOG.error("Subprocess failed: %s", excp)
        return {"error": "Failed to create CSF binary"}, 500
    except Exception as excp:
        LOG.error("Unexpected error: %s", excp)
        return {"error": str(excp)}, 500
    finally:
        clean_up_files([payload_path, csf_path, csf_bin_path])


def save_temp_file(content, prefix="", file_path=None, mode='wb'):
    if file_path is None:
        with tempfile.NamedTemporaryFile(prefix=prefix, delete=False, mode=mode) as temp_file:
            temp_file.write(content)
            return temp_file.name
    else:
        with open(file_path, mode) as file:
            file.write(content)
            return file_path


def log_file_md5(file_path, file_type):
    with open(file_path, 'rb') as file:
        md5hash = hashlib.md5(file.read()).hexdigest()
        LOG.info("Using %s with md5 %s", file_type, md5hash)


def replace_placeholders(csf_path, pki_id, payload_path):
    with open(csf_path, 'r', encoding='utf-8') as csf_file:
        content = csf_file.read()
        cert_path_content = content.replace(
            '%%CERTS_PATH%%',
            os.path.join(PKI_DIR, pki_id, "crts"))
        bin_path_content = cert_path_content.replace(
            '%%BIN_PATH%%',
            payload_path)
        LOG.info("Replaced placeholders in CSF %s", bin_path_content)
    return bin_path_content


def generate_csf_binary(csf_path):
    with tempfile.NamedTemporaryFile(prefix="cst-", delete=False, mode='wb') as csf_bin_file:
        csf_bin_path = csf_bin_file.name
        cmd = ["cst", "-o", csf_bin_path, "-i", csf_path]
        LOG.info("Running cmd %s", cmd)
        result = subprocess.run(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=True)
        LOG.info("CST stdout: %s", result.stdout.decode())
        LOG.info("CST stderr: %s", result.stderr.decode())
    return csf_bin_path


def read_and_encode_file(file_path):
    with open(file_path, 'rb') as file:
        md5hash = hashlib.md5(file.read()).hexdigest()
        LOG.info("Returning CSF binary with md5 %s", md5hash)
        file.seek(0)  # Reset file pointer to the beginning
        return base64.b64encode(file.read()).decode().rstrip("\n")


def clean_up_files(file_paths):
    for file_path in file_paths:
        if file_path is not None:
            os.remove(file_path)
            LOG.info("Cleaned up temporary file %s", file_path)
