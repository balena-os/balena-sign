import base64
import shutil
import struct
import subprocess
import uuid

import pytest

# Signing doesn't look at the module contents, so any payload will do.
PAYLOAD = b"balenaSign test kernel module\n"

# See include/linux/module_signature.h in the kernel sources
MODULE_SIG_MAGIC = b"~Module signature appended~\n"
MODULE_SIG_FORMAT = ">BBBBB3xI"
PKEY_ID_PKCS7 = 2


def split_signed_module(signed):
    assert signed.endswith(MODULE_SIG_MAGIC)
    signed = signed[:-len(MODULE_SIG_MAGIC)]

    info_len = struct.calcsize(MODULE_SIG_FORMAT)
    algo, hash_algo, id_type, signer_len, key_id_len, sig_len = struct.unpack(
        MODULE_SIG_FORMAT, signed[-info_len:])
    assert id_type == PKEY_ID_PKCS7
    # These are carried inside the PKCS#7 message instead
    assert (algo, hash_algo, signer_len, key_id_len) == (0, 0, 0, 0)

    signed = signed[:-info_len]
    return signed[:-sig_len], signed[-sig_len:]


def verify_cms(tmp_path, cert, content, signature):
    cert_path = tmp_path / "cert.pem"
    content_path = tmp_path / "content"
    signature_path = tmp_path / "signature.der"
    cert_path.write_text(cert)
    content_path.write_bytes(content)
    signature_path.write_bytes(signature)

    cmd = [
        "openssl", "cms", "-verify", "-binary", "-inform", "DER",
        "-in", str(signature_path), "-content", str(content_path),
        "-certfile", str(cert_path), "-CAfile", str(cert_path),
        "-purpose", "any", "-out", "/dev/null",
    ]
    return subprocess.run(cmd, capture_output=True).returncode == 0


@pytest.fixture(scope="module")
def cert(client):
    cert_id = f"test-kmod-{uuid.uuid4()}"
    response = client.post("/cert", json={
        "cert_id": cert_id,
        "subject": "/CN=balenaSign test kmod certificate/",
    })
    assert response.status_code == 200
    return cert_id, response.json()["cert"]


def test_get_cert(anonymous_client, cert):
    cert_id, pem = cert
    response = anonymous_client.get(f"/kmod/cert/{cert_id}")
    assert response.status_code == 200
    assert response.json()["cert"] == pem


def test_sign(client, tmp_path, cert):
    # The server inherits PATH from the test runner
    if shutil.which("sign-file") is None:
        pytest.fail("`sign-file` from the kernel sources must be on PATH")

    cert_id, pem = cert
    response = client.post("/kmod/sign", json={
        "key_id": cert_id,
        "payload": base64.b64encode(PAYLOAD).decode(),
    })
    assert response.status_code == 200

    signed = base64.b64decode(response.json()["signed"])
    content, signature = split_signed_module(signed)
    assert content == PAYLOAD

    assert verify_cms(tmp_path, pem, content, signature)
    assert not verify_cms(tmp_path, pem, content + b"x", signature)
