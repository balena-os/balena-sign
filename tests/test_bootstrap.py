import base64
import hashlib
import json
import os
import re

import gnupg
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from test_imx import (LOAD_ADDRESS, PAYLOAD_SIZE, parse_csf, parse_srk_table,
                      sign as sign_csf, srk_efuses, srk_public_key, issued_by)
from test_imx import verify_cms as verify_csf_cms
from test_kmod import split_signed_module, verify_cms as verify_kmod_cms
from test_secureboot_efi import sbverify
from test_secureboot_esl import (LOADER_HASH, check_signed_esl, hash_esl,
                                 parse_auth, verify_auth)

PAYLOAD = b"balenaSign test payload\n"

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def readme_request():
    with open(os.path.join(REPO_DIR, "README.md")) as readme:
        match = re.search(r"/bootstrap \\.*?-d '(\{.*?\})'", readme.read(), re.DOTALL)
    assert match, "No bootstrap example found in README.md"
    return json.loads(match.group(1))


REQUEST = readme_request()
CERTIFICATES = REQUEST["certificates"]


def cert_id(name):
    return CERTIFICATES[name]["cert_id"]


@pytest.fixture(scope="module")
def bootstrap(client, cst_dir):
    response = client.post("/bootstrap", json=REQUEST)
    assert response.status_code == 200
    return response.json()


@pytest.fixture(scope="module")
def certs(bootstrap):
    return bootstrap["certificates"]


def test_response(bootstrap):
    assert re.fullmatch("[0-9A-Fa-f]{40}", bootstrap["gpg"]["fingerprint"])
    assert re.fullmatch("[0-9a-f]{32}", bootstrap["rsa"]["fingerprint"])
    # The spec calls these pkiHab and pkiAhab, see TODO
    assert re.fullmatch("[0-9a-f]{32}", bootstrap["hab"]["pki_id"])
    assert re.fullmatch("[0-9a-f]{32}", bootstrap["ahab"]["pki_id"])
    assert sorted(bootstrap["certificates"]) == sorted(CERTIFICATES)


@pytest.mark.parametrize("name", sorted(CERTIFICATES))
def test_certificate(anonymous_client, certs, name):
    request = CERTIFICATES[name]
    cert = x509.load_pem_x509_certificate(certs[name].encode())
    subject = request["subject"].strip("/").split("=", 1)[1]
    assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == subject
    assert cert.public_key().key_size == request.get("key_length", 2048)

    response = anonymous_client.get(f"/cert/{request['cert_id']}")
    assert response.status_code == 200
    assert response.json()["cert"] == certs[name]


def test_gpg(client, anonymous_client, tmp_path, bootstrap):
    fingerprint = bootstrap["gpg"]["fingerprint"]
    response = anonymous_client.get("/gpg/keys")
    assert response.status_code == 200
    assert fingerprint in response.json()["keys"]

    response = anonymous_client.get(f"/gpg/key/{fingerprint}")
    assert response.status_code == 200
    local_gpg = gnupg.GPG(gnupghome=str(tmp_path))
    imported = local_gpg.import_keys(response.json()["key"])
    assert imported.fingerprints == [fingerprint]
    uid = f"{REQUEST['gpg']['name_real']} <{REQUEST['gpg']['name_email']}>"
    assert local_gpg.list_keys()[0]["uids"] == [uid]

    response = client.post("/gpg/sign", json={
        "key_id": fingerprint,
        "payload": base64.b64encode(PAYLOAD).decode(),
    })
    assert response.status_code == 200
    signature_path = tmp_path / "payload.sig"
    signature_path.write_bytes(base64.b64decode(response.json()["signature"]))
    verified = local_gpg.verify_data(str(signature_path), PAYLOAD)
    assert verified.valid
    assert verified.pubkey_fingerprint == fingerprint


def test_rsa(client, anonymous_client, bootstrap):
    fingerprint = bootstrap["rsa"]["fingerprint"]
    response = anonymous_client.get("/rsa/keys")
    assert response.status_code == 200
    assert fingerprint in response.json()["keys"]

    response = anonymous_client.get(f"/rsa/key/{fingerprint}")
    assert response.status_code == 200
    key = serialization.load_pem_public_key(response.json()["key"].encode())

    response = client.post("/rsa/sign", json={
        "key_id": fingerprint,
        "payload": base64.b64encode(PAYLOAD).decode(),
    })
    assert response.status_code == 200
    lines = base64.b64decode(response.json()["signature"]).decode().splitlines()
    signature = bytes.fromhex(lines[-1][len("rsa2048: "):])
    key.verify(signature, PAYLOAD, padding.PKCS1v15(), hashes.SHA256())


def test_pk(anonymous_client, tmp_path, certs):
    # PK is self-signed
    response = anonymous_client.get(f"/secureboot/pk/{cert_id('pk')}")
    check_signed_esl(tmp_path, response, "PK",
                     [(cert_id("pk"), certs["pk"])], certs["pk"])


def test_kek(anonymous_client, tmp_path, certs):
    # KEK is signed by PK
    response = anonymous_client.get(f"/secureboot/kek/{cert_id('kek')}")
    check_signed_esl(tmp_path, response, "KEK",
                     [(cert_id("kek"), certs["kek"])], certs["pk"])


def test_db(anonymous_client, tmp_path, certs):
    # bootstrap signs db with itself instead of KEK, see TODO
    response = anonymous_client.get(f"/secureboot/db/{cert_id('db')}")
    check_signed_esl(tmp_path, response, "db",
                     [(cert_id("db"), certs["db"])], certs["db"])


@pytest.mark.parametrize("var", ["db", "dbx"])
def test_kek_signs_esl(client, tmp_path, certs, var):
    esl = hash_esl(LOADER_HASH)
    response = client.post(f"/secureboot/{var}", json={
        "esl": base64.b64encode(esl).decode(),
        "signing_key_id": cert_id("kek"),
    })
    assert response.status_code == 200
    auth = base64.b64decode(response.json()["auth"])

    _, _, signed_esl = parse_auth(auth)
    assert signed_esl == esl
    assert verify_auth(tmp_path, auth, var, certs["kek"])
    assert not verify_auth(tmp_path, auth, var, certs["pk"])


def test_db_signs_efi(client, tmp_path, certs, efi_binary):
    response = client.post("/secureboot/efi", json={
        "key_id": cert_id("db"),
        "payload": base64.b64encode(efi_binary).decode(),
    })
    assert response.status_code == 200

    signed_path = tmp_path / "signed.efi"
    signed_path.write_bytes(base64.b64decode(response.json()["signed"]))
    cert_path = tmp_path / "db.pem"
    cert_path.write_text(certs["db"])
    other_path = tmp_path / "kek.pem"
    other_path.write_text(certs["kek"])

    result = sbverify("--cert", cert_path, signed_path)
    assert result.returncode == 0, result.stderr
    assert sbverify("--cert", other_path, signed_path).returncode != 0


def test_kmod(client, anonymous_client, tmp_path, certs):
    response = anonymous_client.get(f"/kmod/cert/{cert_id('kmod')}")
    assert response.status_code == 200
    assert response.json()["cert"] == certs["kmod"]

    response = client.post("/kmod/sign", json={
        "key_id": cert_id("kmod"),
        "payload": base64.b64encode(PAYLOAD).decode(),
    })
    assert response.status_code == 200
    content, signature = split_signed_module(base64.b64decode(response.json()["signed"]))
    assert content == PAYLOAD
    assert verify_kmod_cms(tmp_path, certs["kmod"], content, signature)
    assert not verify_kmod_cms(tmp_path, certs["pk"], content, signature)


@pytest.mark.parametrize("hab_type, digest_size", [
    ("hab", hashlib.sha256().digest_size),
    ("ahab", hashlib.sha512().digest_size),
])
def test_pki(anonymous_client, bootstrap, hab_type, digest_size):
    pki_id = bootstrap[hab_type]["pki_id"]
    response = anonymous_client.get("/imx/pkis")
    assert response.status_code == 200
    assert pki_id in response.json()["pkis"]

    response = anonymous_client.get(f"/imx/efuses/{pki_id}")
    assert response.status_code == 200
    assert len(base64.b64decode(response.json()["efuses"])) == digest_size


def test_hab_signs_csf(client, anonymous_client, tmp_path, bootstrap):
    pki_id = bootstrap["hab"]["pki_id"]
    payload = hashlib.shake_256(PAYLOAD).digest(PAYLOAD_SIZE)
    commands, srk_table, certs, signatures = parse_csf(sign_csf(client, pki_id, payload))

    keys = parse_srk_table(srk_table)
    efuses = anonymous_client.get(f"/imx/efuses/{pki_id}").json()["efuses"]
    assert srk_efuses(keys) == base64.b64decode(efuses)
    for cert in certs.values():
        assert issued_by(cert, srk_public_key(keys[0]))

    (_, _, csf_signature), (_, img_blocks, img_signature) = signatures
    assert verify_csf_cms(tmp_path, certs[1], commands, csf_signature)
    assert img_blocks == [(LOAD_ADDRESS, PAYLOAD_SIZE)]
    assert verify_csf_cms(tmp_path, certs[2], payload, img_signature)
