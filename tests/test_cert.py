import base64
import datetime
import hashlib
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

SUBJECT = "/CN=balenaSign test certificate/"
COMMON_NAME = "balenaSign test certificate"

PAYLOAD = b"balenaSign test payload\n"


def new_cert_id():
    return f"test-{uuid.uuid4()}"


def create_cert(client, **fields):
    body = dict({"cert_id": new_cert_id(), "subject": SUBJECT}, **fields)
    response = client.post("/cert", json=body)
    assert response.status_code == 200
    return body["cert_id"], response.json()["cert"]


@pytest.fixture(scope="module")
def cert(client):
    return create_cert(client)


def test_new_cert(cert):
    _, pem = cert
    certificate = x509.load_pem_x509_certificate(pem.encode())

    common_name = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert [attr.value for attr in common_name] == [COMMON_NAME]
    # Self-signed
    assert certificate.issuer == certificate.subject

    public_key = certificate.public_key()
    assert isinstance(public_key, rsa.RSAPublicKey)
    assert public_key.key_size == 2048

    validity = certificate.not_valid_after_utc - certificate.not_valid_before_utc
    assert validity == datetime.timedelta(days=7305)


def test_new_cert_options(client):
    _, pem = create_cert(client, key_length=4096, days=30)
    certificate = x509.load_pem_x509_certificate(pem.encode())

    assert certificate.public_key().key_size == 4096
    validity = certificate.not_valid_after_utc - certificate.not_valid_before_utc
    assert validity == datetime.timedelta(days=30)


def test_get_cert(anonymous_client, cert):
    cert_id, pem = cert
    response = anonymous_client.get(f"/cert/{cert_id}")
    assert response.status_code == 200
    assert response.json()["cert"] == pem
    assert "PRIVATE KEY" not in pem


def test_sign(client, cert):
    cert_id, pem = cert
    digest = hashlib.sha256(PAYLOAD).digest()

    response = client.post("/cert/sign", json={
        "cert_id": cert_id,
        "digest": digest.hex(),
    })
    assert response.status_code == 200
    signature = base64.b64decode(response.json()["signature"])

    # The server signs the bare digest with PKCS#1 v1.5 padding, without the
    # DigestInfo structure a regular RSA-SHA256 signature would contain.
    public_key = x509.load_pem_x509_certificate(pem.encode()).public_key()
    recovered = public_key.recover_data_from_signature(
        signature, padding.PKCS1v15(), None)
    assert recovered == digest
