import base64
import hashlib
import time

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

PAYLOAD = b"balenaSign test payload\n"

TIMESTAMP_TOLERANCE = 300


@pytest.fixture(scope="module")
def key_id(client):
    response = client.post("/rsa/key", json={})
    assert response.status_code == 200
    fingerprint = response.json()["fingerprint"]
    assert fingerprint, "Server returned an empty fingerprint"
    return fingerprint


@pytest.fixture(scope="module")
def public_key(anonymous_client, key_id):
    response = anonymous_client.get(f"/rsa/key/{key_id}")
    assert response.status_code == 200
    return response.json()["key"]


def test_new_key(key_id):
    int(key_id, 16)


def test_key_listed(anonymous_client, key_id):
    response = anonymous_client.get("/rsa/keys")
    assert response.status_code == 200
    assert key_id in response.json()["keys"]


def test_get_public_key(public_key):
    assert public_key.startswith("-----BEGIN PUBLIC KEY-----")
    assert "PRIVATE KEY" not in public_key

    key = serialization.load_pem_public_key(public_key.encode())
    assert isinstance(key, rsa.RSAPublicKey)
    assert key.key_size == 2048


def test_sign(client, public_key, key_id):
    response = client.post("/rsa/sign", json={
        "key_id": key_id,
        "payload": base64.b64encode(PAYLOAD).decode(),
    })
    assert response.status_code == 200

    # The signature is in the rsa-eeprom-digest format:
    # https://github.com/raspberrypi/rsa-eeprom/blob/master/rsa-eeprom-digest
    lines = base64.b64decode(response.json()["signature"]).decode().splitlines()
    assert len(lines) == 3
    digest, timestamp, signature = lines

    assert digest == hashlib.sha256(PAYLOAD).hexdigest()

    assert timestamp.startswith("ts: ")
    assert abs(int(timestamp[len("ts: "):]) - time.time()) < TIMESTAMP_TOLERANCE

    assert signature.startswith("rsa2048: ")
    signature = bytes.fromhex(signature[len("rsa2048: "):])

    key = serialization.load_pem_public_key(public_key.encode())
    key.verify(signature, PAYLOAD, padding.PKCS1v15(), hashes.SHA256())
    with pytest.raises(InvalidSignature):
        key.verify(signature, PAYLOAD + b"x", padding.PKCS1v15(), hashes.SHA256())
