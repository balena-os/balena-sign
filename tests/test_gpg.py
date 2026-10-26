import base64

import pytest

NEW_KEY_REQUEST = {
    "name_real": "balenaSign test key",
    "name_email": "test@example.com",
}

PAYLOAD = b"balenaSign test payload\n"


@pytest.fixture(scope="module")
def key_id(client):
    response = client.post("/gpg/key", json=NEW_KEY_REQUEST)
    assert response.status_code == 200
    fingerprint = response.json()["fingerprint"]
    assert fingerprint, "Server returned an empty fingerprint"
    return fingerprint


def test_new_key(key_id):
    assert len(key_id) == 40
    int(key_id, 16)


def test_key_listed(anonymous_client, key_id):
    response = anonymous_client.get("/gpg/keys")
    assert response.status_code == 200
    assert key_id in response.json()["keys"]


def test_get_public_key(anonymous_client, local_gpg, key_id):
    response = anonymous_client.get(f"/gpg/key/{key_id}")
    assert response.status_code == 200

    armored = response.json()["key"]
    assert armored.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    assert "PRIVATE KEY" not in armored

    imported = local_gpg.import_keys(armored)
    assert imported.fingerprints == [key_id]
    assert local_gpg.list_keys(secret=True) == []


def test_sign(client, anonymous_client, local_gpg, tmp_path, key_id):
    response = client.post("/gpg/sign", json={
        "key_id": key_id,
        "payload": base64.b64encode(PAYLOAD).decode(),
    })
    assert response.status_code == 200

    signature_path = tmp_path / "payload.sig"
    signature_path.write_bytes(base64.b64decode(response.json()["signature"]))

    armored = anonymous_client.get(f"/gpg/key/{key_id}").json()["key"]
    local_gpg.import_keys(armored)

    verified = local_gpg.verify_data(str(signature_path), PAYLOAD)
    assert verified.valid
    assert verified.pubkey_fingerprint == key_id

    tampered = local_gpg.verify_data(str(signature_path), PAYLOAD + b"x")
    assert not tampered.valid
