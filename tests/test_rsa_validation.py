import pytest

from helpers import but, without

SIGN_REQUEST = {
    "key_id": "00" * 16,
    "payload": "AA==",
}


@pytest.mark.parametrize("body", [
    pytest.param([], id="array"),
    pytest.param("", id="string"),
    pytest.param(1, id="number"),
])
def test_new_key_invalid(client, body):
    response = client.post("/rsa/key", json=body)
    assert response.status_code == 400


@pytest.mark.parametrize("key_id", [
    pytest.param("xyz", id="not-hex"),
    pytest.param("00 00", id="space"),
])
def test_get_key_invalid_id(anonymous_client, key_id):
    response = anonymous_client.get(f"/rsa/key/{key_id}")
    assert response.status_code == 400


@pytest.mark.parametrize("body", [
    pytest.param({}, id="empty"),
    pytest.param(without(SIGN_REQUEST, "key_id"), id="no-key_id"),
    pytest.param(without(SIGN_REQUEST, "payload"), id="no-payload"),
])
def test_sign_missing_required(client, body):
    response = client.post("/rsa/sign", json=body)
    assert response.status_code == 400


@pytest.mark.parametrize("body", [
    pytest.param(but(SIGN_REQUEST, key_id=1), id="key_id-number"),
    pytest.param(but(SIGN_REQUEST, key_id=None), id="key_id-null"),
    pytest.param(but(SIGN_REQUEST, key_id=""), id="key_id-empty"),
    pytest.param(but(SIGN_REQUEST, key_id="xyz"), id="key_id-not-hex"),
    pytest.param(but(SIGN_REQUEST, key_id="../00"), id="key_id-path"),
    pytest.param(but(SIGN_REQUEST, payload=1), id="payload-number"),
    pytest.param(but(SIGN_REQUEST, payload=""), id="payload-empty"),
    pytest.param(but(SIGN_REQUEST, payload="not base64!"), id="payload-not-base64"),
    pytest.param(but(SIGN_REQUEST, payload="AA==="), id="payload-bad-padding"),
    pytest.param([SIGN_REQUEST], id="array"),
])
def test_sign_invalid(client, body):
    response = client.post("/rsa/sign", json=body)
    assert response.status_code == 400


def test_sign_no_body(client):
    response = client.post("/rsa/sign")
    assert response.status_code == 400
