import pytest

# Signing with a key that does not exist passes authentication without
# changing any state on the server.
SIGN_REQUEST = {"key_id": "00", "payload": "AA=="}

PUBLIC_ENDPOINTS = [
    "/gpg/keys",
    "/rsa/keys",
    "/imx/pkis",
]


def test_missing_api_key(anonymous_client):
    response = anonymous_client.post("/gpg/sign", json=SIGN_REQUEST)
    assert response.status_code == 401


def test_invalid_api_key(make_client):
    response = make_client("invalid").post("/gpg/sign", json=SIGN_REQUEST)
    assert response.status_code == 401


def test_valid_api_key(client):
    response = client.post("/gpg/sign", json=SIGN_REQUEST)
    assert response.status_code == 404


@pytest.mark.parametrize("path", PUBLIC_ENDPOINTS)
def test_public_endpoint_without_api_key(anonymous_client, path):
    response = anonymous_client.get(path)
    assert response.status_code == 200
