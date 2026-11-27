import pytest

from helpers import but, without

SIGN_REQUEST = {
    "key_id": "test-validation",
    "payload": "AA==",
}


@pytest.mark.parametrize("body", [
    pytest.param({}, id="empty"),
    pytest.param(without(SIGN_REQUEST, "key_id"), id="no-key_id"),
    pytest.param(without(SIGN_REQUEST, "payload"), id="no-payload"),
])
def test_sign_missing_required(client, body):
    response = client.post("/kmod/sign", json=body)
    assert response.status_code == 400


@pytest.mark.parametrize("body", [
    pytest.param(but(SIGN_REQUEST, key_id=1), id="key_id-number"),
    pytest.param(but(SIGN_REQUEST, key_id=None), id="key_id-null"),
    pytest.param(but(SIGN_REQUEST, payload=1), id="payload-number"),
    pytest.param(but(SIGN_REQUEST, payload=None), id="payload-null"),
    pytest.param(but(SIGN_REQUEST, payload=""), id="payload-empty"),
    pytest.param(but(SIGN_REQUEST, payload="not base64!"), id="payload-not-base64"),
    pytest.param(but(SIGN_REQUEST, payload="AA==="), id="payload-bad-padding"),
    pytest.param([SIGN_REQUEST], id="array"),
])
def test_sign_invalid(client, body):
    response = client.post("/kmod/sign", json=body)
    assert response.status_code == 400


def test_sign_no_body(client):
    response = client.post("/kmod/sign")
    assert response.status_code == 400
