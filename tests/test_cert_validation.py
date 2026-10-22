import pytest

from helpers import but, without

NEW_CERT_REQUEST = {
    "cert_id": "test-validation",
    "subject": "/CN=balenaSign test certificate/",
}

SIGN_REQUEST = {
    "cert_id": "test-validation",
    "digest": "00" * 32,
}


@pytest.mark.parametrize("body", [
    pytest.param({}, id="empty"),
    pytest.param(without(NEW_CERT_REQUEST, "cert_id"), id="no-cert_id"),
    pytest.param(without(NEW_CERT_REQUEST, "subject"), id="no-subject"),
])
def test_new_cert_missing_required(client, body):
    response = client.post("/cert", json=body)
    assert response.status_code == 400


@pytest.mark.parametrize("body", [
    pytest.param(but(NEW_CERT_REQUEST, cert_id=1), id="cert_id-number"),
    pytest.param(but(NEW_CERT_REQUEST, cert_id=None), id="cert_id-null"),
    pytest.param(but(NEW_CERT_REQUEST, subject=1), id="subject-number"),
    pytest.param(but(NEW_CERT_REQUEST, subject=None), id="subject-null"),
    pytest.param(but(NEW_CERT_REQUEST, key_length="2048"), id="key_length-string"),
    pytest.param(but(NEW_CERT_REQUEST, key_length=1024), id="key_length-not-in-enum"),
    pytest.param(but(NEW_CERT_REQUEST, days="30"), id="days-string"),
    pytest.param(but(NEW_CERT_REQUEST, days=1.5), id="days-float"),
    pytest.param(but(NEW_CERT_REQUEST, days=0), id="days-zero"),
    pytest.param(but(NEW_CERT_REQUEST, days=-1), id="days-negative"),
    pytest.param([NEW_CERT_REQUEST], id="array"),
])
def test_new_cert_invalid(client, body):
    response = client.post("/cert", json=body)
    assert response.status_code == 400


def test_new_cert_no_body(client):
    response = client.post("/cert")
    assert response.status_code == 400


@pytest.mark.xfail(strict=True, reason="cert_id is not validated, see TODO")
def test_new_cert_id_path_traversal(client, anonymous_client):
    response = client.post("/cert", json=but(
        NEW_CERT_REQUEST, cert_id="../x509/test-traversal"))
    assert response.status_code == 400
    assert anonymous_client.get("/cert/test-traversal").status_code == 404


@pytest.mark.parametrize("body", [
    pytest.param({}, id="empty"),
    pytest.param(without(SIGN_REQUEST, "cert_id"), id="no-cert_id"),
    pytest.param(without(SIGN_REQUEST, "digest"), id="no-digest"),
])
def test_sign_missing_required(client, body):
    response = client.post("/cert/sign", json=body)
    assert response.status_code == 400


@pytest.mark.parametrize("body", [
    pytest.param(but(SIGN_REQUEST, cert_id=1), id="cert_id-number"),
    pytest.param(but(SIGN_REQUEST, cert_id=None), id="cert_id-null"),
    pytest.param(but(SIGN_REQUEST, digest=1), id="digest-number"),
    pytest.param(but(SIGN_REQUEST, digest=None), id="digest-null"),
    pytest.param(but(SIGN_REQUEST, digest=""), id="digest-empty"),
    pytest.param(but(SIGN_REQUEST, digest="00" * 31), id="digest-too-short"),
    pytest.param(but(SIGN_REQUEST, digest="00" * 33), id="digest-too-long"),
    pytest.param(but(SIGN_REQUEST, digest="zz" * 32), id="digest-not-hex"),
    pytest.param([SIGN_REQUEST], id="array"),
])
def test_sign_invalid(client, body):
    response = client.post("/cert/sign", json=body)
    assert response.status_code == 400


def test_sign_no_body(client):
    response = client.post("/cert/sign")
    assert response.status_code == 400
