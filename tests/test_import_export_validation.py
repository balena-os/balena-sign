import pytest

from helpers import but, without

EXPORT_REQUEST = {
    "key": "balenaSignTestPassphrase",
}

IMPORT_REQUEST = {
    "key": "balenaSignTestPassphrase",
    "data": "AAAA",
    "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
}


@pytest.mark.parametrize("body", [
    pytest.param({}, id="empty"),
    pytest.param(but(EXPORT_REQUEST, key=1), id="key-number"),
    pytest.param(but(EXPORT_REQUEST, key=None), id="key-null"),
    pytest.param(but(EXPORT_REQUEST, key=""), id="key-empty"),
    pytest.param(but(EXPORT_REQUEST, key="not base64!"), id="key-not-base64"),
    pytest.param([EXPORT_REQUEST], id="array"),
])
def test_export_invalid(client, body):
    response = client.post("/export", json=body)
    assert response.status_code == 400


def test_export_no_body(client):
    response = client.post("/export")
    assert response.status_code == 400


@pytest.mark.parametrize("field", ["key", "data", "salt"])
def test_import_missing_required(client, field):
    response = client.post("/import", json=without(IMPORT_REQUEST, field))
    assert response.status_code == 400


@pytest.mark.parametrize("body", [
    pytest.param({}, id="empty"),
    pytest.param(but(IMPORT_REQUEST, key=1), id="key-number"),
    pytest.param(but(IMPORT_REQUEST, key=""), id="key-empty"),
    pytest.param(but(IMPORT_REQUEST, data=1), id="data-number"),
    pytest.param(but(IMPORT_REQUEST, data=None), id="data-null"),
    pytest.param(but(IMPORT_REQUEST, data="not base64!"), id="data-not-base64"),
    pytest.param(but(IMPORT_REQUEST, salt=1), id="salt-number"),
    pytest.param(but(IMPORT_REQUEST, salt="not base64!"), id="salt-not-base64"),
    pytest.param([IMPORT_REQUEST], id="array"),
])
def test_import_invalid(client, body):
    response = client.post("/import", json=body)
    assert response.status_code == 400


def test_import_no_body(client):
    response = client.post("/import")
    assert response.status_code == 400


def test_import_not_encrypted(client):
    # Well-formed, but not encrypted with the given passphrase
    response = client.post("/import", json=IMPORT_REQUEST)
    assert response.status_code == 401
