import pytest

from helpers import but, without

NEW_REQUEST = {
    "hab_type": "hab",
}

CST_REQUEST = {
    "pki_id": "0" * 32,
    "hab_type": "hab",
    "payload": "AA==",
    "csf": "AA==",
}


@pytest.mark.parametrize("body", [
    pytest.param({}, id="empty"),
    pytest.param(but(NEW_REQUEST, hab_type=1), id="hab_type-number"),
    pytest.param(but(NEW_REQUEST, hab_type=None), id="hab_type-null"),
    pytest.param(but(NEW_REQUEST, hab_type=""), id="hab_type-empty"),
    pytest.param(but(NEW_REQUEST, hab_type="hab4"), id="hab_type-hab4"),
    pytest.param(but(NEW_REQUEST, hab_type="HAB"), id="hab_type-uppercase"),
    pytest.param(but(NEW_REQUEST, hab_type="ahab\n"), id="hab_type-newline",
                 marks=pytest.mark.xfail(strict=True, reason="pattern $ matches before a trailing newline, see TODO")),
    pytest.param([NEW_REQUEST], id="array"),
])
def test_new_invalid(client, body):
    response = client.post("/imx/pki", json=body)
    assert response.status_code == 400


def test_new_no_body(client):
    response = client.post("/imx/pki")
    assert response.status_code == 400


@pytest.mark.parametrize("pki_id", [
    pytest.param("xyz", id="not-hex"),
    pytest.param("..", id="dot-dot"),
    pytest.param("..%2Fsecrets", id="traversal"),
])
def test_efuses_invalid(anonymous_client, pki_id):
    # Depending on how the path is normalized, these don't even reach the route
    response = anonymous_client.get(f"/imx/efuses/{pki_id}")
    assert response.status_code in (400, 404)


@pytest.mark.parametrize("field", ["pki_id", "hab_type", "payload", "csf"])
def test_cst_missing_required(client, field):
    response = client.post("/imx/cst", json=without(CST_REQUEST, field))
    assert response.status_code == 400


@pytest.mark.parametrize("body", [
    pytest.param({}, id="empty"),
    pytest.param(but(CST_REQUEST, pki_id=1), id="pki_id-number"),
    pytest.param(but(CST_REQUEST, pki_id=None), id="pki_id-null"),
    pytest.param(but(CST_REQUEST, pki_id=""), id="pki_id-empty"),
    pytest.param(but(CST_REQUEST, pki_id="xyz"), id="pki_id-not-hex"),
    pytest.param(but(CST_REQUEST, pki_id="../ca"), id="pki_id-traversal"),
    pytest.param(but(CST_REQUEST, hab_type="hab4"), id="hab_type-hab4"),
    pytest.param(but(CST_REQUEST, hab_type=None), id="hab_type-null"),
    pytest.param(but(CST_REQUEST, payload=1), id="payload-number"),
    pytest.param(but(CST_REQUEST, payload=""), id="payload-empty"),
    pytest.param(but(CST_REQUEST, payload="not base64!"), id="payload-not-base64"),
    pytest.param(but(CST_REQUEST, payload="AA==="), id="payload-bad-padding"),
    pytest.param(but(CST_REQUEST, csf=1), id="csf-number"),
    pytest.param(but(CST_REQUEST, csf=None), id="csf-null"),
    pytest.param([CST_REQUEST], id="array"),
])
def test_cst_invalid(client, body):
    response = client.post("/imx/cst", json=body)
    assert response.status_code == 400


def test_cst_no_body(client):
    response = client.post("/imx/cst")
    assert response.status_code == 400
