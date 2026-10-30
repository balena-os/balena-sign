import pytest

from helpers import but, without

INTERNAL_REQUEST = {
    "key_id": "test-validation",
    "signing_key_id": "test-validation",
}

EXTERNAL_REQUEST = {
    "esl": "AA==",
    "signing_key_id": "test-validation",
}

INTERNAL_INVALID = [
    pytest.param(but(INTERNAL_REQUEST, key_id=1), id="key_id-number"),
    pytest.param(but(INTERNAL_REQUEST, key_id=None), id="key_id-null"),
    pytest.param(but(INTERNAL_REQUEST, key_id=[1]), id="key_id-list-of-numbers"),
    pytest.param(but(INTERNAL_REQUEST, key_id={}), id="key_id-object"),
    pytest.param(but(INTERNAL_REQUEST, signing_key_id=1), id="signing_key_id-number"),
    pytest.param(but(INTERNAL_REQUEST, signing_key_id=["a"]), id="signing_key_id-list"),
    pytest.param(but(INTERNAL_REQUEST, append="true"), id="append-string"),
    pytest.param(but(INTERNAL_REQUEST, append=1), id="append-number"),
    pytest.param([INTERNAL_REQUEST], id="array"),
]


@pytest.mark.parametrize("var", ["pk", "kek", "db", "dbx"])
def test_internal_missing_key_id(client, var):
    response = client.post(f"/secureboot/{var}",
                           json=without(INTERNAL_REQUEST, "key_id"))
    assert response.status_code == 400


@pytest.mark.parametrize("var", ["pk", "kek", "db", "dbx"])
@pytest.mark.parametrize("body", INTERNAL_INVALID)
def test_internal_invalid(client, var, body):
    response = client.post(f"/secureboot/{var}", json=body)
    assert response.status_code == 400


@pytest.mark.parametrize("var", ["pk", "kek", "db", "dbx"])
def test_no_body(client, var):
    response = client.post(f"/secureboot/{var}")
    assert response.status_code == 400


@pytest.mark.parametrize("var", ["db", "dbx"])
@pytest.mark.parametrize("body", [
    pytest.param({}, id="empty"),
    pytest.param(without(EXTERNAL_REQUEST, "esl"), id="no-esl"),
    pytest.param(without(EXTERNAL_REQUEST, "signing_key_id"), id="no-signing_key_id"),
])
def test_external_missing_required(client, var, body):
    response = client.post(f"/secureboot/{var}", json=body)
    assert response.status_code == 400


@pytest.mark.parametrize("var", ["db", "dbx"])
@pytest.mark.parametrize("body", [
    pytest.param(but(EXTERNAL_REQUEST, esl=1), id="esl-number"),
    pytest.param(but(EXTERNAL_REQUEST, esl=None), id="esl-null"),
    pytest.param(but(EXTERNAL_REQUEST, esl=""), id="esl-empty"),
    pytest.param(but(EXTERNAL_REQUEST, esl="not base64!"), id="esl-not-base64"),
    pytest.param(but(EXTERNAL_REQUEST, esl="AA==="), id="esl-bad-padding"),
    pytest.param(but(EXTERNAL_REQUEST, signing_key_id=1), id="signing_key_id-number"),
    pytest.param(but(EXTERNAL_REQUEST, signing_key_id=None), id="signing_key_id-null"),
    pytest.param(but(EXTERNAL_REQUEST, append="true"), id="append-string"),
])
def test_external_invalid(client, var, body):
    response = client.post(f"/secureboot/{var}", json=body)
    assert response.status_code == 400
