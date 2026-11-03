import base64
import io
import os
import shutil
import tarfile

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from helpers import Client
from test_bootstrap import REQUEST, cert_id, certs  # noqa: F401
# Run all the bootstrap checks again, this time against the server the
# bootstrapped secrets were imported into, see the fixtures below.
from test_bootstrap import (  # noqa: F401
    test_certificate, test_db, test_db_signs_efi, test_gpg, test_hab_signs_csf,
    test_kek, test_kek_signs_esl, test_kmod, test_pk, test_pki, test_response,
    test_rsa)

PASSPHRASE = "balenaSignTestPassphrase"


def encrypt(data, passphrase):
    # Same scheme as aes.encrypt on the server
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=100000)
    key = base64.b64encode(kdf.derive(passphrase.encode()))
    return {
        "data": Fernet(key).encrypt(data).decode(),
        "salt": base64.b64encode(salt).decode(),
    }


def archive(files):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as tar:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return data.getvalue()


@pytest.fixture(scope="module")
def source(tmp_path_factory, server_factory, api_key, cst_dir):
    """
    Bootstraps a server, exports its secrets and wipes it.
    """
    base_dir = tmp_path_factory.mktemp("balenasign-source")
    with server_factory(base_dir) as url:
        client = Client(url, api_key)
        response = client.post("/bootstrap", json=REQUEST)
        assert response.status_code == 200
        bootstrap = response.json()

        response = client.post("/export", json={"key": PASSPHRASE})
        assert response.status_code == 200
        exported = response.json()
    shutil.rmtree(base_dir)

    return bootstrap, exported


@pytest.fixture(scope="module")
def imported_server(tmp_path_factory, server_factory, api_key, source):
    with server_factory(tmp_path_factory.mktemp("balenasign-imported")) as url:
        client = Client(url, api_key)
        assert client.get("/gpg/keys").json()["keys"] == []
        assert client.get(f"/cert/{cert_id('pk')}").status_code == 404

        _, exported = source
        response = client.post("/import", json={"key": PASSPHRASE, **exported})
        assert response.status_code == 204
        yield url


@pytest.fixture(scope="module")
def client(imported_server, api_key):
    return Client(imported_server, api_key)


@pytest.fixture(scope="module")
def anonymous_client(imported_server):
    return Client(imported_server)


@pytest.fixture(scope="module")
def bootstrap(source):
    return source[0]


def test_export_response(source):
    _, exported = source
    assert sorted(exported) == ["data", "salt"]


def test_import_wrong_passphrase(client, source):
    _, exported = source
    response = client.post("/import", json={"key": PASSPHRASE + "x", **exported})
    assert response.status_code == 401


@pytest.fixture(scope="module")
def scratch_server(tmp_path_factory, server_factory, api_key):
    base_dir = tmp_path_factory.mktemp("balenasign-scratch")
    with server_factory(base_dir) as url:
        yield Client(url, api_key), base_dir


def import_archive(client, files):
    return client.post("/import", json={
        "key": PASSPHRASE,
        **encrypt(archive(files), PASSPHRASE),
    })


@pytest.mark.xfail(strict=True, reason="archive isn't flushed before reading, see TODO")
def test_import_small_archive(scratch_server):
    client, base_dir = scratch_server
    response = import_archive(client, {"x509/test-small.txt": b"small\n"})
    assert response.status_code == 204
    assert (base_dir / "app" / "secrets" / "x509" / "test-small.txt").exists()


@pytest.mark.xfail(strict=True, reason="import extracts outside of the vault, see TODO")
def test_import_path_traversal(scratch_server):
    client, base_dir = scratch_server
    import_archive(client, {
        # Large enough to get past the unflushed write buffer
        "padding": os.urandom(64 * 1024),
        "../test-traversal.txt": b"outside of the vault\n",
    })
    assert not (base_dir / "app" / "test-traversal.txt").exists()
