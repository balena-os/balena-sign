import base64
import subprocess
import uuid

import pytest


def create_cert(client):
    cert_id = f"test-efi-{uuid.uuid4()}"
    response = client.post("/cert", json={
        "cert_id": cert_id,
        "subject": "/CN=balenaSign test EFI certificate/",
    })
    assert response.status_code == 200
    return cert_id, response.json()["cert"]


def sbverify(*args):
    return subprocess.run(["sbverify", *map(str, args)],
                          capture_output=True, text=True)


@pytest.fixture(scope="module")
def cert(client):
    return create_cert(client)


@pytest.fixture(scope="module")
def signed(client, cert, efi_binary):
    cert_id, _ = cert
    response = client.post("/secureboot/efi", json={
        "key_id": cert_id,
        "payload": base64.b64encode(efi_binary).decode(),
    })
    assert response.status_code == 200
    return base64.b64decode(response.json()["signed"])


@pytest.fixture
def cert_path(tmp_path, cert):
    path = tmp_path / "cert.pem"
    path.write_text(cert[1])
    return path


def test_unsigned_binary(tmp_path, cert_path, efi_binary):
    unsigned_path = tmp_path / "unsigned.efi"
    unsigned_path.write_bytes(efi_binary)

    assert "No signature table present" in sbverify("--list", unsigned_path).stderr
    assert sbverify("--cert", cert_path, unsigned_path).returncode != 0


def test_sign(tmp_path, cert_path, signed):
    signed_path = tmp_path / "signed.efi"
    signed_path.write_bytes(signed)

    listing = sbverify("--list", signed_path).stdout
    assert [line for line in listing.splitlines()
            if line.startswith("signature ")] == ["signature 1"]

    result = sbverify("--cert", cert_path, signed_path)
    assert result.returncode == 0, result.stderr


def test_sign_other_cert(client, tmp_path, signed):
    _, other_cert = create_cert(client)
    other_cert_path = tmp_path / "other.pem"
    other_cert_path.write_text(other_cert)
    signed_path = tmp_path / "signed.efi"
    signed_path.write_bytes(signed)

    assert sbverify("--cert", other_cert_path, signed_path).returncode != 0


def test_sign_tampered(tmp_path, cert_path, signed, efi_binary):
    # The middle of the original image is covered by the signature
    tampered = bytearray(signed)
    tampered[len(efi_binary) // 2] ^= 0xff
    tampered_path = tmp_path / "tampered.efi"
    tampered_path.write_bytes(tampered)

    assert sbverify("--cert", cert_path, tampered_path).returncode != 0
