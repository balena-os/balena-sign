import base64
import datetime
import hashlib
import struct
import subprocess
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# See the UEFI specification, "Variable Services" and "Signature Database"
EFI_GLOBAL_VARIABLE = uuid.UUID("8be4df61-93ca-11d2-aa0d-00e098032b8c")
EFI_IMAGE_SECURITY_DATABASE_GUID = uuid.UUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f")
EFI_CERT_TYPE_PKCS7_GUID = uuid.UUID("4aafd29d-68df-49ee-8aa9-347d375665a7")
EFI_CERT_X509_GUID = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
EFI_CERT_SHA256_GUID = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328")

VENDOR_GUIDS = {
    "PK": EFI_GLOBAL_VARIABLE,
    "KEK": EFI_GLOBAL_VARIABLE,
    "db": EFI_IMAGE_SECURITY_DATABASE_GUID,
    "dbx": EFI_IMAGE_SECURITY_DATABASE_GUID,
}

# NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS
# | TIME_BASED_AUTHENTICATED_WRITE_ACCESS
EFI_VARIABLE_ATTRIBUTES = 0x27
EFI_VARIABLE_APPEND_WRITE = 0x40

WIN_CERT_REVISION_2_0 = 0x0200
WIN_CERT_TYPE_EFI_GUID = 0x0ef1

# ESLs of image hashes as sent by the balenaOS build, one ESL per hash
HASH_OWNER = uuid.UUID("605dab50-e046-4300-abb6-3dd810dd8b23")
LOADER_HASH = hashlib.sha256(b"balenaSign test loader").digest()
KERNEL_HASH = hashlib.sha256(b"balenaSign test kernel").digest()

TIMESTAMP_TOLERANCE = datetime.timedelta(minutes=5)

# DER encoding of OID 1.2.840.113549.1.7.2 (PKCS#7 signedData)
OID_PKCS7_SIGNED_DATA = bytes.fromhex("06092a864886f70d010702")


def hash_esl(digest):
    signature_size = 16 + len(digest)
    header = EFI_CERT_SHA256_GUID.bytes_le + struct.pack(
        "<III", 28 + signature_size, 0, signature_size)
    return header + HASH_OWNER.bytes_le + digest


def parse_esl(esl):
    entries = []
    offset = 0
    while offset < len(esl):
        signature_type = uuid.UUID(bytes_le=esl[offset:offset + 16])
        list_size, header_size, signature_size = struct.unpack(
            "<III", esl[offset + 16:offset + 28])
        entry = offset + 28 + header_size
        while entry < offset + list_size:
            owner = uuid.UUID(bytes_le=esl[entry:entry + 16])
            data = esl[entry + 16:entry + signature_size]
            entries.append((signature_type, owner, data))
            entry += signature_size
        offset += list_size
    assert offset == len(esl)
    return entries


def parse_efi_time(data):
    year, month, day, hour, minute, second = struct.unpack("<HBBBBB", data[:7])
    return datetime.datetime(year, month, day, hour, minute, second,
                             tzinfo=datetime.timezone.utc)


def der_length(length):
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def parse_auth(auth):
    # EFI_VARIABLE_AUTHENTICATION_2: EFI_TIME, then WIN_CERTIFICATE_UEFI_GUID
    # with a PKCS#7 SignedData, followed by the ESL itself.
    timestamp = auth[:16]
    length, revision, cert_type = struct.unpack("<IHH", auth[16:24])
    assert revision == WIN_CERT_REVISION_2_0
    assert cert_type == WIN_CERT_TYPE_EFI_GUID
    assert uuid.UUID(bytes_le=auth[24:40]) == EFI_CERT_TYPE_PKCS7_GUID

    signed_data = auth[40:16 + length]
    # UEFI carries a bare SignedData, wrap it in a ContentInfo for openssl
    body = OID_PKCS7_SIGNED_DATA + bytes([0xa0]) + \
        der_length(len(signed_data)) + signed_data
    content_info = bytes([0x30]) + der_length(len(body)) + body

    return timestamp, content_info, auth[16 + length:]


def verify_auth(tmp_path, auth, var, cert, append=False):
    timestamp, content_info, esl = parse_auth(auth)

    attributes = EFI_VARIABLE_ATTRIBUTES
    if append:
        attributes |= EFI_VARIABLE_APPEND_WRITE
    signed = var.encode("utf-16-le") + VENDOR_GUIDS[var].bytes_le + \
        struct.pack("<I", attributes) + timestamp + esl

    cert_path = tmp_path / "cert.pem"
    content_path = tmp_path / "content"
    signature_path = tmp_path / "signature.der"
    cert_path.write_text(cert)
    content_path.write_bytes(signed)
    signature_path.write_bytes(content_info)

    cmd = [
        "openssl", "cms", "-verify", "-binary", "-inform", "DER",
        "-in", str(signature_path), "-content", str(content_path),
        "-certfile", str(cert_path), "-CAfile", str(cert_path),
        "-purpose", "any", "-out", "/dev/null",
    ]
    return subprocess.run(cmd, capture_output=True).returncode == 0


def cert_der(cert):
    certificate = x509.load_pem_x509_certificate(cert.encode())
    return certificate.public_bytes(serialization.Encoding.DER)


def create_cert(client, name):
    cert_id = f"test-{name}-{uuid.uuid4()}"
    response = client.post("/cert", json={
        "cert_id": cert_id,
        "subject": f"/CN=balenaSign test {name}/",
    })
    assert response.status_code == 200
    return cert_id, response.json()["cert"]


@pytest.fixture(scope="module")
def pk(client):
    cert_id, cert = create_cert(client, "PK")
    response = client.post("/secureboot/pk", json={"key_id": cert_id})
    assert response.status_code == 200
    return cert_id, cert


@pytest.fixture(scope="module")
def kek(client, pk):
    cert_id, cert = create_cert(client, "KEK")
    response = client.post("/secureboot/kek", json={
        "key_id": cert_id,
        "signing_key_id": pk[0],
    })
    assert response.status_code == 200
    return cert_id, cert


@pytest.fixture(scope="module")
def db(client):
    cert_id, cert = create_cert(client, "db")
    response = client.post("/secureboot/db", json={"key_id": cert_id})
    assert response.status_code == 200
    return cert_id, cert


def check_signed_esl(tmp_path, response, var, certs, signing_cert):
    assert response.status_code == 200
    body = response.json()
    auth = base64.b64decode(body[var.lower()])
    esl = base64.b64decode(body["esl"])

    timestamp, _, signed_esl = parse_auth(auth)
    assert signed_esl == esl
    now = datetime.datetime.now(datetime.timezone.utc)
    assert abs(parse_efi_time(timestamp) - now) < TIMESTAMP_TOLERANCE

    # The response lists certificates sorted by their IDs
    ders = [cert_der(cert) for _, cert in sorted(certs)]
    assert [base64.b64decode(der) for der in body["der"]] == ders
    entries = parse_esl(esl)
    assert sorted(data for _, _, data in entries) == sorted(ders)
    assert all(t == EFI_CERT_X509_GUID for t, _, _ in entries)

    assert verify_auth(tmp_path, auth, var, signing_cert)
    # The signature covers the variable name, so it can't be reused elsewhere
    other_var = "KEK" if var == "PK" else "PK"
    assert not verify_auth(tmp_path, auth, other_var, signing_cert)


def test_pk(anonymous_client, tmp_path, pk):
    response = anonymous_client.get(f"/secureboot/pk/{pk[0]}")
    check_signed_esl(tmp_path, response, "PK", [pk], pk[1])


def test_kek(anonymous_client, tmp_path, pk, kek):
    response = anonymous_client.get(f"/secureboot/kek/{kek[0]}")
    check_signed_esl(tmp_path, response, "KEK", [kek], pk[1])

    auth = base64.b64decode(response.json()["kek"])
    assert not verify_auth(tmp_path, auth, "KEK", kek[1])


def test_db(anonymous_client, tmp_path, db):
    response = anonymous_client.get(f"/secureboot/db/{db[0]}")
    check_signed_esl(tmp_path, response, "db", [db], db[1])


def test_db_list(client, anonymous_client, tmp_path, kek):
    certs = [create_cert(client, f"db{n}") for n in range(2)]
    cert_ids = [cert_id for cert_id, _ in certs]
    response = client.post("/secureboot/db", json={
        "key_id": cert_ids,
        "signing_key_id": kek[0],
    })
    assert response.status_code == 200

    response = anonymous_client.get(f"/secureboot/db/{','.join(cert_ids)}")
    check_signed_esl(tmp_path, response, "db", certs, kek[1])


@pytest.mark.xfail(strict=True, reason="cached per-cert ESLs are dropped, see TODO")
def test_db_list_reused_cert(client, anonymous_client, tmp_path, kek, db):
    # db's own ESL already exists, so building this list must reuse it
    certs = [db, create_cert(client, "db-new")]
    cert_ids = [cert_id for cert_id, _ in certs]
    response = client.post("/secureboot/db", json={
        "key_id": cert_ids,
        "signing_key_id": kek[0],
    })
    assert response.status_code == 200

    response = anonymous_client.get(f"/secureboot/db/{','.join(cert_ids)}")
    check_signed_esl(tmp_path, response, "db", certs, kek[1])


@pytest.mark.xfail(strict=True, reason="list key_id breaks default signing key, see TODO")
def test_db_list_default_signing_key(client):
    cert_ids = [create_cert(client, f"db-self{n}")[0] for n in range(2)]
    response = client.post("/secureboot/db", json={"key_id": cert_ids})
    assert response.status_code == 200


@pytest.mark.parametrize("var", ["db", "dbx"])
@pytest.mark.parametrize("append", [False, True])
@pytest.mark.parametrize("esl", [
    pytest.param(hash_esl(LOADER_HASH), id="loader"),
    pytest.param(hash_esl(KERNEL_HASH), id="kernel"),
    pytest.param(hash_esl(LOADER_HASH) + hash_esl(KERNEL_HASH), id="both"),
])
def test_external_esl(client, tmp_path, kek, var, append, esl):
    response = client.post(f"/secureboot/{var}", json={
        "esl": base64.b64encode(esl).decode(),
        "signing_key_id": kek[0],
        "append": append,
    })
    assert response.status_code == 200
    auth = base64.b64decode(response.json()["auth"])

    _, _, signed_esl = parse_auth(auth)
    assert signed_esl == esl

    assert verify_auth(tmp_path, auth, var, kek[1], append=append)
    assert not verify_auth(tmp_path, auth, var, kek[1], append=not append)
