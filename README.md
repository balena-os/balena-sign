# balenaSign

Service used to sign data over the network and retrieve the respective public
keys. The service is a rough analogy to TPM hardware - it holds private keys
that it never exposes and provides an API that lets users use them for signing.

## Authorization

Balena sign uses balenaCloud as the authentication backend. Authorization is controlled by specifying a `FLEET_ID` environment variable. This value enforces that the balenaCloud API key provided must have permissions (operator/developer/etc) access to that fleet to be authorized with this application.

API Keys are handled by passing them in the `X-API-KEY` header like in the following http request:

```
http POST 10.0.0.13/gpg/keys \
  "Content-Type: application/json" \
  "X-API-KEY: $AUTH" <-- your balenaCloud api token
  ...
```

## Setup

[![balena deploy button](https://www.balena.io/deploy.svg)](https://dashboard.balena-cloud.com/deploy?repoUrl=https://github.com/balena-os/balena-sign)

DWB deploy to balenaCloud highly recommended, nothing else has really been
tested. RPi4, Intel NUC and an x86_64 VM were used for development but there
is nothing strongly HW-specific. Any balena supported HW should therefore work
just fine even though x86 HW is likely to generally perform better due to more
crypto features implemented in hardware.

1. Deploy the app to balenaCloud.
2. Set the `FLEED_ID` environment variable for balena-sign to check for authentication.

You can bootstrap all the secrets necessary for integration with balenaOS yocto build using a single bootstrap command:
```
curl -X POST ${SIGNING_SERVER_URL}/bootstrap \
             -H "X-API-Key: XXX" \
             -H "Content-type: application/json" \
             -d '{
  "gpg": {"name_real": "balenaOS GRUB GPG key", "name_email": "security@balena.io"},
  "certificates": {
    "pk": {"cert_id": "balenaos-pk", "subject": "/CN=balenaOS PK/"},
    "kek": {"cert_id": "balenaos-kek", "subject": "/CN=balenaOS KEK/"},
    "db": {"cert_id": "balenaos-db", "subject": "/CN=balenaOS db/"},
    "kmod": {"cert_id": "balenaos-kmod", "subject": "/CN=key for signing 3rd party balenaOS kernel modules/", "key_length": 4096}
  },
  "rsa": {},
  "hab": {"hab_type": "hab"},
  "ahab": {"hab_type": "ahab"}
}'
```

`db` is optional, if you are using hashes for authentication, you do not need the `db` certificate and you can omit it.

## Configuration

Specify the fleet that the provided `X-API-KEY` value has access to by setting a `FLEET_ID` to the ID of the fleet.

### Optional

It is possible to use an external LUKS-encrypted device (e.g. USB stick)
as the secrets storage. The device has to be pre-populated elsewhere, balenaSign
itself has no support for formatting or initializing it (as for now). The device
will be identified by a filesystem (in this case LUKS) label, the default is
`balena-sign-secrets` and can be overriden by `BALENASIGN_LUKS_LABEL` env
variable. The passphrase for the device must be set in a `BALENASIGN_LUKS_KEY`
env variable. The unlocked DM device must be mountable by balenaOS, just use
ext4 if unsure. It must hold two directories: `gpg` and `x509`, both owned
and by user:group `999:999` which will map to `balenasign:balenasign`
within the app. The `gpg` directory must also have `0700` access rights set.

## Development
* download [IMX CST TOOL](https://www.nxp.com/webapp/Download?colCode=IMX_CST_TOOL) from NXP
* place the tool into the `cst` directory
* adjust build ARGs in `Dockerfile.template` if required

### Running the tests

The test suite starts the real server (gunicorn with 4 workers) on a free
port on `127.0.0.1`, in a throwaway directory laid out like the Docker image,
and talks to it over HTTP. Authentication is checked live against
balenaCloud, so the tests need network access to `api.balena-cloud.com` and
a balenaCloud API key with access to a fleet:

```
export FLEET_ID=<fleet ID>
export BALENASIGN_API_KEY=<balenaCloud API key>
make check
```

`make check` creates the `testvenv` virtualenv from `requirements.txt` and
`requirements-test.txt`, then runs `pytest tests`. `make testvenv` only sets
up the virtualenv and `make clean` removes it.

The server shells out to a number of tools, which must be installed on the
test machine. On Debian:

```
apt install gnupg openssl sbsigntool efitools systemd-boot-efi linux-kbuild-<version>
```

* `gpg` needs a working `gpg-agent`.
* `sign-file`, used to sign kernel modules, must be on `PATH`. Debian ships
  it in `/usr/lib/linux-kbuild-<version>/scripts`, where `<version>` is the
  full kernel package version, e.g.
  `PATH=$PATH:/usr/lib/linux-kbuild-6.12.111+deb13/scripts make check`.
* The UEFI binary signing tests need an unsigned UEFI binary. The default is
  `/usr/lib/systemd/boot/efi/systemd-bootx64.efi` from `systemd-boot-efi`;
  use the `EFI_BINARY` make variable to pick another one. It must not be an
  already signed `*.efi.signed` binary.

The i.MX tests need the NXP Code Signing Tool tarball, see
[Development](#development). Download it from
[NXP](https://www.nxp.com/webapp/Download?colCode=IMX_CST_TOOL_NEW&location=null)
and place it at `cst/cst-<version>.tgz`, or point the `CST_TARBALL` make
variable at it. The expected version and MD5 checksum are read from
`Dockerfile.template`. `make testvenv` verifies the checksum and unpacks the
prebuilt binaries into `testvenv/cst`, so no build is needed, but they are
x86_64 only.

The import/export tests start two more servers. The first is bootstrapped,
exported and wiped. The second starts empty and imports the export, and all
the bootstrap checks are then run against it.

Tests marked `xfail` document known bugs and are expected to fail until the
bug is fixed.

> **Note:** the server stores the API key in plaintext in its
> `.balena/balena.cfg`, which ends up in pytest's temporary directory
> (pytest keeps the last 3 runs). Remove it after running the tests, by
> default it's `/tmp/pytest-of-$USER`.
