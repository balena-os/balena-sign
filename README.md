# balenaSign

Service used to sign data over the network and retrieve the respective public
keys. The service is a rough analogy to TPM hardware - it holds private keys
that it never exposes and provides an API that lets users use them for signing.

## Authorization

Balena sign uses balenaCloud as the authentication backend. Authorization is controlled by specifying a `FLEET_ID` environment variable. This value enforces that the balenaCloud API key provided must have permissions (operator/developer/etc) access to that fleet to be authorized with this application.

API Keys are handled by passing them in the `X-API-KEY` header like in the follow httpie request:

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
curl -X POST -H "X-API-Key: XXX" -H "Content-type: application/json" -d '{
  "gpg": {"name_real": "balenaOS GRUB GPG key", "name_email": "security@balena.io"},
  "certificates": {
    "pk": {"cert_id": "balenaos-PK", "subject": "/CN=balenaOS PK/"},
    "kek": {"cert_id": "balenaos-KEK", "subject": "/CN=balenaOS KEK/"},
    "db": {"cert_id": "balenaos-db", "subject": "/CN=balenaOS db/"},
    "kmod": {"cert_id": "balenaos-kmod", "subject": "/CN=key for signing 3rd party balenaOS kernel modules/", "key_length": 4096}
  }
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
