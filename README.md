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

## PKC keys

Additional public key cryptography key types (e.g. for NVIDIA Jetson secure
boot) can be created with `POST /pkc/key`. The only supported `key_type` is
currently `rsa3072`.
```
curl -X POST ${SIGNING_SERVER_URL}/pkc/key \
             -H "X-API-Key: XXX" \
             -H "Content-type: application/json" \
             -d '{"key_type": "rsa3072"}'
```

The response contains the key `fingerprint`, which can be used to fetch the
PEM public key with `GET /pkc/key/{fingerprint}`. `GET /pkc/keys` lists all
available PKC keys.

The existing `/rsa/*` endpoints are unchanged and still create RSA-2048 keys.

### Signing NVIDIA Jetson Orin boot binaries

`POST /pkc/sign` signs a payload with a PKC key using RSA-PSS with a 32 byte
salt and SHA-512 (default) or SHA-256, the scheme used by NVIDIA Jetson secure
boot. The signature is returned base64-encoded in big-endian byte order.

The whole Jetson Linux (L4T) image preparation stays on the build machine,
only the signing operations are sent to balenaSign through the L4T HSM hooks:

1. Replace Linux_for_Tegra/bootloader/tegrasign_v3_softhsm.py with the custom one which
   performs API calls to the signing server
2. Create a configuration file on the host, in `/etc/balenasign/jetson.json` (or to the path in
   the `BALENASIGN_CONFIG` environment variable), readable only by the user
   running the build (`chmod 600`):
   ```
   {"url": "https://sign.example.com", "api_key": "XXX", "pkc_key_id": "<fingerprint>"}
   ```
3. Fetch the PKC public key from the server and save it out side of Linux_for_Tegra/bootloader,
   i.e in ~/keys/pkc_pub.pem`

4. Export the path to the jetson.json file as well as the variables defined for the hardware type (BOARDID,
   CHIP_SKU, BOARD_REV and FAB) and then trigger the creation of the QSPI images:
   cd Linux_for_Tegra/
   # These board variables were obtained from a Jetson Orin Nano 8GB SD-CARD module
   sudo env PATH="$HOME/l4t-venv/bin:$PATH" BALENASIGN_CONFIG="$BALENASIGN_CONFIG" \
       BOARDID=3767 FAB=300 BOARDSKU=0005 BOARDREV=V.2 CHIP_SKU=00:00:00:D5 \
       NO_RECOVERY_IMG=1 NO_ESP_IMG=1 NO_ROOTFS=1 \
       ./tools/kernel_flash/l4t_create_images_for_kernel_flash.sh \
       --qspi-only --hsm -u ~/keys/pkc_pub.pem\
       -p "-c $PWD/bootloader/generic/cfg/flash_t234_qspi.xml" \
       jetson-orin-nano-devkit-super internal


Only PKC signing is supported, encryption (SBK, OEM_K1/EKB) is not.

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
