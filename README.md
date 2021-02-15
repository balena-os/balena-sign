# balenaSign

Service used to sign data over the network and retrieve the respective public
keys. The service is a rough analogy to TPM hardware - it holds private keys
that it never exposes and provides an API that lets users use them for signing.

## Setup

[![balena deploy button](https://www.balena.io/deploy.svg)](https://dashboard.balena-cloud.com/deploy?repoUrl=https://github.com/balena-os/balena-sign)

DWB deploy to balenaCloud highly recommended, nothing else has really been
tested. RPi4, Intel NUC and an x86_64 VM were used for development but there
is nothing strongly HW-specific. Any balena supported HW should therefore work
just fine even though x86 HW is likely to generally perform better due to more
crypto features implemented in hardware.

1. Deploy the app to balenaCloud.
2. Add at least one API key - this is at this moment done by setting
   an environment variable named `BALENASIGN_API_KEY_${API_KEY}` with
   a username as value. Example: `BALENASIGN_API_KEY_123456=jenkins` means
   API key `123456` will map to user `jenkins`.

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
