#!/bin/bash

SECRETS_MOUNT_POINT="/opt/balena/balenasign/secrets"

log() {
	echo "$1" >&2
}

if [ "x${BALENASIGN_LUKS_KEY}" != "x" ]; then
	log "BALENASIGN_LUKS_KEY found, expecting the secrets on a LUKS-encrypted device"

	if [ "x${BALENASIGN_LUKS_LABEL}" ]; then
		BALENASIGN_LUKS_LABEL="balena-sign-secrets"
	fi
	LUKS_DEVICE="/dev/disk/by-label/${BALENASIGN_LUKS_LABEL}"

	log "Starting udev"
	/lib/systemd/systemd-udevd -d
	udevadm trigger
	udevadm settle

	if [ ! -e "${LUKS_DEVICE}" ]; then
		log "BALENASIGN_LUKS_KEY is defined but corresponding LUKS device labelled '${BALENASIGN_LUKS_LABEL}' does not exist"
		log "You must either plug in the device with secrets or unset the BALENASIGN_LUKS_KEY variable"
		exit 1
	fi

	DM_DEVICE_NAME="luks-${BALENASIGN_LUKS_LABEL}"
	DM_DEVICE="/dev/mapper/${DM_DEVICE_NAME}"

	if cryptsetup status "${DM_DEVICE_NAME}" >/dev/null 2>&1; then
		log "It looks like the LUKS device is already unsealed, skipping"
	else
		log "Unsealing the LUKS device"
		echo -n "${BALENASIGN_LUKS_KEY}" | cryptsetup luksOpen "${LUKS_DEVICE}" "${DM_DEVICE_NAME}" --key-file -
	fi

	if [ -e "${DM_DEVICE}" ]; then
		log "It looks like the DM device exists, skipping..."
	else
		log "Creating the DM device"
		/etc/init.d/cryptdisks start
	fi

	if mount | grep -q "^${DM_DEVICE}"; then
		log "It looks like the secrets storage is already mounted, skipping..."
		exit 0
	fi

	log "Mounting the secrets storage"
	if ! mount "${DM_DEVICE}" "${SECRETS_MOUNT_POINT}"; then
		log "Failed to mount the storage with secrets"
		exit 2
	fi
fi

gunicorn -k uvicorn.workers.UvicornWorker -u balenasign -g balenasign --chdir /opt/balena/balenasign --workers 4 --bind 0.0.0.0:8080 app:application
