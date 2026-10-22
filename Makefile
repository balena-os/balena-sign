PYTHON ?= python3
VENV ?= venv
TESTVENV ?= testvenv
HOST ?= 127.0.0.1
PORT ?= 8080
WORKERS ?= 1
EFI_BINARY ?= /usr/lib/systemd/boot/efi/systemd-bootx64.efi
# NXP's Code Signing Tool, version and checksum come from Dockerfile.template
DOCKERFILE_ARG = $(shell sed -n 's/^ARG $(1)=//p' Dockerfile.template | head -1)
CST_VERSION ?= $(call DOCKERFILE_ARG,CST_VERSION)
CST_TARBALL ?= cst/cst-$(CST_VERSION).tgz
CST_TARBALL_CKSUM ?= $(call DOCKERFILE_ARG,CST_TARBALL_CKSUM)

.PHONY: venv testvenv run check clean

venv: $(VENV)/.installed

$(VENV)/.installed: requirements.txt
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -r requirements.txt
	touch $@

testvenv: $(TESTVENV)/.installed $(TESTVENV)/cst/.installed

$(TESTVENV)/.installed: requirements.txt requirements-test.txt
	$(PYTHON) -m venv $(TESTVENV)
	$(TESTVENV)/bin/pip install --upgrade pip
	$(TESTVENV)/bin/pip install -r requirements.txt -r requirements-test.txt
	touch $@

# The tarball comes with prebuilt binaries, so just unpack what the app uses.
# The wildcard keeps a missing tarball from failing before the hint below.
$(TESTVENV)/cst/.installed: $(wildcard $(CST_TARBALL))
	@test -n "$(CST_VERSION)" -a -n "$(CST_TARBALL_CKSUM)" || { echo "Failed to read CST_VERSION and CST_TARBALL_CKSUM from Dockerfile.template" >&2; exit 1; }
	@test -f "$(CST_TARBALL)" || { echo "$(CST_TARBALL) not found, please download the CST tool from https://www.nxp.com/webapp/Download?colCode=IMX_CST_TOOL_NEW&location=null" >&2; exit 1; }
	@test "$$(md5sum "$(CST_TARBALL)" | cut -d' ' -f1)" = "$(CST_TARBALL_CKSUM)" || { echo "Invalid checksum for $(CST_TARBALL) - expecting $(CST_TARBALL_CKSUM)" >&2; exit 1; }
	rm -rf $(TESTVENV)/cst
	mkdir -p $(TESTVENV)/cst
	tar -xzf $(CST_TARBALL) -C $(TESTVENV)/cst --strip-components=1 \
		--wildcards '*/linux64/bin/*' '*/keys/*' '*/ca/*'
	touch $@

# Mirrors the gunicorn invocation in start.sh, minus the user/group switch.
# Runs from the repo root so connexion finds api.yml, with src on the path.
run: venv
	@test -n "$${FLEET_ID}$${BALENA_APP_ID}" || { echo "FLEET_ID must be set, e.g. make run FLEET_ID=123" >&2; exit 1; }
	mkdir -p src/secrets/gpg src/secrets/x509
	chmod 0700 src/secrets/gpg
	$(VENV)/bin/gunicorn -k uvicorn.workers.UvicornWorker \
		--pythonpath src --workers $(WORKERS) --bind $(HOST):$(PORT) app:application

check: testvenv
	BALENASIGN_TEST_EFI_BINARY=$(EFI_BINARY) \
		BALENASIGN_TEST_CST_DIR=$(abspath $(TESTVENV)/cst) \
		$(TESTVENV)/bin/pytest -v tests

clean:
	rm -rf $(VENV) $(TESTVENV)
