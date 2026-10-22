PYTHON ?= python3
VENV ?= venv
TESTVENV ?= testvenv
HOST ?= 127.0.0.1
PORT ?= 8080
WORKERS ?= 1
EFI_BINARY ?= /usr/lib/systemd/boot/efi/systemd-bootx64.efi

.PHONY: venv testvenv run check clean

venv: $(VENV)/.installed

$(VENV)/.installed: requirements.txt
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -r requirements.txt
	touch $@

testvenv: $(TESTVENV)/.installed

$(TESTVENV)/.installed: requirements.txt requirements-test.txt
	$(PYTHON) -m venv $(TESTVENV)
	$(TESTVENV)/bin/pip install --upgrade pip
	$(TESTVENV)/bin/pip install -r requirements.txt -r requirements-test.txt
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
	BALENASIGN_TEST_EFI_BINARY=$(EFI_BINARY) $(TESTVENV)/bin/pytest -v tests

clean:
	rm -rf $(VENV) $(TESTVENV)
