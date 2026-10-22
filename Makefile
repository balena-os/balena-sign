PYTHON ?= python3
VENV ?= venv
HOST ?= 127.0.0.1
PORT ?= 8080
WORKERS ?= 1

.PHONY: venv run clean

venv: $(VENV)/.installed

$(VENV)/.installed: requirements.txt
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -r requirements.txt
	touch $@

# Mirrors the gunicorn invocation in start.sh, minus the user/group switch.
# Runs from the repo root so connexion finds api.yml, with src on the path.
run: venv
	@test -n "$${FLEET_ID}$${BALENA_APP_ID}" || { echo "FLEET_ID must be set, e.g. make run FLEET_ID=123" >&2; exit 1; }
	mkdir -p src/secrets/gpg src/secrets/x509
	chmod 0700 src/secrets/gpg
	$(VENV)/bin/gunicorn -k uvicorn.workers.UvicornWorker \
		--pythonpath src --workers $(WORKERS) --bind $(HOST):$(PORT) app:application

clean:
	rm -rf $(VENV)
