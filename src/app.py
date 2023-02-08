import connexion
import logging

import config
from config import load as load_config

from gpg import new as create_gpg
from cert import new as create_cert

LOG = logging.getLogger("app")


def bootstrap(body, user):

    LOG.info("%s attempting to bootstrap signing material", user)

    # Try to build list of certificates
    certificates = {"certificates": {}}
    for cert_type in ("pk", "kek", "db", "kmod"):
        response = create_cert({
            "cert_id": body["certificates"]["ids"][cert_type],
            "subject": body["certificates"]["subject"],
            "cert_key_length": body["certificates"].get("key_length", 2048),
            },
                               user)
        if isinstance(response, tuple):
            # Response contains an error so just propogate up to HTTP client
            return response
        
        certificates["certificates"][cert_type] = response["cert"]

    # Create gpg key pair
    gpg = create_gpg(body["gpg"], user)

    LOG.info("%s bootstrapped signing service", user)

    # Return newly created signing material
    return {
        "gpg": gpg,
        "certificates": certificates
    }


def create_application():
    logging.basicConfig(level=logging.INFO)
    load_config(glob=True)

    LOG.info(f"Configured to authenticate with FLEET_ID={config.CONFIG.fleet_id}")

    app = connexion.FlaskApp("balena sign API", options={"swagger_ui": False})
    app.add_api("api.yml")
    return app.app


application = create_application()
