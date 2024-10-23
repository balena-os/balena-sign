import connexion
import logging

import config
from config import load as load_config

from gpg import new as create_gpg
from rsa import new as create_rsa
from imx import new as create_pki
from cert import new as create_cert
from secureboot import sign_pk, sign_kek, sign_db

LOG = logging.getLogger("app")


def bootstrap(body, user):
    LOG.info("%s attempting to bootstrap signing material", user)

    # Try to build list of certificates
    certificates = {}
    for cert_type in ("pk", "kek", "db", "kmod"):
        if cert_type == "db" and "db" not in body["certificates"]:
            continue

        response = create_cert(body["certificates"][cert_type], user)
        if isinstance(response, tuple):
            # Response contains an error so just propogate up to HTTP client
            return response

        certificates[cert_type] = response["cert"]

    pk_cert_id = body["certificates"]["pk"]["cert_id"]
    sign_pk({"key_id": pk_cert_id, "signing_key_id": pk_cert_id}, user)

    kek_cert_id = body["certificates"]["kek"]["cert_id"]
    sign_kek({"key_id": kek_cert_id, "signing_key_id": pk_cert_id}, user)

    if "db" in body["certificates"]:
        db_cert_id = body["certificates"]["db"]["cert_id"]
        sign_db({"key_id": db_cert_id, "signing_key_id": db_cert_id}, user)

    # Create gpg key pair
    gpg = create_gpg(body["gpg"], user)

    # Create a RSA key pair
    rsa = create_rsa(body["rsa"], user)

    # Create NXP's PKI trees
    hab = create_pki(body["hab"], user)
    ahab = create_pki(body["ahab"], user)

    LOG.info("%s bootstrapped signing service", user)

    # Return newly created signing material
    return {
        "gpg": gpg,
        "rsa": rsa,
        "hab": hab,
        "ahab": ahab,
        "certificates": certificates
    }


def create_application():
    logging.basicConfig(level=logging.INFO)
    load_config(glob=True)

    LOG.info(f"Configured to authenticate with FLEET_ID={config.CONFIG.fleet_id}")

    options = connexion.options.SwaggerUIOptions(swagger_ui=False)
    app = connexion.FlaskApp("balena sign API", specification_dir='./', swagger_ui_options=options)
    app.add_api("api.yml", swagger_ui_options=options)
    return app


application = create_application()
