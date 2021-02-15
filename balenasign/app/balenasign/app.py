import connexion
import logging

import balenasign.config
from balenasign.config import load as load_config
from balenasign.utils import init_logging


LOG = logging.getLogger("app")


def create_application():
    load_config(glob=True)
    init_logging()

    LOG.info("Loaded %d API keys", len(balenasign.config.CONFIG.api_keys))

    app = connexion.FlaskApp("balena sign API", options={"swagger_ui": False})
    app.add_api("api.yml")
    return app.app

application = create_application()
