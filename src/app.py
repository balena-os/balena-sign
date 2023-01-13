import connexion
import logging

import config
from config import load as load_config

LOG = logging.getLogger("app")

def create_application():
    logging.basicConfig(level=logging.INFO)
    load_config(glob=True)

    LOG.info(
        f"Configured to authenticate with FLEET_ID={config.CONFIG.fleet_id}"
    )

    app = connexion.FlaskApp("balena sign API", options={"swagger_ui": False})
    app.add_api("api.yml")
    return app.app


application = create_application()
