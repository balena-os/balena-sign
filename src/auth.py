import logging

from balena import Balena
from balena.exceptions import ApplicationNotFound

from config import CONFIG


LOG = logging.getLogger("auth")


def validate(key, fleet_id=CONFIG.fleet_id, required_scopes=None):
    balena_client = get_client(key)
    try:
        fleet = balena_client.models.application.get(fleet_id)
    except ApplicationNotFound:
        LOG.warn(f"Fleet '{fleet_id}' doesn't exist or you don't have access")
        return None

    if "app_name" not in fleet:
        LOG.warn(f"Invalid fleet '{fleet_id}'")
        return None

    user = balena_client.auth.get_user_info()

    return {"uid": user["username"]}

def get_client(key):
    balena_client = Balena()
    balena_client.auth.login_with_token(key)
    return balena_client
