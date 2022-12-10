from balena import Balena 
from balena.exceptions import ApplicationNotFound

from balenasign.config import CONFIG

def validate(key, fleet_id=CONFIG.fleet_id, required_scopes=None):
    balena_client = get_client(key, CONFIG.api_domain)
    try:
        if 'app_name' not in balena_client.models.application.get_by_id(fleet_id):
            raise Exception("Unexpected response from fetching application data. Maybe you don't have access ?")
    except (ApplicationNotFound, Exception):
        return None

    return {"uid": balena_client.auth.who_am_i()}

def get_client(key, domain):
    balena_client = Balena()
    balena_client.settings.set(key="api_domain", value=domain)
    balena_client.auth.login_with_token(key)
    return balena_client
