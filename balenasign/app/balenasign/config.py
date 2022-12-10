import re
import os

DEFAULT_API_DOMAIN = "api.balena-cloud.com"

CONFIG = None


class Config(object):
    def __init__(self, api_domain, fleet_id):
        if not is_domain(api_domain):
            raise ValueError(
                f"`api_domain` value: '{api_domain}' is not a valid domain")
        if not fleet_id.isdigit():
            raise ValueError(
                f"`fleet_id` value: '{fleet_id}' is not a valid fleet ID.")
        self._api_domain = api_domain
        self._fleet_id = fleet_id

    @property
    def api_domain(self):
        return self._api_domain

    @property
    def fleet_id(self):
        return self._fleet_id


def is_domain(value):
    domain_regex = r'^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$'
    return bool(re.match(domain_regex, value))


def load(glob=False):
    api_domain = os.environ.get("BALENA_API_DOMAIN", DEFAULT_API_DOMAIN)
    fleet_id = os.environ.get("FLEET_ID")

    if not fleet_id:
        raise ValueError("`FLEET_ID` env var cannot be empty!")

    result = Config(api_domain, fleet_id)

    if glob:
        global CONFIG
        CONFIG = result

    return result
