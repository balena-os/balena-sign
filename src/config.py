import re
import os

DEFAULT_DOMAIN = "balena-cloud.com"

CONFIG = None


class Config(object):
    def __init__(self, balena_domain, fleet_id):
        if not is_domain(balena_domain):
            raise ValueError(
                f"`balena_domain` value: '{balena_domain}' is not a valid domain")
        if not fleet_id.isdigit():
            raise ValueError(
                f"`fleet_id` value: '{fleet_id}' is not a valid fleet ID.")
        self._balena_domain = balena_domain

        # note: the balena sdk uses the fleet id type to distinguish between using a lookup by
        #       slug name (in case of string) or id (in case of int), so we need to cast it to int
        self._fleet_id = int(fleet_id)

    @property
    def balena_domain(self):
        return self._balena_domain

    @property
    def fleet_id(self):
        return self._fleet_id


def is_domain(value):
    domain_regex = r'^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$'
    return bool(re.match(domain_regex, value))


def load(glob=False):
    balena_domain = os.environ.get("BALENA_DOMAIN", DEFAULT_DOMAIN)
    fleet_id = os.environ.get("FLEET_ID")

    if not fleet_id:
        raise ValueError("`FLEET_ID` env var cannot be empty!")

    result = Config(balena_domain, fleet_id)

    if glob:
        global CONFIG
        CONFIG = result

    return result
