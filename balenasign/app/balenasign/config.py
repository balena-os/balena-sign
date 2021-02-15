import os

CONFIG_KEY_PREFIX = "BALENASIGN_"
API_KEY_PREFIX = "API_KEY_"


CONFIG = None


class Config(object):
    def __init__(self, api_keys):
        if not isinstance(api_keys, dict):
            raise ValueError("`api_keys` must be a dict api_key ~> user")
        self._api_keys = api_keys

    @property
    def api_keys(self):
        return self._api_keys


def load(glob=False):
    api_keys = {}

    for key, value in os.environ.items():
        if not key.startswith(CONFIG_KEY_PREFIX):
            continue

        key_noprefix = key[len(CONFIG_KEY_PREFIX):]

        if key_noprefix.startswith(API_KEY_PREFIX):
            api_key = key_noprefix[len(API_KEY_PREFIX):]
            api_keys[api_key] = value
            continue

        # Handle other config options eventually

    result = Config(api_keys=api_keys)

    if glob:
        global CONFIG
        CONFIG = result

    return result
