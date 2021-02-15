from balenasign.config import CONFIG


def get(key, required_scopes=None):
    username = CONFIG.api_keys.get(key, None)
    if username is None:
        return None

    return {"uid": username}
