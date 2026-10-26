import subprocess

import requests


class Client(object):
    def __init__(self, base_url, api_key=None):
        self.base_url = base_url
        self.session = requests.Session()
        if api_key is not None:
            self.session.headers["X-API-Key"] = api_key

    def request(self, method, path, **kwargs):
        return self.session.request(method, self.base_url + path, **kwargs)

    def get(self, path, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path, **kwargs):
        return self.request("POST", path, **kwargs)


def without(request, field):
    return {k: v for k, v in request.items() if k != field}


def but(request, **fields):
    return dict(request, **fields)


def kill_gpg_agent(homedir):
    # gpg starts gpg-agent as a daemon, which outlives whoever used the keyring
    subprocess.run(["gpgconf", "--homedir", str(homedir), "--kill", "all"],
                   capture_output=True, check=False)
