from .config import config

import requests


class RequestsWithSessionAndUserAgent:
    def __init__(self):
        self.session = requests.Session()

    def get(self, url, *args, **kwargs):
        return self._call_method('get', url, *args, **kwargs)

    def get_content(self, url, *args, **kwargs):
        response = self.get(url, *args, **kwargs)
        response.raise_for_status()
        return response.content

    def post(self, url, *args, **kwargs):
        return self._call_method('post', url, *args, **kwargs)

    def _call_method(self, method, url, *args, **kwargs):
        if 'headers' not in kwargs:
            kwargs['headers'] = {}

        kwargs['headers']['user-agent'] = config.user_agent

        return self.session.request(method, url, *args, **kwargs)
