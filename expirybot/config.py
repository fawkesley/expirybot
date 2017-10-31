import io
import json
import logging
import getpass
import platform

from os.path import abspath, dirname, join as pjoin

import requests


class Config():
    CONFIG_JSON = abspath(pjoin(dirname(__file__), '..', 'config.json'))

    def __init__(self):

        try:
            with io.open(self.CONFIG_JSON) as f:
                config = json.load(f)

        except EnvironmentError:
            logging.warn('Failed to open {}'.format(self.CONFIG_JSON))
            config = {}

        self.mailgun_domain = config.get('mailgun_domain', 'example.com')

        self.mailgun_api_key = config.get('mailgun_api_key', 'INVALID')

        self.rollbar_api_key = config.get('rollbar_api_key', None)

        self.rollbar_environment = config.get('rollbar_environment', 'dev')

        self.from_line = config.get('from_line', 'example@example.com')

        self.reply_to = config.get('reply_to', '')

        self.evaluation_email = config.get(
            'evaluation_email', 'null@example.com'
        )

        self.blacklisted_domains = config.get('blacklisted_domains', [])

        self.keyserver = config.get(
            'keyserver', 'http://pool.sks-keyservers.net:11371'
        )

        self.user_agent = config.get(
            'user_agent', self._default_user_agent()
        )

    @property
    def data_dir(self):
        return abspath(pjoin(dirname(__file__), '..', 'data'))

    @property
    def csv_header(self):
        return [
            'fingerprint',
            'algorithm_number',
            'size_bits',
            'uids',
            'created_date',
            'expiry_date',
        ]

    def _default_user_agent(self):
        username = getpass.getuser()
        hostname = platform.node()

        return '{} {user}@{hostname}'.format(
            requests.utils.default_user_agent(),
            user=username,
            hostname=hostname)


config = Config()
