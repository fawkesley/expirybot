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

        self.blacklisted_domains = config.get('blacklisted_domains', [])

        self.keyserver = config.get(
            'keyserver', 'http://pool.sks-keyservers.net:11371'
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


config = Config()
