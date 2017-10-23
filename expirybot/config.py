import io
import json
import logging

from os.path import abspath, dirname, join as pjoin


class Config():
    CONFIG_JSON = abspath(pjoin(dirname(__file__), '..', 'config.json'))

    def __init__(self):
        self.keyserver = 'http://pool.sks-keyservers.net:11371'
        self.mailgun_domain = 'example.com'
        self.mailgun_api_key = 'INVALID-API-KEY'
        self.blacklisted_domains = []

        try:
            with io.open(self.CONFIG_JSON) as f:
                config_json = json.load(f)

                self.keyserver = config_json['keyserver']
                self.mailgun_domain = config_json['mailgun_domain']
                self.mailgun_api_key = config_json['mailgun_api_key']
                self.blacklisted_domains = config_json['blacklisted_domains']

        except EnvironmentError:
            logging.warn('Failed to open {}'.format(self.CONFIG_JSON))

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
