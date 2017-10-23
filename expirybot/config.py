import io
import json
from os.path import abspath, dirname, join as pjoin

try:
    with io.open(abspath(pjoin(dirname(__file__), '..', 'config.json'))) as f:
        config_json = json.load(f)
except EnvironmentError:
    config_json = {}


KEYSERVER = config_json.get(
    'keyserver', 'http://pool.sks-keyservers.net:11371'
)

MAILGUN_API_KEY = config_json.get(
    'mailgun_api_key', 'MAILGUN-API-TOKEN-NOT-SET'
)

BLACKLISTED_DOMAINS = config_json.get(
    'blacklisted_domains', []
)


DATA_DIR = abspath(pjoin(dirname(__file__), '..', 'data'))

FINGERPRINT_CSV_HEADER = [
    'fingerprint',
    'algorithm_number',
    'size_bits',
    'uids',
    'created_date',
    'expiry_date',
]
