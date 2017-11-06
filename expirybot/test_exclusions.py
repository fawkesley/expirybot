from nose.tools import assert_equal

from .exclusions import all_blacklisted_domains, roughly_validate_email
from .pgp_key import PGPKey
from .config import config


def test_all_blacklisted_domains():
    config.blacklisted_domains = ['blacklisted.com']

    for uids, expected in [
        ('paul@blacklisted.com', True),
        ('paul@example.com', False),
        ('paul@blacklisted.com|paul2@blacklisted.com', True),
        ('paul@blacklisted.com|paul@example.com', False),

        ('paul@example.com|invalid', False),
    ]:
        key = PGPKey(uids=uids)
        yield assert_equal, expected, all_blacklisted_domains(key)


def test_roughly_validate_email():
    assert_equal(False, roughly_validate_email('invalid'))
