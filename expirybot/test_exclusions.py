from nose.tools import assert_true, assert_false

from .exclusions import is_strong_key, is_blacklisted_domain, has_missing_email
from .pgp_key import PGPKey


def test_has_missing_email():
    yield assert_true, has_missing_email(PGPKey(uids='a@a'))
    yield assert_false, has_missing_email(PGPKey(uids='paul@example.com'))
