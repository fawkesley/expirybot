import io
import datetime

from os.path import dirname, join as pjoin

from nose.tools import assert_equal, assert_raises
import unittest
from unittest.mock import MagicMock
from contextlib import contextmanager

from .keyserver_client import KeyserverClient
from .exceptions import SuspiciousKeyError


@contextmanager
def open_sample(name):
    fn = pjoin(dirname(__file__), 'sample_data', name)
    with io.open(fn, 'rb') as f:
        yield f


class TestKeyserverClient(unittest.TestCase):

    class MockHttpGetter():
        pass

    @classmethod
    def setUpClass(cls):

        http_getter = cls.MockHttpGetter()

        with open_sample('vindex_paulfurley') as f:
            http_getter.get = MagicMock(return_value=f.read())

        cls.client = KeyserverClient(
            keyserver='http://a.com',
            http_getter=http_getter)

    def test_make_vindex_url(self):
        client = KeyserverClient(keyserver='http://a.com')

        assert_equal(
            'http://a.com/pks/lookup?search=0xDEADBEEF&op=vindex&options=mr',
            client._make_vindex_url('0xDEADBEEF')
        )

    def test_get_keys_for_short_id(self):
        pass  # TODO

    def test_get_key_for_fingerprint(self):
        fingerprint = '0xA999B7498D1A8DC473E53C92309F635DAD1B5517'

        key = self.client.get_key_for_fingerprint(fingerprint)

        assert_equal(fingerprint, key.fingerprint)
        assert_equal(datetime.date(2017, 12, 22), key.expiry_date)

    def test_get_key_for_fingerprint_rejects_fingerprint_mismatch(self):
        fingerprint = '0x0000000000000000000000000000000000000000'

        assert_raises(
            SuspiciousKeyError,
            lambda: self.client.get_key_for_fingerprint(fingerprint)
        )
