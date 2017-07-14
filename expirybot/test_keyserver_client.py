import io
import datetime

from os.path import dirname, join as pjoin

from nose.tools import assert_equal, assert_true, assert_raises
import unittest
from unittest.mock import MagicMock
from contextlib import contextmanager

from .keyserver_client import KeyserverClient, KeyserverVindexParser
from .exceptions import SuspiciousKeyError


@contextmanager
def open_sample(name):
    fn = pjoin(dirname(__file__), 'sample_data', name)
    with io.open(fn, 'rb') as f:
        yield f


class TestKeyserverVindexParser(unittest.TestCase):
    TEST_STRING = (
        'info:1:2\n'
        'pub:A999B7498D1A8DC473E53C92309F635DAD1B5517:1:4096:1414791274:1513954217:\n'
        'uid:Paul Michael Furley <paul@paulfurley.com>:1482418217::\n'
        'uid:Paul Michael Furley <furbitso@gmail.com>:1482418217::\n'
        'pub:5DD5B8F28CBEFA024F9F472B638C78A5E281ACDB:1:2048:1392480548::r\n'
        'uid:Paul M Furley (http%3A//paulfurley.com) <paul@paulfurley.com>:1392480548::\n'
    )

    def test_split_on_key(self):
        expected = [(
            'pub:A999B7498D1A8DC473E53C92309F635DAD1B5517:1:4096:1414791274:1513954217:\n'
            'uid:Paul Michael Furley <paul@paulfurley.com>:1482418217::\n'
            'uid:Paul Michael Furley <furbitso@gmail.com>:1482418217::'
        ), (
            'pub:5DD5B8F28CBEFA024F9F472B638C78A5E281ACDB:1:2048:1392480548::r\n'
            'uid:Paul M Furley (http%3A//paulfurley.com) <paul@paulfurley.com>:1392480548::'
        )]

        got = list(KeyserverVindexParser._split_on_key(self.TEST_STRING))

        print(got)

        assert_equal(2, len(got))
        assert_equal(expected[0], got[0])
        assert_equal(expected[1], got[1])

    def test_keys(self):
        got = list(
            KeyserverVindexParser(self.TEST_STRING.encode('utf-8')).keys()
        )

        assert_equal(2, len(got))

        # key 1
        assert_equal(
            'A999B7498D1A8DC473E53C92309F635DAD1B5517',
            got[0].fingerprint
        )

        print(got[0])
        print(got[1])

        assert_equal(
            datetime.date(2017, 12, 22),
            got[0].expiry_date
        )

        # key 2

        assert_equal(
            '5DD5B8F28CBEFA024F9F472B638C78A5E281ACDB',
            got[1].fingerprint
        )

        assert_equal(None, got[1].expiry_date)

        assert_true(got[1].is_revoked)

    def test_process_key_with_null_byte_in_uid(self):
        with open_sample('vindex_null_byte') as f:
            got = list(KeyserverVindexParser(f.read()).keys())

        assert_equal([], got)

    def test_process_key_with_unicode_in_uid(self):
        with open_sample('vindex_unicode') as f:
            got = list(KeyserverVindexParser(f.read()).keys())

        assert_equal('Tobias Yüksel <Tobias.yueksel@googlemail.com>',
                     got[0].uids[0])


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
