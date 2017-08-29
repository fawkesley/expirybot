import datetime

from nose.tools import assert_equal, assert_true
import unittest

from .keyserver_client import KeyserverVindexParser
from .test_utils import open_sample


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
