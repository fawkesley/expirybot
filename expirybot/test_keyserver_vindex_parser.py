import datetime

from nose.tools import assert_equal, assert_true, assert_false
import unittest

from .keyserver_client import KeyserverVindexParser
from .test_utils import open_sample


class TestKeyserverVindexParser(unittest.TestCase):

    def test_split_on_key(self):
        TEST_STRING = (
            'info:1:2\n'
            'pub:A999B7498D1A8DC473E53C92309F635DAD1B5517:1:4096:1414791274:1513954217:\n'
            'uid:Paul Michael Furley <paul@paulfurley.com>:1482418217::\n'
            'uid:Paul Michael Furley <furbitso@gmail.com>:1482418217::\n'
            'pub:5DD5B8F28CBEFA024F9F472B638C78A5E281ACDB:1:2048:1392480548::r\n'
            'uid:Paul M Furley (http%3A//paulfurley.com) <paul@paulfurley.com>:1392480548::\n'
        )
        expected = [(
            'pub:A999B7498D1A8DC473E53C92309F635DAD1B5517:1:4096:1414791274:1513954217:\n'
            'uid:Paul Michael Furley <paul@paulfurley.com>:1482418217::\n'
            'uid:Paul Michael Furley <furbitso@gmail.com>:1482418217::'
        ), (
            'pub:5DD5B8F28CBEFA024F9F472B638C78A5E281ACDB:1:2048:1392480548::r\n'
            'uid:Paul M Furley (http%3A//paulfurley.com) <paul@paulfurley.com>:1392480548::'
        )]

        got = list(KeyserverVindexParser._split_on_key(TEST_STRING))

        print(got)

        assert_equal(2, len(got))
        assert_equal(expected[0], got[0])
        assert_equal(expected[1], got[1])

    def test_keys(self):
        keys = self._parse_sample_file('vindex_multiple_keys')

        assert_equal(2, len(keys))

        # key 1
        assert_equal(
            'A999B7498D1A8DC473E53C92309F635DAD1B5517',
            keys[0].fingerprint
        )

        # key 2

        assert_equal(
            '5DD5B8F28CBEFA024F9F472B638C78A5E281ACDB',
            keys[1].fingerprint
        )

    def test_process_key_with_null_byte_in_uid(self):
        keys = self._parse_sample_file('vindex_null_byte')

        assert_equal([], keys)

    def test_process_key_with_unicode_in_uid(self):
        keys = self._parse_sample_file('vindex_unicode')

        assert_equal('Tobias Yüksel <Tobias.yueksel@googlemail.com>',
                     keys[0].uids[0])

    def test_parse_expiry_date(self):
        keys = self._parse_sample_file('vindex_paulfurley')
        assert_equal(datetime.date(2017, 12, 22), keys[0].expiry_date)

    def test_parse_empty_expiry_date_as_none(self):
        keys = self._parse_sample_file('vindex_no_expiry')
        assert_equal(None, keys[0].expiry_date)

    def test_is_revoked_false_for_valid_keys(self):
        keys = self._parse_sample_file('vindex_paulfurley')
        assert_false(keys[0].is_revoked)

    def test_is_revoked_true_for_revoked_keys(self):
        keys = self._parse_sample_file('vindex_revoked')
        assert_true(keys[0].is_revoked)

    def _parse_sample_file(self, filename):
        with open_sample(filename) as f:
            parsed_keys = list(KeyserverVindexParser(f.read()).keys())
            return parsed_keys
