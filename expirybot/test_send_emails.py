import datetime

from nose.tools import assert_equal
import unittest

import freezegun

from .send_emails import ExpiryEmail
from .pgp_key import PGPKey


class TestExpiryEmailClass(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key = PGPKey(
            fingerprint='A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517',
            algorithm_number=1,
            size_bits=4096,
            uids='Paul Furley <recipient@example.com>',
            expiry_date=datetime.date(2017, 12, 4),
            created_date=None
        )

        with freezegun.freeze_time(datetime.date(2017, 12, 1)):
            cls.expiry_email = ExpiryEmail(key)

    def test_body(self):
        lines = self.expiry_email.body.split('\n')

        assert_equal(
            'fingerprint: A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517',
            lines[4]
        )

        assert_equal(
            'long key id: 0x309F635DAD1B5517',
            lines[5]
        )

        assert_equal(
            'https://pgp.mit.edu/pks/lookup'
            '?op=vindex&search=0x309F635DAD1B5517',
            lines[9]
        )

    def test_subject(self):
        assert_equal(
            'PGP key expires in 3 days: 0x309F635DAD1B5517 '
            '(it can be extended)',
            self.expiry_email.subject
        )

    def test_to(self):
        assert_equal(
            'recipient@example.com',
            self.expiry_email.to
        )

    def test_from_line(self):
        assert_equal(
            '"Paul M Furley" <paul@keyserver.paulfurley.com>',
            self.expiry_email.from_line
        )

    def test_reply_to(self):
        assert_equal(
            'paul@paulfurley.com',
            self.expiry_email.reply_to
        )
