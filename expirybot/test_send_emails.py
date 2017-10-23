import datetime
import tempfile

from nose.tools import assert_equal
import unittest

import freezegun

from .send_emails import ExpiryEmail
from .pgp_key import PGPKey
from .test_utils import open_sample, sample_filename


class TestExpiryEmailClass(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key = PGPKey(
            fingerprint='A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517',
            algorithm_number=1,
            size_bits=4096,
            uids='Paul Furley <paul1@example.com>|Paul <paul2@example.com',
            expiry_date=datetime.date(2017, 12, 4),
            created_date=None
        )

        with freezegun.freeze_time(datetime.date(2017, 12, 1)):
            cls.expiry_email = ExpiryEmail(key)

            with tempfile.NamedTemporaryFile('w', suffix='.txt') as f:
                f.write(cls.expiry_email.body)
                print('Wrote self.email_email.body to {}'.format(f.name))

    def test_body(self):
        expected_file = '_expected_email.txt'

        with open_sample(expected_file) as f:
            try:
                assert_equal(f.read().decode('utf-8'), self.expiry_email.body)
            except AssertionError:

                with tempfile.NamedTemporaryFile('wb', prefix='got_',
                                                 delete=False) as g:
                    g.write(self.expiry_email.body.encode('utf-8'))

                print('Try $ diff {} {}'.format(
                    sample_filename(expected_file), g.name))
                raise

    def test_subject(self):
        assert_equal(
            'PGP key expires in 3 days: 0x309F635DAD1B5517 '
            '(it can be extended)',
            self.expiry_email.subject
        )

    def test_to(self):
        assert_equal(
            'paul1@example.com',
            self.expiry_email.to
        )

    def test_from_line(self):
        assert_equal(
            '"Paul M Furley" <paul@keyserver.paulfurley.com>',
            self.expiry_email.from_line
        )

    def test_reply_to(self):
        assert_equal(
            '"Paul M Furley" <paul@paulfurley.com>',
            self.expiry_email.reply_to
        )
