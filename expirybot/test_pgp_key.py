from .pgp_key import PGPKey
from nose.tools import assert_equal


EMAIL_CASES = [
    ('Paul F <paul@example.com>', 'paul@example.com'),
    ('Paul F (hello) <paul@example.com>', 'paul@example.com'),
    ('Paul F () <paul@example.com>', 'paul@example.com'),
    ('Paul F <paul@example.com>', 'paul@example.com'),
]

EMAIL_LINE_CASES = [
    ('Paul F <paul@example.com>', 'Paul F <paul@example.com>'),
    ('Paul (hello) <paul@example.com>', 'Paul <paul@example.com>'),
    ('Paul F (hello) <paul@example.com>', 'Paul F <paul@example.com>'),
    ('Paul F () <paul@example.com>', 'Paul F <paul@example.com>'),
    ('Paul F <paul@example.com>', 'Paul F <paul@example.com>'),
    ('paul@example.com', 'paul@example.com'),
]


def test_parse_email_line():
    for raw, expected in EMAIL_LINE_CASES:
        yield assert_equal, expected, PGPKey._parse_uid_as_email_line(raw)


def test_parse_uid_as_email():
    for raw, expected in EMAIL_CASES:
        yield assert_equal, expected, PGPKey._parse_uid_as_email(raw)
