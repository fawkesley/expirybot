from .pgp_key import PGPKey, UID
from nose.tools import assert_equal


EMAIL_LINE_CASES = [
    ('Paul F <paul@example.com>', 'Paul F <paul@example.com>'),
    ('José <jose@gmail..com>', None),

    ('Paul (hello) <paul@example.com>', 'Paul <paul@example.com>'),
    ('Paul F (hello) <paul@example.com>', 'Paul F <paul@example.com>'),
    ('Paul F () <paul@example.com>', 'Paul F <paul@example.com>'),

    ('paul@example.com', 'paul@example.com'),

    ('paul@invalid', None),
    ('paul@domain.onion', None),
    ('Paul <paul@invalid>', None),
]


def test_parse_email_line():
    for uid, expected in EMAIL_LINE_CASES:
        yield assert_equal, expected, UID(uid).email_line


def test_uid_class():
    uid = UID('hello')
    assert_equal('hello', str(uid))
