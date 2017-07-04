import datetime
import re


class PGPKey:
    def __init__(self, fingerprint=None, uids=None, expiry_date=None,
                 created_date=None):
        self._fingerprint = None
        self._expiry_date = None
        self._uids = []
        self._revoked = False

        if fingerprint is not None:
            self.set_fingerprint(fingerprint)

        if uids is not None:
            for uid in uids.split('|'):
                self.add_uid(uid)

        if expiry_date is not None:
            self.set_expiry_date(expiry_date)

    def __str__(self):
        return 'PGPKey({} {})'.format(
            self.fingerprint,
            '[revoked]' if self._revoked else '[expires {}]'.format(
                self.expiry_date)
        )

    def set_fingerprint(self, fingerprint):
        self._fingerprint = Fingerprint(fingerprint)

    def set_expiry_timestamp(self, timestamp):
        if not isinstance(timestamp, int):
            timestamp = int(timestamp)

        self._expiry_date = datetime.datetime.fromtimestamp(timestamp).date()

    def set_expiry_date(self, date):
        if not date:
            self._expiry_date = None

        elif isinstance(date, datetime.date):
            self._expiry_date = date

        elif isinstance(date, str):
            self._expiry_date = datetime.date(
                *[int(part) for part in date.split('-')]
            )

        else:
            raise TypeError('Unknown date format: {}'.format(date))

    def add_uid(self, uid_string):
        self._uids.append(uid_string)

    def set_revoked(self):
        self._revoked = True

    @property
    def fingerprint(self):
        return self._fingerprint

    @property
    def long_id(self):
        return self._fingerprint.to_long_id()

    @property
    def is_revoked(self):
        return self._revoked

    @property
    def days_until_expiry(self, today=None):
        if today is None:
            today = datetime.date.today()

        if self.expiry_date:
            return (self.expiry_date - today).days
        else:
            return None

    @property
    def friendly_expiry_date(self):
        if self.expiry_date:
            return self.expiry_date.strftime('%A %d %B %Y')
        else:
            return None

    @property
    def expiry_date(self):
        return self._expiry_date

    @property
    def uids(self):
        return self._uids

    @property
    def primary_email(self):
        emails = self.emails

        if len(emails):
            return emails[0]

    @property
    def emails(self):
        return list(filter(None, map(self._parse_email, self.uids)))

    @staticmethod
    def _parse_email(uid):
        match = re.match('.*<(?P<email>.+@.+)>$', uid)
        if match:
            return match.group('email')

    def expires_in(self, days):
        return self.days_until_expiry == days


class Fingerprint():
    def __init__(self, fingerprint_string):
        self._hex_digits = self.normalize(fingerprint_string)

    def normalize(self, string):
        pattern = r'^(0x)?(?P<hex>([A-Fa-f0-9]{4}\s*){10})$'
        match = re.match(pattern, string)

        if match is not None:
            return re.sub(
                '[^A-Fa-f0-9]',
                '',
                match.group('hex').upper()
            )  # e.g. return 'A999B749...'
        else:
            raise ValueError(
                "Fingerprint appears to be invalid: `{}`".format(string))

    def to_long_id(self):
        return '0x{}'.format(self._hex_digits.upper().replace(' ', '')[-16:])

    def __str__(self):
        return '{} {} {} {} {}  {} {} {} {} {}'.format(
            self._hex_digits[0:4],
            self._hex_digits[4:8],
            self._hex_digits[8:12],
            self._hex_digits[12:16],
            self._hex_digits[16:20],
            self._hex_digits[20:24],
            self._hex_digits[24:28],
            self._hex_digits[28:32],
            self._hex_digits[32:36],
            self._hex_digits[36:40]
        )

    def __repr__(self):
        return '<Fingerprint {}>'.format(self.__str__())

    def __eq__(self, other):
        if not isinstance(other, Fingerprint):
            other = Fingerprint(other)
        return self.hex_format == other.hex_format

    @property
    def hex_format(self):
        return '0x{}'.format(self._hex_digits)
