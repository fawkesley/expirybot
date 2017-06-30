#!/usr/bin/env python3

"""
- iterate through a list of short ids
- download the key for each short id
- if it expires in 3 days from now, add it to the output CSV
"""

import csv
import datetime
import re
import sys
import io
import logging
import requests
import tempfile
import subprocess
import os

from os.path import abspath, dirname, join as pjoin

EXPIRING_DAYS = 3
DATA_DIR = abspath(pjoin(dirname(__file__), '..', 'data'))
CSV_HEADER = [
    'fingerprint',
    'key_id',
    'uids',
    'primary_email',
    'date',
    'days_until_expiry',
    'friendly_expiry_date',
]


def main():
    logging.basicConfig(level=logging.WARN)

    short_ids_file = sys.argv[1]

    output_filename = make_output_filename(
        datetime.date.today(),
    )

    gpg_parser = GPGParser()

    short_ids = read_short_ids(short_ids_file)

    with io.open(atomic_filename(output_filename), 'w', 1) as f:
        csv_writer = csv.DictWriter(f, CSV_HEADER, quoting=csv.QUOTE_ALL)
        csv_writer.writeheader()

        for short_id in short_ids:
            for key in get_keys_for_short_id(short_id, gpg_parser):

                logging.debug("Key for short id {}: {}".format(short_id, key))

                if key.expires_in(EXPIRING_DAYS):
                    write_key_to_csv(key, csv_writer)

    os.rename(
        atomic_filename(output_filename),
        output_filename
    )


def fake_get_keys(short_id, gpg_parser):
    yield PGPKeyWrapper({
        'fingerprint': 'A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517',
        'expiry_date': datetime.date(2017, 7, 1),
        'uids': ['Paul Michael Furley <paul@paulfurley.com>', 'furbitso <furbitso@gmail.com>'],
    })


def atomic_filename(filename):
    path, name = os.path.split(filename)
    return pjoin(path, '.{}'.format(name))


def write_key_to_csv(key, csv_writer):
    primary_email = key.primary_email

    if primary_email is None:
        logging.warn("Can't extract valid email for key: {}".format(key))

    csv_writer.writerow({
        'fingerprint': key.fingerprint,
        'key_id': key.long_id,
        'uids': ', '.join(key.uids),
        'primary_email': key.primary_email,
        'date': key.expiry_date.isoformat(),
        'days_until_expiry': key.days_until_expiry,
        'friendly_expiry_date': key.friendly_expiry_date,
    })


def make_output_filename(today):
    return pjoin(DATA_DIR, today.isoformat(), 'keys_expiring.csv')


def read_short_ids(filename):
    start_time = datetime.datetime.now()

    with io.open(filename, 'r') as f:
        count = 0

        for line in f:
            yield line.strip()
            count += 1
            if count % 1000 == 0:
                print('{} short ids ({})'.format(
                    count, datetime.datetime.now() - start_time)
                )


def get_keys_for_short_id(short_id, gpg_parser):
    response = requests.get('http://localhost:11372/pks/lookup?op=get&options=mr&search={}'.format(short_id))
    # logging.debug(response.text)
    return gpg_parser.get_keys(response.text)


class PGPKeyWrapper:
    def __init__(self, key_dict):
        self._key = key_dict

    @property
    def fingerprint(self):
        return self._key['fingerprint']

    @property
    def long_id(self):
        return '0x{}'.format(self.fingerprint.upper().replace(' ', '')[-16:])

    @property
    def days_until_expiry(self):
        if self.expiry_date:
            return (self.expiry_date - datetime.date.today()).days
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
        return self._key.get('expiry_date', None)

    @property
    def uids(self):
        return self._key.get('uids', [])

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


class GPGParser:

    GPG = 'gpg2'

    def __init__(self):
        self.gpg_home = tempfile.mkdtemp(
            dir='/dev/shm', prefix='tmp.expirybot.'
        )
        os.chmod(self.gpg_home, 0o700)
        with io.open(pjoin(self.gpg_home, 'gpg.conf'), 'wt') as f:
            f.write('with-fingerprint\n')
            f.write('keyid-format 0xlong\n')

        subprocess.call([self.GPG, '--list-keys', '--homedir', self.gpg_home])

    def get_keys(self, pgp_ascii_armor):

        with tempfile.NamedTemporaryFile(
                dir="/dev/shm/", prefix="tmp.expirybot.") as f:
            f.write(pgp_ascii_armor.encode('ascii'))
            f.flush()

            stdout, stderr = self._run_gpg(f.name)

            logging.debug(stdout)

            for key in self._parse_keys(stdout):
                yield PGPKeyWrapper(key)

    @staticmethod
    def _parse_keys(stdout):
        """
        pub  rsa4096/0x9B08F1E400000000 2012-03-15
              Key fingerprint = ABCD CF87 34A8 407B 60E9  DA26 9B08 F1E4 0000 0000
        uid                             Paul Furley <paul@paulfurley.com>
        pub  rsa4096/0xFA0D2D9200000000 2009-06-13 [revoked: 2012-09-13]
              Key fingerprint = ABCD 008D A232 D19B C612  CC01 FA0D 2D92 0000 0000
        uid                             John Smith <john.smith@gmail.com>
        uid                             John Smith (Born 1985-Mar-03 in Portland, OR, USA)
        sub  rsa4096/0xC76F076C048DB876 2012-09-13 [revoked: 2012-09-13]
        sub  rsa4096/0xB1F62E681D764D22 2012-09-13 [revoked: 2012-09-13]
        """

        current_key = {}

        for line in stdout.split('\n'):
            if line.startswith('pub'):
                if current_key:
                    yield current_key

                current_key = {}
                GPGParser._update_key_from_pub_line(current_key, line)

            elif line.lstrip().startswith('Key fingerprint = '):
                GPGParser._update_key_from_fingerprint_line(current_key, line)

            elif line.startswith('uid'):
                GPGParser._update_key_from_uid_line(current_key, line)

        if current_key:
            yield current_key

    @staticmethod
    def _update_key_from_pub_line(key_dict, line):
        expiry_date = GPGParser._parse_expiry_date(line)

        if expiry_date:
            key_dict['expiry_date'] = expiry_date

    @staticmethod
    def _update_key_from_uid_line(key_dict, line):
        if 'uids' not in key_dict:
            key_dict['uids'] = []
        key_dict['uids'].append(line[4:].strip())

    @staticmethod
    def _parse_expiry_date(line):
        match = re.match('.*\[expires: (?P<date>\d{4}-\d{2}-\d{2})\].*$', line)

        if match is not None:
            return GPGParser._parse_date(match.group('date'))

    @staticmethod
    def _update_key_from_fingerprint_line(key_dict, line):
        key_dict['fingerprint'] = line.split('= ')[1].strip()

    @staticmethod
    def _parse_date(date_string):
        return datetime.date(
            *[int(part) for part in date_string.split('-')]
        )

    def _run_gpg(self, key_filename):

        cmd_parts = [
            self.GPG,
            '--homedir',
            self.gpg_home,
            '--batch',
            key_filename
        ]

        p = subprocess.Popen(
            cmd_parts,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        try:
            stdout, stderr = p.communicate()
        except subprocess.TimeoutExpired:
            p.kill()
            stdout, stderr = p.communicate()
            raise  # TODO: is this the right handling?
        else:
            if p.returncode != 0:
                logging.warning(
                    'gpg failed with code {} stdout: {} stderr: {}'.format(
                        p.returncode, stdout, stderr
                    )
                )
                return ('', '')
        if stdout is None:
            stdout = b''

        if stderr is None:
            stderr = b''

        try:
            return stdout.decode('utf-8'), stderr.decode('utf-8')
        except UnicodeError as e:
            logging.exception(e)
            return ('', '')


if __name__ == '__main__':
    main()
