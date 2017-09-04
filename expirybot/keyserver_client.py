import io
import datetime
import logging
import os
import re
import tempfile
import shlex
import subprocess
from os.path import join as pjoin

from .requests_wrapper import RequestsWithSessionAndUserAgent
from .pgp_key import Fingerprint
from .exceptions import SuspiciousKeyError
from .keyserver_vindex_parser import KeyserverVindexParser

GPG_FINGERPRINT_PATTERN = '[A-F0-9]{4} [A-F0-9]{4} [A-F0-9]{4} [A-F0-9]{4} [A-F0-9]{4}  [A-F0-9]{4} [A-F0-9]{4} [A-F0-9]{4} [A-F0-9]{4} [A-F0-9]{4}'  # noqa
LOG = logging.getLogger(__name__)


class KeyserverClient:
    def __init__(self, keyserver='https://keyserver.paulfurley.com',
                 http_getter=None):
        self.keyserver = keyserver

        self.http_getter = http_getter or RequestsWithSessionAndUserAgent()

    def get_keys_for_short_id(self, short_id):
        for key in self.do_vindex_search(short_id):
            if key.is_valid:
                yield key

    def get_key_for_fingerprint(self, fingerprint):
        if not isinstance(fingerprint, Fingerprint):
            fingerprint = Fingerprint(fingerprint)

        keys = list(self.do_vindex_search(fingerprint.hex_format))

        if len(keys) != 1:
            raise RuntimeError('Expected 1 key for {}, got: {}'.format(
                fingerprint, keys))

        pgp_key = keys[0]

        if pgp_key.fingerprint != fingerprint:
            raise SuspiciousKeyError(
                'Requested a key from the keyserver with fingerprint {} '
                'and got one back with fingerprint {}'.format(
                    fingerprint, pgp_key.fingerprint))

        return pgp_key

    def do_vindex_search(self, search_query):
        url = self._make_vindex_url(search_query)

        return KeyserverVindexParser(self.http_getter.get_content(url)).keys()

    def _make_vindex_url(self, search_query):
        return '{}/pks/lookup?search={}&op=vindex&options=mr'.format(
            self.keyserver, search_query
        )

    def url_get_key_from_fingerprint(self, fingerprint):
        if not isinstance(fingerprint, Fingerprint):
            raise TypeError("Not a Fingerprint: `{}`".format(fingerprint))

        return '{}/pks/lookup?op=get&search={}&options=mr'.format(
            self.keyserver, fingerprint.hex_format
        )


class GPGCommandLineParser():
    def __init__(self, key_string):
        self.gpg = 'gpg2'
        self.key_string = key_string

    def get_fingerprint(self):
        stdout, stderr = self.run_gpg('', stdin=self.key_string)
        return self._parse_fingerprint(stdout)

    def get_uids(self):
        stdout, stderr = self.run_gpg('', stdin=self.key_string)
        return self._parse_uids(stdout)

    def get_expiries(self):
        stdout, stderr = self.run_gpg('', stdin=self.key_string)
        return self._parse_expiries(stdout)

    def run_gpg(self, command, stdin=None):
        """
        Run e.g. `gpg --homedir <tmpdir> <command>`, pass in stdin and
        return stdout, stderr
        """
        gpg_home = tempfile.mkdtemp(prefix='gpg.')
        os.chmod(gpg_home, 0o700)

        with io.open(pjoin(gpg_home, 'gpg.conf'), 'wt') as f:
            f.write('with-fingerprint\n')
            f.write('keyid-format 0xlong\n')

        subprocess.call([self.gpg, '--list-keys', '--homedir', gpg_home])

        cmd_parts = [
            self.gpg,
            '--homedir',
            gpg_home,
        ] + shlex.split(command)

        p = subprocess.Popen(
            cmd_parts, stdin=subprocess.PIPE, stdout=subprocess.PIPE
        )

        try:
            stdout, stderr = p.communicate(input=stdin.encode('ascii'))
        except subprocess.TimeoutExpired:
            p.kill()
            stdout, stderr = p.communicate()
            raise  # TODO: is this the right handling?
        else:
            if p.returncode != 0:
                raise RuntimeError(
                    'returncode: {} {} {}'.format(p.returncode, stdout, stderr)
                )

            if stdout is None:
                stdout = b''

            if stderr is None:
                stderr = b''

            return stdout.decode('utf-8'), stderr.decode('utf-8')

    @staticmethod
    def _parse_fingerprint(gpg_output):
        """
        pub  rsa4096/0x309F635DAD1B5517 2014-10-31 [expires: 2017-12-22]
              Key fingerprint = A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517  # noqa
        uid                             Paul Michael Furley <paul@paulfurley.com>   # noqa
        sub  rsa4096/0x627B1B4E8E532C34 2014-10-31 [expires: 2017-12-22]
        sub  rsa4096/0x0AC6AD63E8E8A9B0 2014-10-31 [expires: 2017-12-22]

        """

        def parse_fingerprint_from_line(line):
            match = re.match(
                '.*fingerprint = (?P<fingerprint>' + GPG_FINGERPRINT_PATTERN + ')',
                 line)

            if match is not None:
                return match.group('fingerprint')

        fingerprints = list(filter(
            None,
            map(parse_fingerprint_from_line, gpg_output.split('\n'))
        ))

        if len(fingerprints) == 1:
            return fingerprints[0]
        else:
            raise ValueError("Couldn't find single fingerprint: {}".format(
                fingerprints))

    @staticmethod
    def _parse_uids(gpg_output):
        """
        pub  rsa4096/0x309F635DAD1B5517 2014-10-31 [expires: 2017-12-22]
              Key fingerprint = A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517  # noqa
        uid                             Paul Michael Furley <paul@paulfurley.com>   # noqa
        sub  rsa4096/0x627B1B4E8E532C34 2014-10-31 [expires: 2017-12-22]
        sub  rsa4096/0x0AC6AD63E8E8A9B0 2014-10-31 [expires: 2017-12-22]

        """

        def parse_uid(line):
            match = re.match('^uid\s+(?P<uid>.+)$', line)

            if match is not None:
                return match.group('uid')

        return list(filter(
            None,
            map(parse_uid, gpg_output.split('\n'))
        ))

    @staticmethod
    def _parse_expiries(gpg_output):
        """
        pub  rsa4096/0x309F635DAD1B5517 2014-10-31 [expires: 2017-12-22]
              Key fingerprint = A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517  # noqa
        uid                             Paul Michael Furley <paul@paulfurley.com>   # noqa
        sub  rsa4096/0x627B1B4E8E532C34 2014-10-31 [expires: 2017-12-22]
        sub  rsa4096/0x0AC6AD63E8E8A9B0 2014-10-31 [expires: 2017-12-22]
        """

        def parse_expiry(line):
            match = re.match('^(?P<key_type>pub|sub) .*\[expires: (?P<date>\d{4}-\d{2}-\d{2})]$', line)

            if match is not None:
                return {
                    'type': {'pub': 'primary', 'sub': 'sub'}[match.group('key_type')],
                    'date': GPGCommandLineParser._parse_date(match.group('date'))
                }

        return list(filter(
            None,
            map(parse_expiry, gpg_output.split('\n'))
        ))

    @staticmethod
    def _parse_date(string):
        """
        e.g. '2014-06-24'
        """

        return datetime.date(*map(int, string.split('-')))
