import io
import datetime
import logging
import os
import re
import tempfile
import shlex
import subprocess
from os.path import join as pjoin
from urllib.parse import unquote

import requests

from .pgp_key import PGPKey, Fingerprint, OpenPGPVersion3FingerprintUnsupported

GPG_FINGERPRINT_PATTERN = '[A-F0-9]{4} [A-F0-9]{4} [A-F0-9]{4} [A-F0-9]{4} [A-F0-9]{4}  [A-F0-9]{4} [A-F0-9]{4} [A-F0-9]{4} [A-F0-9]{4} [A-F0-9]{4}'  # noqa
LOG = logging.getLogger(__name__)


class KeyserverClient:
    def __init__(self, keyserver='https://keyserver.paulfurley.com',
                 http_getter=None):
        self.keyserver = keyserver

        self.http_getter = http_getter or HttpGetterWithSessionAndUserAgent()

    def get_keys_for_short_id(self, short_id):
        url = '{}/pks/lookup?search={}&op=vindex&options=mr'.format(
            self.keyserver, short_id
        )

        for key in KeyserverVindexParser(self.http_getter.get(url)).keys():
            if key.is_valid:
                yield key

    #def get_key_for_fingerprint(self, fingerprint):
    #    """
    #    Search the keyservers for the fingerprint and return an ascii-armored
    #    PGP key as a string.
    #    e.g.
    #    >>> get_key_for_fingerprint('A999 B749 8D1A 8DC4 73E5  3C92 309F 635D AD1B 5517'  # noqa
    #    '-----BEGIN PGP PUBLIC KEY BLOCK-----\n...'
    #    """
    #    if not isinstance(fingerprint, Fingerprint):
    #        fingerprint = Fingerprint(fingerprint)

    #    search_url = self.url_get_key_from_fingerprint(fingerprint)

    #    pgp_key = PGPKey(self.http_getter.get(search_url))

    #    if pgp_key.fingerprint != fingerprint:
    #        raise SuspiciousKeyError(
    #            'Requested a key from the keyserver with fingerprint {} '
    #            'and got one back with fingerprint {}'.format(
    #                fingerprint, pgp_key.fingerprint
    #            )
    #        )

    #    return pgp_key

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


class KeyserverVindexParser:
    """
    Parse strings like this:

    info:1:7
    pub:A856CF8734A8407B60E9DA269B08F1E400000000:1:4096:1331844405::
    uid:Thorsten Rapp <Thorsten@giblicht.de>:1418066014::
    pub:C303008DA232D19BC612CC01FA0D2D9200000000:3:4096:1244914753::r
    uid:Julian Blake Kongslie <jblake@omgwallhack.org>:1347568322::
    uid:Julian Blake Kongslie (Born 1985-Mar-03 in Portland, OR, USA):1347568322::
    pub:99054BB650F3B571F2A85B4D95B48A1500000000:1:4096:1465401461::
    uid:%C5%81ukasz Jurczyk <admin@zabszk.net>:1485204387::
    uid:%C5%81ukasz Jurczyk <zabszk@protonmail.ch>:1465402295::
    """

    def __init__(self, response_bytes):
        assert isinstance(response_bytes, bytes), type(response_bytes)
        self.key_strings = self._split_on_key(response_bytes.decode('utf-8'))

    @staticmethod
    def _split_on_key(string):
        current_lines = []

        for line in string.split('\n'):
            if line.startswith('pub'):

                if current_lines:
                    yield '\n'.join(current_lines)
                    current_lines = []

            if line.startswith('pub') or line.startswith('uid'):
                current_lines.append(line)

        if current_lines:
            yield '\n'.join(current_lines)

    def keys(self):
        for key_string in self.key_strings:
            try:
                key = PGPKey()

                for line in key_string.split('\n'):
                    if line.startswith('pub'):
                        self._update_key_from_pub_line(key, line)

                    elif line.startswith('uid'):
                        self._update_key_from_uid_line(key, line)

            except OpenPGPVersion3FingerprintUnsupported as e:
                key = PGPKey()  # invalidate the key
                continue

            except ValueError as e:
                LOG.exception(e)
                key = PGPKey()  # invalidate the key
                continue

            yield key

    @staticmethod
    def _update_key_from_pub_line(key, line):
        """
        pub:A856CF8734A8407B60E9DA269B08F1E400000000:1:4096:1331844405::
        """
        (_, fingerprint, _, _, _, expiry_timestamp, flag) = line.split(':')

        if flag != '' and flag != 'r':
            LOG.info('Got this key flag: `{}`'.format(flag))

        key.set_fingerprint(fingerprint)

        if expiry_timestamp:
            key.set_expiry_timestamp(expiry_timestamp)

        if flag == 'r':
            key.set_revoked()

    @staticmethod
    def _update_key_from_uid_line(key, line):
        """
        uid:Paul Furley <paul@paulfurley.com>:1418066014::
        """
        (_, uid, _, _, _) = line.split(':')

        key.add_uid(unquote(uid))


class HttpGetterWithSessionAndUserAgent:
    def __init__(self):
        self.session = requests.Session()

    def get(self, url, *args, **kwargs):
        if 'headers' not in kwargs:
            kwargs['headers'] = {}

        kwargs['headers']['user-agent'] = (
            'PGP key email verify bot bot@paulfurley.com'
        )

        response = self.session.get(url, *args, **kwargs)
        response.raise_for_status()
        return response.content
