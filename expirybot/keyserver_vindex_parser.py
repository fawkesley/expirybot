import logging
from urllib.parse import unquote

from .pgp_key import PGPKey, Fingerprint, OpenPGPVersion3FingerprintUnsupported
from .exceptions import SuspiciousKeyError

LOG = logging.getLogger(__name__)


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
