import logging

LOG = logging.getLogger(__name__)

RSA = 1
DSA = 17
ECDSA = 19
ECC = 18


def is_strong_key(key):
    if key.algorithm_number == RSA:
        return key.size_bits >= 2048

    elif key.algorithm_number == DSA:
        return key.size_bits >= 2048

    elif key.algorithm_number == ECDSA:
        LOG.warn("Returning 'strong' for ECDSA key size {}".format(
            key.size_bits
            )
        )
        return True

    elif key.algorithm_number == ECC:
        return key.size_bits >= 256

    else:
        LOG.warn("Unknown key algorithm / size: {} {}".format(
            key.algorithm_number, key.size_bits
            )
        )
        return False
