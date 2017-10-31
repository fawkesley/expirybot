import csv
import io
import logging
import sys
import os

from os.path import join as pjoin
from contextlib import contextmanager
from .config import config

import rollbar

from .pgp_key import PGPKey


@contextmanager
def make_atomic_csv_writer(output_filename, header):

    with io.open(atomic_filename(output_filename), 'w', 1) as f:
        csv_writer = csv.DictWriter(f, header, quoting=csv.QUOTE_ALL)
        csv_writer.writeheader()

        yield csv_writer

        os.rename(
            atomic_filename(output_filename),
            output_filename
        )


def setup_logging(log_filename):
    sys.excepthook = _handle_exception

    logging.basicConfig(level=logging.INFO,
                        filename=log_filename,
                        format='%(asctime)s %(levelname)s %(message)s')


def atomic_filename(filename):
    path, name = os.path.split(filename)
    return pjoin(path, '.{}'.format(name))


def load_keys_from_csv(csv_file):
    csv.field_size_limit(500 * 1024 * 1024)

    with io.open(pjoin(config.data_dir, csv_file), 'rt') as f:
        for row in csv.DictReader(f):
            yield PGPKey(**row)


def write_key_to_csv(key, csv_writer):
    csv_writer.writerow({
        'fingerprint': key.fingerprint,
        'algorithm_number': key.algorithm_number,
        'size_bits': key.size_bits,
        'uids': '|'.join(key.uids),
        'created_date': (
            key.created_date.isoformat() if key.created_date else ''
        ),
        'expiry_date': (
            key.expiry_date.isoformat() if key.expiry_date else ''
        )
    })


def make_today_data_dir(today):
    return pjoin(config.data_dir, today.isoformat())


def _handle_exception(exc_type, exc_value, traceback):
    exc_info = (exc_type, exc_value, traceback)

    if config.rollbar_api_key is not None:
        rollbar.init(config.rollbar_api_key, config.rollbar_environment)
        rollbar.report_exc_info(exc_info=exc_info, extra_data={})
    else:
        logging.warn('No rollbar API key, not sending exception.')

    sys.__excepthook__(exc_type, exc_value, traceback)
