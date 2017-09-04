#!/usr/bin/env python3

"""
- iterate through a list of short ids
- download the key for each short id
- if it expires in 3 days from now, add it to the output CSV
"""

import contextlib
import datetime
import logging

from os.path import join as pjoin

from .config import DATA_DIR, FINGERPRINT_CSV_HEADER as CSV_HEADER
from .utils import (
    make_atomic_csv_writer, write_key_to_csv, load_keys_from_csv,
    make_today_data_dir, setup_logging
)

from .exclusions import is_strong_key, is_blacklisted_domain, has_missing_email

EXPIRING_DAYS = 3


class Stats:
    def __init__(self):
        self.parsed_count = 0
        self.expiring_count = 0
        self.excluded_count = 0


def main():
    today_data_dir = make_today_data_dir(datetime.date.today())
    setup_logging(pjoin(today_data_dir, 'make_keys_expiring_csv.log'))

    stats = Stats()

    all_keys_fn = pjoin(DATA_DIR, 'keys.csv')
    expiring_fn = pjoin(today_data_dir, 'keys_expiring.csv')
    excluded_fn = pjoin(today_data_dir, 'keys_excluded.csv')

    with setup_output_csvs(expiring_fn, excluded_fn) as \
            (expiring_csv, excluded_csv):

        for key in load_keys_from_csv(all_keys_fn):
            handle_key(key, expiring_csv, excluded_csv, stats)

    logging.info("Checked {}, excluded {}. {} expiring in {} days.".format(
        stats.parsed_count, stats.excluded_count, stats.expiring_count,
        EXPIRING_DAYS
    ))


def handle_key(key, expiring_csv, excluded_csv, stats):
    stats.parsed_count += 1

    if key.expires_in(EXPIRING_DAYS):
        if should_exclude(key):
            stats.excluded_count += 1
            write_key_to_csv(key, excluded_csv)
        else:
            write_key_to_csv(key, expiring_csv)
            stats.expiring_count += 1


@contextlib.contextmanager
def setup_output_csvs(expiring_fn, excluded_fn):

    with make_atomic_csv_writer(expiring_fn, CSV_HEADER) as expiring_csv, \
         make_atomic_csv_writer(excluded_fn, CSV_HEADER) as excluded_csv:

        yield (expiring_csv, excluded_csv)


def should_exclude(key):
    if not is_strong_key(key):
        logging.warn("Skipping weak key: {}".format(
            key.fingerprint))
        return True

    elif is_blacklisted_domain(key):
        logging.warn("Skipping blacklisted domain: {}".format(
            key.primary_email))
        return True

    elif has_missing_email(key):
        logging.warn("Skipping key without email: {}".format(
            key.fingerprint))
        return True

    else:
        return False


if __name__ == '__main__':
    main()
