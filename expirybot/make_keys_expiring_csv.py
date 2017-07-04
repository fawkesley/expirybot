#!/usr/bin/env python3

"""
- iterate through a list of short ids
- download the key for each short id
- if it expires in 3 days from now, add it to the output CSV
"""

import datetime
import logging

from os.path import join as pjoin

from .config import DATA_DIR, FINGERPRINT_CSV_HEADER
from .utils import (
    make_atomic_csv_writer, write_key_to_csv, load_keys_from_csv,
    make_today_data_dir
)

EXPIRING_DAYS = 3


def main():
    today_data_dir = make_today_data_dir(datetime.date.today())
    setup_logging(today_data_dir)

    keys_parsed_count, keys_expiring_count = (0, 0)

    with make_atomic_csv_writer(
            pjoin(today_data_dir, 'keys_expiring.csv'),
            FINGERPRINT_CSV_HEADER) as csv_writer:

        for key in load_keys_from_csv(pjoin(DATA_DIR, 'keys.csv')):

            if key.expires_in(EXPIRING_DAYS):
                write_key_to_csv(key, csv_writer)
                keys_expiring_count += 1

            keys_parsed_count += 1

    logging.info("Checked {} keys. {} expiring in {} days.".format(
        keys_parsed_count, keys_expiring_count, EXPIRING_DAYS))


def setup_logging(today_data_dir):
    log_filename = pjoin(today_data_dir, 'make_keys_expiring_csv.log')
    logging.basicConfig(level=logging.INFO,
                        filename=log_filename,
                        format='(asctime)s %(levelname)s %(message)s')


if __name__ == '__main__':
    main()
