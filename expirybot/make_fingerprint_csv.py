#!/usr/bin/env python3

"""
- iterate through a list of short ids
- get the fingerprints, uids and expiries for that short id from the keyserver
- output a ${DATA}/keys.csv of all non-revoked keys
"""

import datetime
import sys
import io
import logging

from os.path import join as pjoin

from .config import DATA_DIR, FINGERPRINT_CSV_HEADER, KEYSERVER
from .keyserver_client import KeyserverClient
from .utils import (
    make_atomic_csv_writer, write_key_to_csv, make_today_data_dir,
    setup_logging
)


def main():
    short_ids_file = sys.argv[1]

    today_data_dir = make_today_data_dir(datetime.date.today())
    setup_logging(pjoin(today_data_dir, 'make_fingerprint_csv.log'))

    short_id_count = 0
    keys_parsed_count = 0

    keyserver_client = KeyserverClient(KEYSERVER)

    with make_atomic_csv_writer(
            pjoin(DATA_DIR, 'keys.csv'),
            FINGERPRINT_CSV_HEADER) as csv_writer:

        for short_id in read_short_ids(short_ids_file):
            for key in keyserver_client.get_keys_for_short_id(short_id):
                logging.debug("Key for short id {}: {}".format(short_id, key))

                write_key_to_csv(key, csv_writer)

                keys_parsed_count += 1

            short_id_count += 1

            if short_id_count % 1000 == 0:
                logging.info("Processed {} short ids".format(short_id_count))

    logging.info("Attempted to check {} short ids. Parsed {} keys.".format(
        short_id_count, keys_parsed_count))


def read_short_ids(filename):
    num_lines = 0

    with io.open(filename, 'r') as f:
        for line in f:
            num_lines += 1

    start_time = datetime.datetime.now()

    with io.open(filename, 'r') as f:
        count = 0

        for line in f:
            yield line.strip()
            count += 1

            if count % 5000 == 0:
                duration = datetime.datetime.now() - start_time
                time_per_line = duration / count

                print('{} / {} ({:.1f}%) short ids in {} ({} per million), eta {}'.format(
                    count,
                    num_lines,
                    count / num_lines * 100,
                    duration,
                    duration * (1000000 / count),
                    (num_lines - count) * time_per_line)
                )


if __name__ == '__main__':
    main()
