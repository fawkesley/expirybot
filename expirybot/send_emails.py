#!/usr/bin/env python3

"""
- load all the emails we've currently sent from emails_sent
- work thru the rows in keys expiring CSV
- send emails to N people we haven't already emailed
"""

import csv
import datetime
import re
import io
import logging
import os

from os.path import abspath, dirname, join as pjoin

from .make_csv import CSV_HEADER, DATA_DIR

EMAILS_TO_SEND = 10


def main():
    logging.basicConfig(level=logging.WARN)

    date_data_dir = pjoin(DATA_DIR, datetime.date.today().isoformat())

    keys_expiring_csv = pjoin(date_data_dir, 'keys_expiring.csv')
    emails_sent_csv = pjoin(date_data_dir, 'emails_sent.csv')

    emails_sent = load_emails_sent(emails_sent_csv)

    with io.open(keys_expiring_csv, 'r') as f, io.open(emails_sent_csv, 'w', 1) as g:
        csv_writer = csv.DictWriter(g, CSV_HEADER, quoting=csv.QUOTE_ALL)
        csv_writer.writeheader()

        for row in csv.DictReader(f):
            if send_email(row):
                record_sent(row, csv_writer)

                emails_sent.append(row)

            if len(emails_sent) >= EMAILS_TO_SEND:
                break


def load_emails_sent(emails_sent_csv):
    if not os.path.exists(emails_sent_csv):
        return []

    with io.open(emails_sent_csv, 'r') as f:
        return [row['email'] for row in csv.DictReader(f)]


def send_email(row):
    import time
    import random

    print("Pretending to send email to {}".format(row))
    time.sleep(3)

    return random.choice([True, False])


def record_sent(row, csv_writer):
    csv_writer.writerow(row)


if __name__ == '__main__':
    main()
