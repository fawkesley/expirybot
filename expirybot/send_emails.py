#!/usr/bin/env python3

"""
- load all the emails we've currently sent from emails_sent
- work thru the rows in keys expiring CSV
- send emails to N people we haven't already emailed
"""

import csv
import datetime
import io
import logging
import os
import time
import requests

from os.path import dirname, join as pjoin

from .make_csv import CSV_HEADER
from .config import MAILGUN_API_KEY
from .utils import (
    make_today_data_dir, load_keys_from_csv, write_key_to_csv
)

EMAILS_TO_SEND = 10


def main():
    logging.basicConfig(level=logging.INFO)

    today_data_dir = make_today_data_dir(datetime.date.today())

    keys_expiring_csv = pjoin(today_data_dir, 'keys_expiring.csv')
    emails_sent_csv = pjoin(today_data_dir, 'emails_sent.csv')

    key_ids_already_emailed = load_key_ids_already_emailed(emails_sent_csv)
    logging.info("Already sent {} emails".format(len(key_ids_already_emailed)))

    with io.open(emails_sent_csv, 'a', 1) as g:
        csv_writer = csv.DictWriter(g, CSV_HEADER, quoting=csv.QUOTE_ALL)

        for key in load_keys_from_csv(keys_expiring_csv):
            if len(key_ids_already_emailed) >= EMAILS_TO_SEND:
                logging.info("Stopping now, sent {} emails".format(
                    len(key_ids_already_emailed)))
                break

            if key.key_id in key_ids_already_emailed:
                logging.info("Already emailed key: {}".format(key))
                continue

            if send_email(key):
                write_key_to_csv(key, csv_writer)
                key_ids_already_emailed.add(key.key_id)


def load_key_ids_already_emailed(emails_sent_csv):
    if not os.path.exists(emails_sent_csv):
        with io.open(emails_sent_csv, 'w') as f:
            csv_writer = csv.DictWriter(f, CSV_HEADER, quoting=csv.QUOTE_ALL)
            csv_writer.writeheader()
        return []

    return set([key.key_id for key in load_keys_from_csv(emails_sent_csv)])


def load_template(name):
    with io.open(pjoin(dirname(__file__), 'templates', name), 'r') as f:
        return f.read()


def send_email(row):
    logging.info("send_email: {}".format(row))
    email_body = load_template('email_body.txt').format(**row)
    email_subject = load_template('email_subject.txt').format(**row)

    logging.info("About to send email:\nSubject: {}".format(
        email_subject)
    )
    time.sleep(5)

    domain = 'keyserver.paulfurley.com'

    raise RuntimeError(email_body)

    request_url = 'https://api.mailgun.net/v2/{0}/messages'.format(domain)

    try:
        response = requests.post(
            request_url,
            auth=('api', MAILGUN_API_KEY),
            data={
                'from': '"Paul M Furley" <paul@keyserver.paulfurley.com>',
                'to': row['primary_email'],
                'h:Reply-To': 'paul@paulfurley.com',
                'subject': email_subject,
                'text': email_body
                }
            )
    except Exception as e:
        logging.exception(e)
        return False

    try:
        response.raise_for_status()
    except Exception as e:
        logging.exception(e)
        logging.error('Status: {0}'.format(response.status_code))
        logging.error('Body:   {0}'.format(response.text))
        return False

    return True


def record_sent(row, csv_writer):
    csv_writer.writerow(row)


if __name__ == '__main__':
    main()
