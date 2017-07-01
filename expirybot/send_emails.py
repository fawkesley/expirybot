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
import time
import requests
import json

from os.path import abspath, dirname, join as pjoin

from .make_csv import CSV_HEADER, DATA_DIR

MAILGUN_API_KEY = 'key-573117304668c45426cbfb1769811516'
EMAILS_TO_SEND = 10


def main():
    logging.basicConfig(level=logging.INFO)
    load_config()

    date_data_dir = pjoin(DATA_DIR, datetime.date.today().isoformat())

    keys_expiring_csv = pjoin(date_data_dir, 'keys_expiring.csv')
    emails_sent_csv = pjoin(date_data_dir, 'emails_sent.csv')

    emails_sent = load_emails_sent(emails_sent_csv)
    logging.info("Already sent {} emails".format(len(emails_sent)))

    with io.open(keys_expiring_csv, 'r') as f, io.open(emails_sent_csv, 'a', 1) as g:
        csv_writer = csv.DictWriter(g, CSV_HEADER, quoting=csv.QUOTE_ALL)

        for row in csv.DictReader(f):
            if len(emails_sent) >= EMAILS_TO_SEND:
                logging.info("Stopping now, sent {} emails".format(
                    len(emails_sent)))
                break

            if row in emails_sent:
                logging.info("Skipping row: {}".format(row))
                continue

            if send_email(row):
                record_sent(row, csv_writer)

                emails_sent.append(row)

def load_config():
    with io.open(pjoin(dirname(__file__), '..', 'config.json'), 'r') as f:
        config = json.load(f)
        global MAILGUN_API_KEY
        MAILGUN_API_KEY = config['mailgun_api_key']


def load_emails_sent(emails_sent_csv):
    if not os.path.exists(emails_sent_csv):
        with io.open(emails_sent_csv, 'w') as f:
            csv_writer = csv.DictWriter(f, CSV_HEADER, quoting=csv.QUOTE_ALL)
            csv_writer.writeheader()
        return []

    with io.open(emails_sent_csv, 'r') as f:
        return list(csv.DictReader(f))


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

    request_url = 'https://api.mailgun.net/v2/{0}/messages'.format(domain)

    try:
        response = requests.post(
            request_url,
            auth=('api', MAILGUN_API_KEY),
            data={
                'from': '"Paul M Furley" <paul@keyserver.paulfurley.com>',
                'to': row['primary_email'],
                'bcc': 'paul@paulfurley.com',
                'h:Reply-To': 'paul@paulfurley.com',
                'subject': email_subject,
                'text': email_body
        })
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
