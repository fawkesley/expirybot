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

from .config import MAILGUN_API_KEY, FINGERPRINT_CSV_HEADER, BLACKLISTED_DOMAINS
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
        csv_writer = csv.DictWriter(g, FINGERPRINT_CSV_HEADER, quoting=csv.QUOTE_ALL)

        for key in filter_emails(load_keys_from_csv(keys_expiring_csv)):
            if len(key_ids_already_emailed) >= EMAILS_TO_SEND:
                logging.info("Stopping now, sent {} emails".format(
                    len(key_ids_already_emailed)))
                break

            if key.long_id in key_ids_already_emailed:
                logging.info("Already emailed key: {}".format(key))
                continue

            if send_email(key):
                write_key_to_csv(key, csv_writer)
                key_ids_already_emailed.add(key.long_id)


def filter_emails(keys):
    def has_email(key):
        return key.primary_email is not None

    def not_blacklisted(key):
        _, domain = key.primary_email.split('@', 1)
        blacklisted = domain.lower() in BLACKLISTED_DOMAINS

        if blacklisted:
            logging.info("Skipping blacklisted domain: {}".format(key.primary_email))

        return not blacklisted

    return filter(not_blacklisted, filter(has_email, keys))


def load_key_ids_already_emailed(emails_sent_csv):
    if not os.path.exists(emails_sent_csv):
        with io.open(emails_sent_csv, 'w') as f:
            csv_writer = csv.DictWriter(f, FINGERPRINT_CSV_HEADER, quoting=csv.QUOTE_ALL)
            csv_writer.writeheader()
        return set([])

    return set([key.long_id for key in load_keys_from_csv(emails_sent_csv)])


def load_template(name):
    with io.open(pjoin(dirname(__file__), 'templates', name), 'r') as f:
        return f.read()


def send_email(key):
    logging.info("send_email: {}".format(key))

    data = {
        'fingerprint': key.fingerprint,
        'key_id': key.long_id,
        'friendly_expiry_date': key.friendly_expiry_date,
        'days_until_expiry': key.days_until_expiry
    }

    email_body = load_template('email_body.txt').format(**data)
    email_subject = load_template('email_subject.txt').format(**data)

    to = key.primary_email

    logging.info("About to send email to {}:\nSubject: {}\n{}".format(
        to, email_subject, email_body)
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
                'to': to,
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


if __name__ == '__main__':
    main()
