#!/usr/bin/env python3

"""
- load all the emails we've currently sent from emails_sent
- work thru the rows in keys expiring CSV
- send emails to N people we haven't already emailed
"""

import contextlib
import csv
import datetime
import io
import logging
import os

from os.path import dirname, join as pjoin

import ratelimit
from requests import HTTPError

from .config import config
from .exclusions import is_blacklisted
from .requests_wrapper import RequestsWithSessionAndUserAgent
from .utils import (
    make_today_data_dir, load_keys_from_csv, write_key_to_csv, setup_logging
)


EMAILS_TO_SEND = 500

# We're trying to limit to 100 emails per hour to keep under Mailgun's
# restriction.
# Mailgun counts an email with multiple To: recipients as multiple emails, so
# we need to limit further than 100 per hour.
EMAILS_PER_HOUR = 70
ONE_HOUR = 60 * 60


class ExpiryEmail():
    def __init__(self, key):
        data = {
            'fingerprint': key.fingerprint,
            'key_id': key.long_id,
            'friendly_expiry_date': key.friendly_expiry_date,
            'days_until_expiry': key.days_until_expiry
        }

        self.body = load_template('email_body.txt').format(**data)
        self.subject = load_template(
            'email_subject.txt'
        ).format(**data).rstrip()

        self.to = ', '.join(self._unblacklisted_email_lines(key)[0:10])
        self.from_line = config.from_line
        self.reply_to = config.reply_to

    @staticmethod
    def _unblacklisted_email_lines(key):
        uids_with_emails = filter(
            lambda uid: uid.email is not None,
            key.uids
        )
        unblacklisted_uids = filter(
            lambda uid: not is_blacklisted(uid.domain),
            uids_with_emails
        )

        return list(
            map(
                lambda uid: uid.email_line,
                unblacklisted_uids
            )
        )


def main():
    today_data_dir = make_today_data_dir(datetime.date.today())

    setup_logging(pjoin(today_data_dir, 'send_emails.log'))

    keys_expiring_fn = pjoin(today_data_dir, 'keys_expiring.csv')
    emails_sent_fn = pjoin(today_data_dir, 'emails_sent.csv')

    key_ids_already_emailed = load_key_ids_already_emailed(
        emails_sent_fn
    )
    logging.info("Already sent {} emails".format(len(key_ids_already_emailed)))

    with setup_output_csvs(emails_sent_fn) as emails_sent_csv:

        send_emails_for_keys(
            load_keys_from_csv(keys_expiring_fn),
            emails_sent_csv,
            key_ids_already_emailed
        )


@contextlib.contextmanager
def setup_output_csvs(emails_sent_fn):

    with io.open(emails_sent_fn, 'a', 1) as f:

        emails_sent_csv = csv.DictWriter(
            f, config.csv_header, quoting=csv.QUOTE_ALL
        )

        yield emails_sent_csv


def send_emails_for_keys(keys, emails_sent_csv, key_ids_already_emailed):

    for key in keys:
        if len(key_ids_already_emailed) >= EMAILS_TO_SEND:
            logging.info("Stopping now, sent {} emails".format(
                len(key_ids_already_emailed)))
            break

        if key.long_id in key_ids_already_emailed:
            logging.info("Already emailed key: {}".format(key))

        elif send_email(key):
            logging.info("Emailed {}".format(key))
            write_key_to_csv(key, emails_sent_csv)
            key_ids_already_emailed.add(key.long_id)

        else:
            logging.warn("Failed emailing {}".format(key))


def load_key_ids_already_emailed(emails_sent_csv):
    if not os.path.exists(emails_sent_csv):
        with io.open(emails_sent_csv, 'w') as f:
            csv_writer = csv.DictWriter(
                f, config.csv_header, quoting=csv.QUOTE_ALL)
            csv_writer.writeheader()
        return set([])

    return set([key.long_id for key in load_keys_from_csv(emails_sent_csv)])


def load_template(name):
    with io.open(pjoin(dirname(__file__), 'templates', name), 'r') as f:
        return f.read()


def send_email(key):
    email = ExpiryEmail(key)

    logging.info("About to send email for {} to `{}`\nSubject: {}".format(
        key, email.to, email.subject)
    )
    logging.debug(email.body)

    return send_with_mailgun(email)


@ratelimit.rate_limited(EMAILS_PER_HOUR, ONE_HOUR)
def send_with_mailgun(email, http=None):

    http = http or RequestsWithSessionAndUserAgent()

    request_url = 'https://api.mailgun.net/v2/{0}/messages'.format(
        config.mailgun_domain
    )

    try:
        response = http.post(
            request_url,
            auth=('api', config.mailgun_api_key),
            data={
                'from': email.from_line,
                'to': email.to,
                'h:Reply-To': email.reply_to,
                'subject': email.subject,
                'text': email.body
                }
            )
    except Exception as e:
        logging.exception(e)
        raise

    try:
        response.raise_for_status()
    except HTTPError as e:
        logging.exception(e)
        logging.error('Status: {0}'.format(response.status_code))
        logging.error('Body:   {0}'.format(response.text))
        raise HTTPError(*e.args + (' body: ' + response.text,))

    return True


if __name__ == '__main__':
    main()
