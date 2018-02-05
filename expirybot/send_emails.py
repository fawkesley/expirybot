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
from .requests_wrapper import RequestsWithSessionAndUserAgent
from .utils import (
    make_today_data_dir, load_keys_from_csv, write_key_to_csv, setup_logging
)
from .gpg import sign_text


EMAILS_TO_SEND = 500

# We're trying to limit to 100 emails per hour to keep under Mailgun's
# restriction.
# Mailgun counts an email with multiple To: recipients as multiple emails, so
# we need to limit further than 100 per hour.
EMAILS_PER_HOUR = 70
ONE_HOUR = 60 * 60


class ExpiryEmail():
    """
    Render an expiry email for the given PGP key.
    """

    def __init__(self, key):
        self.key = key
        self.ok_to_send = False

        if not self._get_uid():
            return

        if not self._get_unsubscribe_link():
            return

        data = {
            'fingerprint': key.fingerprint,
            'zero_x_fingerprint': key.zero_x_fingerprint,
            'key_id': key.long_id,
            'friendly_expiry_date': key.friendly_expiry_date,
            'days_until_expiry': key.days_until_expiry,
            'email_address': self.__uid.email,
            'unsubscribe_link': self.unsubscribe_link
        }

        self.__unsigned_body = load_template('email_body.txt').format(**data)
        self.subject = load_template(
            'email_subject.txt'
        ).format(**data).rstrip()

        self.to = self.__uid.email_line
        self.from_line = config.from_line
        self.reply_to = config.reply_to

        self.ok_to_send = True

    def _get_uid(self):
        self.__uid = self.key.most_likely_uid()
        return self.__uid is not None

    def _get_unsubscribe_link(self):
        self.unsubscribe_link = make_unsubscribe_link(self.__uid.email)
        return self.unsubscribe_link is not None

    @property
    def list_unsubscribe_header(self):
        if self.unsubscribe_link is not None:
            return '<{}>'.format(self.unsubscribe_link)
        else:
            return ''

    @property
    def body(self):
        return sign_text(self.__unsigned_body)


def make_unsubscribe_link(email, http=None):
    http = http or RequestsWithSessionAndUserAgent()

    response = http.get(
        'https://www.expirybot.com/apiv1/blacklist/unsubscribe-link/',
        params={
            'email_address': email
        },
        headers={
            'Authorization': 'Token {}'.format(config.expirybot_api_token),
        }
    )

    response.raise_for_status()
    data = response.json()

    logging.info(data)

    if data['allow_email']:
        return data.get('unsubscribe_link', None)
    else:
        return None


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
    if not email.ok_to_send:
        return False

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
                'h:List-Unsubscribe': email.list_unsubscribe_header,
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
