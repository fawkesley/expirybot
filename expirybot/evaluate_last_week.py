#!/usr/bin/env python3

"""
- iterate through a list of short ids
- download the key for each short id
- if it expires in 3 days from now, add it to the output CSV
"""

import datetime
import logging
import io
import json

from collections import OrderedDict
from os.path import join as pjoin

import requests

from .utils import load_keys_from_csv, make_today_data_dir, setup_logging
from .keyserver_client import KeyserverClient
from .config import MAILGUN_API_KEY


def main():
    today = datetime.date.today()
    one_week_ago = today - datetime.timedelta(days=7)

    one_week_ago_data_dir = make_today_data_dir(one_week_ago)
    setup_logging(pjoin(one_week_ago_data_dir, 'evaluate.log'))

    logging.info("It's {} and I'm evaluating the performance of {}".format(
        today, one_week_ago))

    expiring_fingerprints = set(
        k.fingerprint for k in load_keys_from_csv(
            pjoin(one_week_ago_data_dir, 'keys_expiring.csv')
        )
    )

    emailed_fingerprints = set(
        k.fingerprint for k in load_keys_from_csv(
            pjoin(one_week_ago_data_dir, 'emails_sent.csv')
        )
    )

    not_emailed_fingerprints = expiring_fingerprints - emailed_fingerprints

    renewed_count_emailed = count_renewed_keys(emailed_fingerprints)
    renewed_count_control = count_renewed_keys(not_emailed_fingerprints)

    results = OrderedDict([
        ('date_today', today.isoformat()),
        ('date_evaluating', one_week_ago.isoformat()),
        ('keys_expiring', len(expiring_fingerprints)),
        ('keys_emailed', len(emailed_fingerprints)),
        ('keys_emailed_renewed', renewed_count_emailed),
        ('keys_emailed_renewed_pct',
            100 * renewed_count_emailed / len(emailed_fingerprints)),
        ('keys_not_emailed', len(not_emailed_fingerprints)),
        ('keys_not_emailed_renewed', renewed_count_control),
        ('keys_not_emailed_renewed_pct',
            100 * renewed_count_control / len(not_emailed_fingerprints))
    ])

    log_results(results)
    dump_results_to_json(results,
                         pjoin(one_week_ago_data_dir, 'evaluation.json'))
    email_results(results)


def log_results(results):

    logging.info("There were {} keys expiring of which we emailed {}".format(
        results['keys_expiring'], results['keys_emailed']))

    logging.info("{} / {} ({:.1f}%) of the keys we emailed have renewed vs "
                 "{} / {} ({:.1f}%) of the remaining keys".format(
                     results['keys_emailed_renewed'],
                     results['keys_emailed'],
                     results['keys_emailed_renewed_pct'],
                     results['keys_not_emailed_renewed'],
                     results['keys_not_emailed'],
                     results['keys_not_emailed_renewed_pct']))


def dump_results_to_json(results, filename):
    with io.open(filename, 'w') as f:
        json.dump(results, f, indent=4)


def email_results(results):
    domain = 'keyserver.paulfurley.com'
    request_url = 'https://api.mailgun.net/v2/{0}/messages'.format(domain)

    email_subject = (
        "{}/{} ({:.1f}%) renewed vs "
        "{}/{} ({:.1f}%) not emailed").format(
                results['keys_emailed_renewed'],
                results['keys_emailed'],
                results['keys_emailed_renewed_pct'],
                results['keys_not_emailed_renewed'],
                results['keys_not_emailed'],
                results['keys_not_emailed_renewed_pct']
    )

    email_body = json.dumps(results, indent=4)

    try:
        response = requests.post(
            request_url,
            auth=('api', MAILGUN_API_KEY),
            data={
                'from': '"Paul M Furley" <paul@keyserver.paulfurley.com>',
                'to': 'paul@paulfurley.com',
                'subject': email_subject,
                'text': email_body
                }
            )
        response.raise_for_status()

    except Exception as e:
        logging.exception(e)
        raise


def count_renewed_keys(fingerprints):
    keyserver_client = KeyserverClient()

    count = 0

    for fingerprint in fingerprints:
        key = keyserver_client.get_key_for_fingerprint(fingerprint)

        if not key.has_expired:
            logging.info("{} has renewed".format(fingerprint))
            count += 1

    return count


if __name__ == '__main__':
    main()
