import io

from os.path import dirname, join as pjoin

from contextlib import contextmanager

SAMPLE_DIR = pjoin(dirname(__file__), 'sample_data')


@contextmanager
def open_sample(name):
    with io.open(sample_filename(name), 'rb') as f:
        yield f


def sample_filename(name):
    return pjoin(SAMPLE_DIR, name)
