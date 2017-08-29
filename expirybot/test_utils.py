import io

from os.path import dirname, join as pjoin

from contextlib import contextmanager


@contextmanager
def open_sample(name):
    fn = pjoin(dirname(__file__), 'sample_data', name)
    with io.open(fn, 'rb') as f:
        yield f
