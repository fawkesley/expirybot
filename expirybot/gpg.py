from os.path import abspath, dirname, join as pjoin

import subprocess
import logging

SIGN_TEXT = abspath(pjoin(dirname(__file__), 'gpg_wrapper', 'sign_text'))


class SigningError(RuntimeError):
    pass


def sign_text(text):
    if not isinstance(text, str):
        raise TypeError("Expected string, got {}".format(type(text)))

    cmd_parts = [
        SIGN_TEXT
    ]

    p = subprocess.Popen(
        cmd_parts,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    try:
        stdout, stderr = p.communicate(
            input=text.encode('utf-8'),
            timeout=5
        )
    except subprocess.TimeoutExpired as e:
        p.kill()
        stdout, stderr = p.communicate()
        logging.exception(e)
        raise SigningError('Command timed out')
    else:
        if p.returncode != 0:
            raise SigningError(
                'failed with code {} stdout: {} stderr: {}'.format(
                    p.returncode, stdout, stderr
                )
            )

    if stdout is None:
        raise SigningError('Got back empty stdout')
        stdout = b''

    if stderr is None:
        stderr = b''

    return stdout.decode('utf-8')


if __name__ == '__main__':
    print(sign_text('hello'))
