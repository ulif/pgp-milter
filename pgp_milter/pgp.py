# -*- coding: utf-8 -*-
#
# OpenPGP related stuff
#
from email.parser import Parser
from email.policy import default


def parse_raw(headers, body):
    """Turn headers and body of an email into message
    object.
    """
    str_headers = b'\n'.join([b'%s: %s' % (k, v) for k, v in headers])
    raw_msg = "%s\n\n\n%s" % (str_headers.decode(), body.decode())
    return Parser(policy=default).parsestr(raw_msg)


def gpg_encrypt(gpg, text, fpr):
    """Encrypt `text` for fingerprint `fpr`.
    """
    return gpg.encrypt(text, fpr, always_trust=True)
