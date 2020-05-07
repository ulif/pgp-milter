# -*- coding: utf-8 -*-
#
# tests for the `pgp` module.
#
import gnupg
from email.message import Message
from pgp_milter import pgp


def test_parse_raw():
    # we can turn raw messages into Message objects
    headers = [
        (b'Return-Path', b'<lauren@foobar.com>'),
        (b'Received', b'from foobar.com (localhost [127.0.0.1])'
         b'\n	by hemholt.foobar.com (8.9.3/8.8.7) with ESMTP id SAA03001;'
         b'\n	Mon, 29 Jan 2001 18:08:41 -0500'),
        (b'Sender', b'lauren@foobar.com'),
        (b'Message-ID', b'<3A75F7F6.CBF9E75@foobar.com>'),
        (b'Date', b'Mon, 29 Jan 2001 18:08:39 -0500'),
        (b'From', b'Lauren Hemholz <lauren@foobar.com>'),
        (b'Organization', b'Hemholtz Family'),
        (b'X-Mailer', b'Mozilla 4.76 [en] (X11; U; Linux 2.2.16-3 i586)'),
        (b'X-Accept-Language', b'en'),
        (b'MIME-Version', b'1.0'),
        (b'To', b'Jriser13@aol.com'),
        (b'Subject', b'Re: P.B.S kids'),
        (b'References', b'<e4.1045e74c.27a7018b@aol.com>'),
        (b'Content-Type', b'multipart/alternative;'
         b'\n boundary="------------7EC2082FC4F651D73FCD6FE1"'),
        (b'Status', b'O')
    ]
    body = open('tests/sample_body1.txt', 'rb').read().split(b"\n\n\n")[-1]
    parsed = pgp.parse_raw(headers, body)
    assert isinstance(parsed, Message)


def test_gpg_encrypt(tmpdir):
    # we can pgp encrypt text
    gpg = gnupg.GPG(gnupghome=str(tmpdir))
    ascii_key = open("tests/alice.pub", "r").read()
    gpg.import_keys(ascii_key)
    fpr = gpg.list_keys()[0]['fingerprint']
    msg = pgp.gpg_encrypt(gpg, "meet me at dawn", fpr)
    assert str(msg).startswith("-----BEGIN PGP MESSAGE-----")


def test_as_mime():
    # we can turn text into MIMEtext
    result = pgp.as_mime("meet me at dawn")
    assert result.as_string() == (
        'Content-Type: text/plain; charset="us-ascii"\n'
        'MIME-Version: 1.0\n'
        'Content-Transfer-Encoding: 7bit\n'
        '\n'
        'meet me at dawn')
