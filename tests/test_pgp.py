# -*- coding: utf-8 -*-
#
# tests for the `pgp` module.
#
from email.message import Message
from pgp_milter import pgp


def test_parse_raw():
    # we can turn raw messages into Message objects
    headers = [
        (b'Return-Path', b'<lauren@foobar.com>'),
        (b'Received', b'from foobar.com (localhost [127.0.0.1])\n	by hemholt.foobar.com (8.9.3/8.8.7) with ESMTP id SAA03001;\n	Mon, 29 Jan 2001 18:08:41 -0500'),
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
        (b'Content-Type', b'multipart/alternative;\n boundary="------------7EC2082FC4F651D73FCD6FE1"'),
        (b'Status', b'O')
    ]
    body = open('tests/sample_body1.txt', 'rb').read().split(b"\n\n\n")[-1]
    parsed = pgp.parse_raw(headers, body)
    assert isinstance(parsed, Message)
