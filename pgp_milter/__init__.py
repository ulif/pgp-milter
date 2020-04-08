# -*- coding: utf-8 -*-
import sys
import Milter
from argparse import ArgumentParser
from io import BytesIO


__version__ = "0.1.dev0"  # set also in setup.py


def print_version():
    """Output current version and copyright infos.
    """
    print("pgp-milter %s" % __version__)
    print("Copyright (C) 2020 Uli Fouquet")


def handle_options(args):
    """Handle commandline arguments.
    """
    parser = ArgumentParser(
        description=(
            "Mail filter for encrypting/decrypting mails on the fly"))
    parser.add_argument(
        '--version', action='store_true',
        help='output version information and exit.',
    )
    args = parser.parse_args(args)
    return args


class PGPMilter(Milter.Base):
    """A milter that currently does nothing.
    """

    def __init__(self):
        self._id = Milter.uniqueID()
        self.fp = None
        self.headers_seen = []

    @Milter.noreply
    def connect(self, ip_name, family, hostaddr):
        """A client connected to our server.

        We save only some basic connection data that might be interesting for
        logging.
        """
        self._ip = hostaddr[0]
        self._port = hostaddr[1]
        self._ip_name = ip_name
        return Milter.CONTINUE

    @Milter.noreply
    def envfrom(self, name, *esmtp_params):
        """Called on MAIL FROM.

        This is the sign for a new message. There might be multiple messages
        per connection.
        """
        if self.fp:
            self.fp.close()
        self.fp = BytesIO()
        return Milter.CONTINUE

    @Milter.noreply
    def envrcpt(self, name, *strings):
        """Called ON RCPT TO.
        """
        return Milter.CONTINUE

    @Milter.noreply
    def header(self, hkey, hval):
        """Called for each header line.
        """
        self.headers_seen.append((hkey, hval), )
        if self.fp:
            hline = '%s: %s' % (hkey, hval)
            self.fp.write(hline.encode())
        return Milter.CONTINUE

    def eoh(self):
        """Called when all headers have been processed.

        (end-of-headers)
        """
        if self.fp:
            self.fp.write(b'\n')
        return Milter.CONTINUE

    def body(self, chunk):
        """Called for each chunk of message body.
        """
        if self.fp:
            self.fp.write(chunk)
        return Milter.CONTINUE

    def eom(self):
        """Called when end of message is reached.
        """
        return Milter.CONTINUE

    def close(self):
        """Called when connection is closed.
        """
        if self.fp:
            self.fp.close()
        return Milter.CONTINUE


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    args = handle_options(argv)
    if args.version:
        print_version()
        sys.exit(0)

# vim: expandtab ts=4 sw=4
