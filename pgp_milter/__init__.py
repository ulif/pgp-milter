# -*- coding: utf-8 -*-
import sys
import Milter
from argparse import ArgumentParser
from io import BytesIO


__version__ = "0.1.dev0"  # set also in setup.py


# Default values
BINDADDR = '[::1]'
PORT = '30072'


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
            "Mail filter for PGP-encrypting/decrypting mails on the fly"
        )
    )
    parser.add_argument(
        "--debug", "-d",
        default=False,
        action="store_true",
        help="Enable debug output."),
    parser.add_argument(
        "--socket", "-s",
        type=str,
        default="inet6:{0}@{1}".format(PORT, BINDADDR),
        help="IPv4, IPv6 or unix socket (default: %(default)s)")
    parser.add_argument(
        "--version",
        action="store_true",
        help="output version information and exit.",
    )
    args = parser.parse_args(args)
    return args


class PGPMilter(Milter.Base):
    """A milter that currently does nothing.
    """

    def __init__(self):
        self._id = Milter.uniqueID()
        self._ip = None
        self._ip_name = None
        self._port = None

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
        print("Connect from %s[%s]:%s" % (
            self._ip_name,
            self._ip,
            self._port))
        return Milter.CONTINUE

    @Milter.noreply
    def envfrom(self, name, *esmtp_params):
        """Called on MAIL FROM.

        This is the sign for a new message. There might be multiple messages
        per connection.
        """
        if hasattr(self, "fp") and self.fp:
            self.fp.close()
        self.headers_seen = []
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
        self.headers_seen.append((hkey, hval),)
        if self.fp:
            hline = "%s: %s" % (hkey, hval)
            self.fp.write(hline.encode())
        return Milter.CONTINUE

    def eoh(self):
        """Called when all headers have been processed.

        (end-of-headers)
        """
        if self.fp:
            self.fp.write(b"\n")
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


def run(name, sock, timeout=300):
    """Start a milter loop.
    """
    Milter.factory = PGPMilter
    Milter.set_flags(Milter.CHGHDRS + Milter.ADDHDRS + Milter.CHGBODY)
    Milter.runmilter(name, sock, timeout=timeout)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    args = handle_options(argv)
    if args.version:
        print_version()
        sys.exit(0)
    run('pgpmilter', args.socket)


# vim: expandtab ts=4 sw=4
