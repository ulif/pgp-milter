# -*- coding: utf-8 -*-
import sys
import Milter
from argparse import ArgumentParser, Namespace
from email import message_from_binary_file
from email.policy import default as default_policy
from io import BytesIO
from pgp_milter.config import get_config_dict
from pgp_milter.pgp import encrypt_msg, prepare_pgp_lookups


__version__ = "0.1.dev0"  # set also in setup.py


def print_version():
    """Output current version and copyright infos.
    """
    print("pgp-milter %s" % __version__)
    print("Copyright (C) 2020 Uli Fouquet")


def handle_options(args):
    """Handle commandline arguments.
    """
    defaults = get_config_dict()
    parser = ArgumentParser(
        description=(
            "Mail filter for PGP-encrypting/decrypting mails on the fly"
        )
    )
    parser.add_argument(
        "--debug", "-d",
        action="store_true",
        help="Enable debug output."),
    parser.add_argument(
        "--socket", "-s",
        type=str,
        help="IPv4, IPv6 or unix socket (default: %(default)s)")
    parser.add_argument(
        "--pgphome", "-p",
        type=str,
        help="home for pgp keys (default: %(default)s)")
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        help="timeout in seconds for connections.")
    parser.add_argument(
        "--bufsize", "-b",
        type=int,
        help="buffer size in bytes when feeding MTA (default: %(default)s)")
    parser.add_argument(
        "--version",
        action="store_true",
        help="output version information and exit.",
    )
    parser.set_defaults(**defaults)
    args = parser.parse_args(args)
    return args


class PGPMilter(Milter.Base):
    """A milter that currently does nothing.
    """

    config = None

    def __init__(self):
        self._id = Milter.uniqueID()
        self._ip = None
        self._ip_name = None
        self._port = None

        self.fp = None
        self.headers_seen = []
        self.rcpts = []
        self.config = Namespace(**get_config_dict())

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
        self.rcpts = []     # reset list of recipients
        return Milter.CONTINUE

    @Milter.noreply
    def envrcpt(self, name, *strings):
        """Called ON RCPT TO.
        """
        self.rcpts.append(name)
        return Milter.CONTINUE

    @Milter.noreply
    def header(self, hkey, hval):
        """Called for each header line.
        """
        self.headers_seen.append((hkey, hval),)
        if self.fp:
            hline = "%s: %s\n" % (hkey, hval)
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
        if self.fp:               # pragma: no branch
            self.fp.write(chunk)
        return Milter.CONTINUE

    def eom(self):
        """Called when end of message is reached.
        """
        self.addheader(
                "X-PGPMilter", "Scanned by PGPMilter %s" % __version__, -1)
        self.fp.seek(0)
        msg = message_from_binary_file(self.fp, policy=default_policy)
        changed, new_msg = encrypt_msg(msg, self.rcpts, self.config.pgphome)
        if not changed:
            return Milter.ACCEPT
        self.update_headers(msg, new_msg)
        fp = BytesIO(new_msg.as_bytes().split(b'\n\n', 1)[1])
        while True:
            buf = fp.read(self.config.bufsize)
            if len(buf) == 0:
                break
            self.replacebody(buf)
        return Milter.ACCEPT

    def close(self):
        """Called when connection is closed.
        """
        self.rcpts = []
        if self.fp:
            self.fp.close()
        return Milter.CONTINUE

    def update_headers(self, old_msg, new_msg):
        """Replace headerfields from `old_msg` by the ones of `new_msg`.
        """
        # delete old values
        for name in set(old_msg.keys()):
            for n in range(len(old_msg.get_all(name)), 0, -1):
                self.chgheader(name, n-1, '')
        # add current headers
        for name, val in new_msg.items():
            self.addheader(name, val)


def run(name, config):
    """Start a milter loop.
    """
    Milter.factory = PGPMilter
    Milter.factory.config = config
    Milter.set_flags(Milter.ADDHDRS + Milter.CHGHDRS + Milter.CHGBODY)
    Milter.runmilter(name, config.socket, timeout=config.timeout)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    args = handle_options(argv)
    if args.version:
        print_version()
        sys.exit(0)
    prepare_pgp_lookups(args)
    run('pgpmilter', args)


# vim: expandtab ts=4 sw=4
