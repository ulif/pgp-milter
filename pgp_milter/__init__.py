# -*- coding: utf-8 -*-
import sys
import Milter
from argparse import ArgumentParser


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


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    args = handle_options(argv)
    if args.version:
        print_version()
        sys.exit(0)

# vim: expandtab ts=4 sw=4
