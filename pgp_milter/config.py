# -*- coding: utf-8 -*-
import pathlib
from configparser import ConfigParser


OPTIONS_DEFAULTS = dict(
    socket="inet6:12345@localhost",
    debug=False,
)


def config_paths():
    """Paths, where we look for config files.
    """
    return [
        pathlib.Path("/etc/pgpmilter.cfg").absolute(),
        pathlib.Path(pathlib.Path.home(), ".pgpmilter.cfg").absolute(),
        pathlib.Path("pgpmilter.cfg").absolute(),
        ]
