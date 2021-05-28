# -*- coding: utf-8 -*-
import pathlib
from configparser import ConfigParser


OPTIONS_DEFAULTS = dict(
    socket="inet6:30072@[::1]",
    timeout=300,
    pgphome="~/.pgphome",
    bufsize=8192,
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


def get_config_dict():
    """Get a dict representing the config.

    All configuration values can be set in config files. We look in the
    locations given by `config_paths` and return a dict representing the
    default values or respective custom values.
    """
    result = dict(OPTIONS_DEFAULTS)
    parser = ConfigParser()
    parser.read_dict({"pgpmilter": OPTIONS_DEFAULTS})
    parser.read(config_paths())
    for key, val in OPTIONS_DEFAULTS.items():
        if isinstance(val, bool):
            result[key] = parser.getboolean("pgpmilter", key)
        elif isinstance(val, int):
            result[key] = parser.getint("pgpmilter", key)
        else:
            result[key] = parser.get("pgpmilter", key).strip("\"'")
    result["pgphome"] = str(pathlib.Path(result["pgphome"]).expanduser())
    return result
