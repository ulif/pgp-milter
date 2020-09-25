import os
import pathlib
from pgp_milter.config import (
    OPTIONS_DEFAULTS,
    config_paths,
    get_config_dict,
    )


def test_defaults_exist():
    # there is a set of defaults available
    assert OPTIONS_DEFAULTS is not None


def test_config_paths_are_absolute():
    # no relative paths, please
    paths = config_paths()
    assert [True, True, True] == [x.is_absolute() for x in paths]


def test_get_config_dict(home_dir, monkeypatch):
    # os.chdir(home_dir)
    conf_path1 = home_dir / "pgpmilter1.conf"
    conf_path2 = home_dir / "pgpmilter2.conf"
    def fake_config_dict():
        return [conf_path1, conf_path2]
    monkeypatch.setattr("pgp_milter.config.config_paths", fake_config_dict)
    conf_path1.write("[pgpmilter]\nsocket = foo\ndebug = yes")
    conf_path2.write("[pgpmilter]\nsocket = bar\n")
    result = get_config_dict()
    assert result == {'debug': True, 'socket': 'bar'}
