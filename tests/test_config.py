from pathlib import Path
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
    conf_path1 = home_dir / "pgpmilter1.conf"
    conf_path2 = home_dir / "pgpmilter2.conf"

    def fake_config_dict():
        return [conf_path1, conf_path2]
    monkeypatch.setattr("pgp_milter.config.config_paths", fake_config_dict)
    conf_path1.write("[pgpmilter]\nsocket = foo\ndebug = yes")
    conf_path2.write("[pgpmilter]\nsocket = bar\n")
    result = get_config_dict()
    pgphome = str(Path(Path.home(), ".pgphome"))
    assert result == {
        'debug': True, 'socket': 'bar', 'timeout': 300,
        'bufsize': 8192, 'pgphome': pgphome
    }


def test_get_config_reads_in_right_order(home_dir):
    # the config files are read in right order.
    # ./pgpmilter.cfg overrides ~/.pgpmilter.cfg overrides /etc/pgpmilter.cfg
    path1 = home_dir / "pgpmilter.cfg"
    path2 = home_dir / ".pgpmilter.cfg"
    assert get_config_dict()["socket"] == OPTIONS_DEFAULTS["socket"]
    path2.write("[pgpmilter]\nsocket = bat\n")
    assert get_config_dict()["socket"] == "bat"
    path1.write("[pgpmilter]\nsocket = baz\n")
    assert get_config_dict()["socket"] == "baz"
