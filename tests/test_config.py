from pgp_milter.config import (
    OPTIONS_DEFAULTS,
    config_paths,
    )


def test_defaults_exist():
    # there is a set of defaults available
    assert OPTIONS_DEFAULTS is not None


def test_config_paths_are_absolute():
    # no relative paths, please
    paths = config_paths()
    assert [True, True, True] == [x.is_absolute() for x in paths]
