import pgp_milter
import pkg_resources
import pytest
from pgp_milter import (
    __version__, handle_options, main
)


def test_importable():
    # we can import pgp_milter
    assert pgp_milter is not None


def test_version():
    # assure versions in setup.py and package match
    v1 = __version__
    v2 = pkg_resources.get_distribution('pgp_milter').version
    assert v1 == v2


def test_handle_options_defaults():
    # we can expect sensible defaults set
    args = handle_options([])
    assert args.version is False


def test_handle_options_version():
    # we support `--version'
    assert handle_options(['--version']).version is True
    assert handle_options([]).version is False


def test_main_version(capsys):
    # we can output the version
    with pytest.raises(SystemExit) as exc_info:
        main(['--version'])
    out, err = capsys.readouterr()
    assert str(__version__) in out
