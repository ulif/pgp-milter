import pgp_milter
import pkg_resources
from pgp_milter import (
    __version__, handle_options
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
