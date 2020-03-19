import pgp_milter
import pkg_resources
from pgp_milter import handle_options


def test_importable():
    # we can import pgp_milter
    assert pgp_milter is not None


def test_version():
    # assure versions in setup.py and package match
    v1 = pgp_milter.__version__
    v2 = pkg_resources.get_distribution('pgp_milter').version
    assert v1 == v2

def test_handle_options_version():
    # we support `--version'
    assert handle_options(['--version']).version is True
    assert handle_options([]).version is False
