import pgp_milter
import pkg_resources


def test_importable():
    # we can import pgp_milter
    assert pgp_milter is not None


def test_version():
    # assure versions in setup.py and package match
    v1 = pgp_milter.__version__
    v2 = pkg_resources.get_distribution('pgp_milter').version
    assert v1 == v2
