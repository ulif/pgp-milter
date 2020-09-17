from pgp_milter.config import (
    OPTIONS_DEFAULTS,
    )


def test_defaults_exist():
    # there is a set of defaults available
    assert OPTIONS_DEFAULTS is not None
