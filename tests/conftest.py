import copy
import os
import pathlib
import pytest
from pgp_milter import PGPMilter


PATH_OF_TESTS = pathlib.Path(__file__).parent


@pytest.fixture()
def tpath():
    """A fixture providing the path to tests.
    """
    return PATH_OF_TESTS


@pytest.fixture(scope="function", autouse=True)
def home_dir(request, monkeypatch, tmpdir):
    """Provide a temporary user home.
    """
    _old_cwd = os.getcwd()
    tmpdir.mkdir("home")
    monkeypatch.setenv("HOME", str(tmpdir / "home"))
    os.chdir(str(tmpdir / "home"))
    os.mkdir(str(tmpdir / "home" / ".pgphome"))

    def teardown():
        os.chdir(_old_cwd)
    request.addfinalizer(teardown)
    return tmpdir / "home"


@pytest.fixture(scope="function", autouse=True)
def reset_pgpmilter_class_vars(request, monkeypatch):
    """Reset PGPMilter.config and PGPMilter.key_mgr after each test.
    """
    std_config = copy.deepcopy(PGPMilter.config)
    std_keymgr = copy.deepcopy(PGPMilter.key_mgr)

    def teardown():
        monkeypatch.setattr("pgp_milter.PGPMilter.config", std_config)
        monkeypatch.setattr("pgp_milter.PGPMilter.key_mgr", std_keymgr)
    request.addfinalizer(teardown)
