import os
import pathlib
import pytest


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
def reset_config(monkeypatch):
    """Reset PGPMilter.config before/after each test.
    """
    monkeypatch.setattr("pgp_milter.PGPMilter.config", None)
    monkeypatch.setattr("pgp_milter.PGPMilter.key_mgr", None)
