import os
import pytest


@pytest.fixture(scope="function", autouse=True)
def home_dir(request, monkeypatch, tmpdir):
    """Provide a temporary user home.
    """
    _old_cwd = os.getcwd()
    tmpdir.mkdir("home")
    monkeypatch.setenv("HOME", str(tmpdir / "home"))
    os.chdir(str(tmpdir / "home"))

    def teardown():
        os.chdir(_old_cwd)
    request.addfinalizer(teardown)
    return tmpdir / "home"
