import pytest


@pytest.fixture(scope="function")
def home_dir(request, monkeypatch, tmpdir):
    """Provide a temporary user home.
    """
    tmpdir.mkdir("home")
    monkeypatch.setenv("HOME", str(tmpdir / "home"))
    return tmpdir / "home"
