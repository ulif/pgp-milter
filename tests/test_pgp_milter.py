import pgp_milter
import pkg_resources
import pytest
import Milter.testctx
from pgp_milter import (
    __version__, handle_options, main, PGPMilter,
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
    with pytest.raises(SystemExit):
        main(['--version'])
    out, err = capsys.readouterr()
    assert str(__version__) in out


def test_main_sys_argv_considered(capsys, monkeypatch):
    # we consider args set in sys.argv if none are passed in
    monkeypatch.setattr("sys.argv", ["scriptname", "--version"])
    with pytest.raises(SystemExit):
        main()
    out, err = capsys.readouterr()
    assert str(__version__) in out


def test_pgp_milter_constructable():
    # we can create PGPMilters
    m = PGPMilter()
    assert hasattr(m, '_id')
    assert isinstance(m, PGPMilter)


class TestPGPMilter(object):

    def test_create(self):
        # we can create PGPMilters
        assert PGPMilter() is not None

    def test_connect(self):
        # we handle connects properly
        ctx = Milter.testctx.TestCtx()
        Milter.factory = PGPMilter
        rc = ctx._connect("sample.host")
        assert rc == Milter.NOREPLY
        assert ctx.getpriv()._ip_name == 'sample.host'

    def test_header(self):
        # header lines are stored
        ctx = Milter.testctx.TestCtx()
        Milter.factory = PGPMilter
        ctx._connect()
        ctx._header("X-Foo", "foo")
        ctx._header("X-Foo", "bar")
        m = ctx.getpriv()
        assert m.headers_seen == [
                ('X-Foo', 'foo'),
                ('X-Foo', 'bar')]

    def test_eoh(self):
        # we are called back on end of headers
        ctx = Milter.testctx.TestCtx()
        Milter.factory = PGPMilter
        ctx._connect()
        with open("tests/sample_body1.txt", "rb") as fp:
            ctx._feedFile(fp)
        rc = ctx._eoh()
        m = ctx.getpriv()
        assert rc == Milter.CONTINUE
        assert ctx._msg['To'] == 'Jriser13@aol.com'
        assert ('To', 'Jriser13@aol.com') in m.headers_seen

    def test_eom(self):
        # we are called back on end of message
        ctx = Milter.testctx.TestCtx()
        Milter.factory = PGPMilter
        ctx._connect()
        with open("tests/sample_body1.txt", "rb") as fp:
            rc = ctx._feedFile(fp)
        assert rc == Milter.CONTINUE
        assert ctx._body.getvalue().startswith(b"Return-Path:")
        rc = ctx._eom()
        assert rc == Milter.CONTINUE
        assert ctx._msg['To'] == 'Jriser13@aol.com'

# vim: expandtab ts=4 sw=4
