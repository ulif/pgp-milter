import mime
import pgp_milter
import pgpy
import pytest
import re
import Milter.testctx
from argparse import Namespace
from conftest import mime_structure
from email.parser import Parser
from io import BytesIO
from Milter.test import TestBase as MilterTestBase
from pathlib import Path
from pgp_milter import (
    __version__,
    handle_options,
    main,
    PGPMilter,
)
from pgp_milter import run as run_main
from pgp_milter.pgp import KeyManager
try:
    import importlib.metadata as importlib_metadata
except ImportError:  # Python < 3.8 # NOQA  # pragma: no cover
    import importlib_metadata

import pathlib
TESTS = pathlib.Path(__file__).parent


# A regular expression matching PGP MESSAGE blocks
RE_PGPMSG = re.compile(
    b".*(-----BEGIN PGP MESSAGE-----\n(.*)\n"
    b"-----END PGP MESSAGE-----\n).*", re.S)


class PGPTestMilter(MilterTestBase, PGPMilter):
    """A test milter wrapping PGPMilter
    """
    def __init__(self):
        MilterTestBase.__init__(self, logfile="milter.log")
        PGPMilter.__init__(self)


def test_importable():
    # we can import pgp_milter
    assert pgp_milter is not None


def test_version():
    # assure versions in setup.py and package match
    v1 = __version__
    v2 = importlib_metadata.version("pgp_milter")
    assert v1 == v2


def test_handle_options_defaults():
    # we can expect sensible defaults set
    args = handle_options([])
    assert args.version is False
    assert args.debug is False
    assert args.socket == "inet6:30072@[::1]"
    assert args.timeout == 300
    assert args.pgphome == str(Path(Path.home(), ".pgphome"))


def test_handle_options_debug():
    # we can enable debug mode
    assert handle_options([]).debug is False
    assert handle_options(["-d"]).debug is True
    assert handle_options(["--debug"]).debug is True


def test_handle_options_socket():
    # we can set a connection socket to bind to
    assert handle_options([]).socket == "inet6:30072@[::1]"
    assert handle_options(
        ["-s=inet:6666@1.1.1.1"]).socket == "inet:6666@1.1.1.1"
    assert handle_options(
        ["--socket=inet:6666@1.1.1.1"]).socket == "inet:6666@1.1.1.1"


def test_handle_options_version():
    # we support `--version'
    assert handle_options(["--version"]).version is True
    assert handle_options([]).version is False


def test_run(monkeypatch):
    # we can run milters
    def mock_runmilter(name, sock, timeout=300):
        Milter._mock_vals = [name, sock, timeout]
    config = Namespace(socket="inet6:2323@[::1]", timeout=200)
    monkeypatch.setattr("Milter.runmilter", mock_runmilter)
    monkeypatch.setattr("Milter._mock_vals", [], raising=False)
    result = run_main("testmilter", config)
    assert Milter.factory == PGPMilter
    assert Milter._mock_vals == ["testmilter", "inet6:2323@[::1]", 200]
    assert result is None


def test_main_version(capsys):
    # we can output the version
    with pytest.raises(SystemExit):
        main(["--version"])
    out, err = capsys.readouterr()
    assert str(__version__) in out


def test_main_sys_argv_considered(capsys, monkeypatch):
    # we consider args set in sys.argv if none are passed in
    monkeypatch.setattr("sys.argv", ["scriptname", "--version"])
    with pytest.raises(SystemExit):
        main()
    out, err = capsys.readouterr()
    assert str(__version__) in out


def test_main_calls_run(monkeypatch):
    # calling main w/o args will call `run`
    def mock_runmilter(name, sock, timeout=300):
        Milter._mock_vals = [name, sock, timeout]
    monkeypatch.setattr("sys.argv", ["scriptname"])
    monkeypatch.setattr("Milter.runmilter", mock_runmilter)
    monkeypatch.setattr("Milter._mock_vals", [], raising=False)
    assert PGPMilter.config.timeout == 200
    result = main()
    assert Milter.factory == PGPMilter
    assert Milter._mock_vals == ["pgpmilter", "inet6:30072@[::1]", 300]
    assert Milter.factory.config is not None
    assert result is None


def test_pgp_milter_constructable():
    # we can create PGPMilters
    m = PGPMilter()
    assert hasattr(m, "_id")
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
        assert ctx.getpriv()._ip_name == "sample.host"

    def test_header(self):
        # header lines are stored
        ctx = Milter.testctx.TestCtx()
        Milter.factory = PGPMilter
        ctx._connect()
        ctx.getpriv().fp = BytesIO()
        ctx._header("X-Foo", "foo")
        ctx._header("X-Foo", "bar")
        m = ctx.getpriv()
        m.fp.seek(0)
        assert m.fp.read() == b'X-Foo: foo\nX-Foo: bar\n'

    def test_header_without_fp(self):
        # we cope with the internal file descritor being closed
        ctx = Milter.testctx.TestCtx()
        Milter.factory = PGPMilter
        ctx._connect()
        ctx.getpriv().fp = None
        ctx._header("X-Foo", "foo")
        m = ctx.getpriv()
        assert m.headers_seen == [("X-Foo", "foo")]

    def test_eoh_adds_linebreak(self):
        # we add a linebreak when all headers were sent
        ctx = Milter.testctx.TestCtx()
        Milter.factory = PGPMilter
        ctx._connect()
        ctx.getpriv().fp = BytesIO()
        ctx._eoh()
        m = ctx.getpriv()
        m.fp.seek(0)
        assert m.fp.read() == b'\n'

    def test_eoh_copes_w_missing_fp(self):
        # eoh() copes with the internal file descriptor being closed
        ctx = Milter.testctx.TestCtx()
        Milter.factory = PGPMilter
        ctx._connect()
        ctx.getpriv().fp = None
        assert ctx._eoh() == Milter.CONTINUE

    def test_envfrom_blanks_seen_data(self):
        # stored messages and headers are blanked on each msg from
        ctx = Milter.testctx.TestCtx()
        Milter.factory = PGPMilter
        ctx._connect()
        ctx._envfrom("foo@bar")
        ctx._header("X-Foo", "foo")
        assert ctx.getpriv().fp is not None
        assert b"X-Foo" in ctx.getpriv().fp.getvalue()
        ctx._envfrom("bar@baz")
        assert b"X-Foo" not in ctx.getpriv().fp.getvalue()

    def test_envrcpt_stores_recipients(self):
        # we store all recipients sent by RCPT TO
        ctx = Milter.testctx.TestCtx()
        Milter.factory = PGPMilter
        ctx._connect()
        ctx._envfrom("<foo@bar>")
        rc1 = ctx._envrcpt("<bar@bar>")
        rc2 = ctx._envrcpt("<baz@bar>")
        assert rc1 == rc2 == Milter.CONTINUE
        assert ctx.getpriv().rcpts == ["<bar@bar>", "<baz@bar>"]

    def test_envrcpt_list_empty_on_beginning(self):
        # at the beginning the recipients list is empty
        ctx = Milter.testctx.TestCtx()
        Milter.factory = PGPMilter
        ctx._connect()
        assert ctx.getpriv().rcpts == []

    def test_envrcpt_reset_on_mailfrom(self):
        # on MAIL FROM, any recipients are removed
        ctx = Milter.testctx.TestCtx()
        Milter.factory = PGPMilter
        ctx._connect()
        ctx._envfrom("<foo@bar>")
        ctx._envrcpt("<bar@bar>")
        assert ctx.getpriv().rcpts == ["<bar@bar>"]
        ctx._envfrom("<foo@bar>")
        assert ctx.getpriv().rcpts == []

    def test_envrcpt_reset_on_close(self):
        # we remove recipients from our list when connection closes
        ctx = Milter.testctx.TestCtx()
        Milter.factory = PGPMilter
        ctx._connect()
        ctx._envfrom("<foo@bar>")
        ctx._envrcpt("<bar@bar>")
        assert ctx.getpriv().rcpts == ["<bar@bar>"]
        ctx._close()
        assert ctx.getpriv().rcpts == []

    def test_envrcpt_reset_on_abort(self):
        # we remove recipients from our list when connection is aborted
        ctx = Milter.testctx.TestCtx()
        Milter.factory = PGPMilter
        ctx._connect()
        ctx._envfrom("<foo@bar>")
        ctx._envrcpt("<bar@bar>")
        assert ctx.getpriv().rcpts == ["<bar@bar>"]
        ctx._abort()
        assert ctx.getpriv().rcpts == []

    def test_x_pgpmilter_header_added(self, tpath, home_dir):
        # the X-PGPMilter header is added during eom()
        milter = PGPTestMilter()
        milter.config = Namespace(pgphome=str(home_dir))
        assert milter.connect() == Milter.CONTINUE
        with (tpath / "samples" / "full-mail01").open("rb") as fp:
            rc = milter.feedFile(fp)
            assert rc == Milter.ACCEPT
        assert "X-PGPMilter" in milter._msg.keys()
        assert milter._bodyreplaced is False
        milter.logfp.close()

    def test_eom_encrypting(self, home_dir, tpath):
        # eom() can encrypt messages
        key = tpath.joinpath("alice3.pub").read_text()
        milter = PGPTestMilter()
        home_dir.join(".pgphome", "OpenPGP_0x00000000000000A3.asc").write(key)
        milter.key_mgr = KeyManager(path=str(home_dir / ".pgphome"))
        assert milter.connect() == Milter.CONTINUE
        with tpath.joinpath("samples", "full-mail01").open("rb") as fp:
            rc = milter.feedFile(fp, rcpt="alice@sample.net")
            assert rc == Milter.ACCEPT
        assert "X-PGPMilter" in milter._msg.keys()
        assert milter._bodyreplaced is True
        priv_key, _ = pgpy.PGPKey.from_file(str(tpath / "alice3.sec"))
        milter._body.seek(0)
        enc_msg = RE_PGPMSG.match(milter._body.read()).groups()[0]
        dec_msg = priv_key.decrypt(
            pgpy.PGPMessage.from_blob(enc_msg))
        assert dec_msg.is_encrypted is False
        dec_mime_msg = Parser().parsestr(dec_msg.message)
        assert mime_structure(dec_mime_msg) == (
            '└┬multipart/mixed \n'
            ' ├─text/rfc822-headers \n'
            ' └┬multipart/alternative \n'
            '  ├─text/plain \n'
            '  └─text/html \n'
        )
        milter.logfp.close()

    def test_eom_leaves_headercontent(self, home_dir, tpath):
        # headerfields might be moved, but are not changed
        # We try to leave headerfields untouched.
        key = tpath.joinpath("alice3.pub").read_text()
        milter = PGPTestMilter()
        home_dir.join(".pgphome", "OpenPGP_0x00000000000000A3.asc").write(key)
        milter.key_mgr = KeyManager(path=str(home_dir / ".pgphome"))
        assert milter.connect() == Milter.CONTINUE
        with (tpath / "samples" / "full-mail03").open("rb") as fp:
            rc = milter.feedFile(fp, rcpt="alice@sample.net")
            assert rc == Milter.ACCEPT
        assert "X-PGPMilter" in milter._msg.keys()
        assert milter._bodyreplaced is True
        milter._body.seek(0)
        content = milter._body.read()
        # should not contain encoding settings
        assert "Ümlaut" in content.decode('utf-8')
        milter.logfp.close()

    def test_eom_leaves_encrypted_untouched(self, home_dir, tpath):
        # we do not reencrypt already encrypted messages
        key = tpath.joinpath("alice3.pub").read_text()
        milter = PGPTestMilter()
        home_dir.join(".pgphome", "OpenPGP_0x00000000000000A3.asc").write(key)
        milter.key_mgr = KeyManager(path=str(home_dir / ".pgphome"))
        assert milter.connect() == Milter.CONTINUE
        with (tpath / "samples" / "full-mail01-enc").open("rb") as fp:
            rc = milter.feedFile(fp, rcpt="alice@sample.net")
            assert rc == Milter.ACCEPT
        assert "X-PGPMilter" in milter._msg.keys()
        assert milter._bodyreplaced is False
        milter.logfp.close()

    def test_update_headers(self, home_dir, tpath):
        # we can update complete sets of headers
        milter = PGPTestMilter()
        milter._body = "1"
        msg1 = mime.message_from_file(
            BytesIO(b'A: foo\nB: bar\n\n\ntest\n'))
        milter._msg = msg1
        msg2 = mime.message_from_file(
            BytesIO(b'C: baz\nD: bat\n\n\ntest\n'))
        milter.update_headers(msg1, msg2)
        assert milter._msg.items() == msg2.items()
        milter.logfp.close()

    def test_update_headers_multiple(self, home_dir, tpath):
        # we can update headers where some names are repeated
        milter = PGPTestMilter()
        milter._body = "1"
        msg1 = mime.message_from_file(
            BytesIO(b'A: foo\nB: bar\nA: baz\n\n\ntest\n'))
        milter._msg = msg1
        msg2 = mime.message_from_file(
            BytesIO(b'A: foo\nC: baz\nA: baz\n\n\ntest\n'))
        milter.update_headers(msg1, msg2)
        assert milter._msg.items() == msg2.items()
        milter.logfp.close()

    def test_close_closes_also_fp(self):
        # the local filepointer is closed then the connection closes.
        ctx = Milter.testctx.TestCtx()
        Milter.factory = PGPMilter
        ctx._connect()
        ctx._envfrom("foo@bar")
        ctx._header("X-Foo", "foo")
        assert ctx.getpriv().fp.closed is False
        ctx._close()
        assert ctx.getpriv().fp.closed is True

    def test_close_copes_with_closed_fp(self):
        # closing call copes with removed internal filepointer
        ctx = Milter.testctx.TestCtx()
        Milter.factory = PGPMilter
        ctx._connect()
        ctx._envfrom("foo@bar")
        ctx._header("X-Foo", "foo")
        ctx.getpriv().fp = None
        assert ctx._close() is None


# vim: expandtab ts=4 sw=4
