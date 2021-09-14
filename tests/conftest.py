import copy
import io
import os
import pathlib
import pytest
import sys
from pgp_milter import PGPMilter


PATH_OF_TESTS = pathlib.Path(__file__).parent


# adapted from notmuch:devel/printmimestructure
# adapted from autocrypt:memoryhole/generators/render_mime_structure
def render_mime_structure(z, prefix='└', stream=sys.stdout):
    # z should be an email.message.Message object
    fname = '' if z.get_filename() is None else ' [' + z.get_filename() + ']'
    cset = '' if z.get_charset() is None else ' (' + str(z.get_charset()) + ')'
    disp = z.get_params(None, header='Content-Disposition')
    disposition = '' if disp is None else ''.join(
            [' ' + x[0] for x in disp if x[0] in ['attachment', 'inline']])
    subject = '' if 'subject' not in z else ' (Subject: %s)' % z['subject']

    if (z.is_multipart()):
        print("%s┬%s%s%s%s %s bytes %s" % (
            prefix, z.get_content_type(), cset, disposition, fname,
            str(len(z.as_string())), subject), file=stream)
        if prefix.endswith('└'):
            prefix = prefix[:-1] + ' '
        if prefix.endswith('├'):
            prefix = prefix[:-1] + '│'
        parts = z.get_payload()
        for i, part in enumerate(parts):
            prefix_ext = '├' if i < len(parts) - 1 else '└'
            render_mime_structure(part, prefix + prefix_ext, stream=stream)
    else:
        print("%s─%s%s%s%s %s bytes %s" % (
            prefix, z.get_content_type(), cset, disposition, fname,
            str(len(z.as_string())), subject), file=stream)


def mime_structure(msg):
    # msg should be an email.message.Message object
    with io.StringIO() as fp:
        render_mime_structure(msg, stream=fp)
        fp.seek(0)
        return fp.read()


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
