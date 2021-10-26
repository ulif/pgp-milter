# -*- coding: utf-8 -*-
#
# tests for the `pgp` module.
#
import os
import pgpy
import re
from conftest import mime_structure
from copy import deepcopy
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import Message
from email.parser import Parser, BytesParser
from email.policy import default as default_policy, compat32
from pgp_milter import pgp


# PGP fingerprints
FPR_ALICE = "FC576D66A075141F41770B15F028476ACE63FE41"
FPR_ALICE2 = "BC8E0FFE80B27CAB91D6D2315B1D44F70BA91072"
FPR_ALICE3 = "CB0374057FD3EEC52D39B467524AE6A48F5EB464"
FPR_BOB = "FDBE48E6FE58D021A5C8BE3B982AD46FA8789D5C"


# Paths to PGP public keys
PUBKEY_PATH_ALICE = os.path.join(os.path.dirname(__file__), "alice.pub")
PUBKEY_PATH_ALICE2 = os.path.join(os.path.dirname(__file__), "alice2.pub")
PUBKEY_PATH_ALICE3 = os.path.join(os.path.dirname(__file__), "alice3.pub")


def replace_pgp_msg(text):
    # helper to remove pgp messages out of MIME containers.
    # pgp messages differ from each other when generated, even if they encrypt
    # the same message.
    return re.sub(
        "-----BEGIN PGP MESSAGE-----\n\n(.+?)-----END PGP MESSAGE-----",
        (
            "-----BEGIN PGP MESSAGE-----\n\n"
            "<PGP STUFF>\n\n-----END PGP MESSAGE-----"
        ),
        text,
        flags=re.M + re.S,
    )


class TestMemoryKeyStore(object):

    def test_get_recipients_keys(self):
        keystore = pgp.MemoryKeyStore()
        keys = keystore.get_recipients_keys("alice@sample.net")
        assert keys["alice@sample.net"] is None
        keystore._ring.load(PUBKEY_PATH_ALICE)
        keys = keystore.get_recipients_keys("alice@sample.net")
        assert keys["alice@sample.net"].fingerprint == FPR_ALICE

    def test_get_recipients_keys_overlapping(self):
        # we only find exactly matching email addresses
        keystore = pgp.MemoryKeyStore()
        # load keys of alice@sample.net and thealice@sample.net
        keystore._ring.load([PUBKEY_PATH_ALICE, PUBKEY_PATH_ALICE2])
        keys1 = keystore.get_recipients_keys("alice@sample.net")
        keys2 = keystore.get_recipients_keys("thealice@sample.net")
        assert keys1["alice@sample.net"].fingerprint == FPR_ALICE
        assert keys2["thealice@sample.net"].fingerprint == FPR_ALICE2

    def test_get_recipients_keys_returns_newesst(self):
        # in case of keys with matching UIDs we take the newest one.
        keystore = pgp.MemoryKeyStore()
        # import older (ALICE) and newer (ALICE3) key of alice@sample.net
        keystore._ring.load([PUBKEY_PATH_ALICE, PUBKEY_PATH_ALICE3])
        keys = keystore.get_recipients_keys("alice@sample.net")
        assert keys["alice@sample.net"].fingerprint == FPR_ALICE3

    def test_get_recipients_keys_accepts_list(self):
        # we also accept a list of addresses as parameter
        keystore = pgp.MemoryKeyStore()
        keystore._ring.load([PUBKEY_PATH_ALICE, PUBKEY_PATH_ALICE2])
        keys = keystore.get_recipients_keys(
            ["alice@sample.net", "thealice@sample.net"])
        assert sorted(
            keys.keys()) == ["alice@sample.net", "thealice@sample.net"]

    def test_add_key(self):
        # we can store keys
        keystore = pgp.MemoryKeyStore()
        key, _ = pgpy.PGPKey.from_file(PUBKEY_PATH_ALICE)
        assert keystore._ring.fingerprints("public", "primary") == set()
        keystore.add_key(key)
        stored = [x for x in keystore._ring.fingerprints("public", "primary")]
        assert FPR_ALICE in stored

    def test_add_key_uniq(self):
        # we cannot add same key twice
        keystore = pgp.MemoryKeyStore()
        key, _ = pgpy.PGPKey.from_file(PUBKEY_PATH_ALICE)
        keystore.add_key(key)
        keystore.add_key(key)
        assert len(keystore._ring.fingerprints("public", "primary")) == 1


class TestDirectoryKeyStore(object):

    def test_re_keyfilename(self):
        # the RE_KEYFILENAME regexp matches only expected strings
        assert pgp.RE_KEYFILENAME.match("foo") is None
        assert pgp.RE_KEYFILENAME.match(
                "OpenPGP_0x0123456789ABCDEF.asc") is not None
        assert pgp.RE_KEYFILENAME.match(
                "OpenPGP_0x0123456789ABCDEFF.asc") is None
        assert pgp.RE_KEYFILENAME.match(
                "OpenPGP_0x0123456789ABCDE.asc") is None
        assert pgp.RE_KEYFILENAME.match(
                "OOpenPGP_0x0123456789ABCDEF.asc") is None
        assert pgp.RE_KEYFILENAME.match(
                "OpenPGP_0x0123456789ABCDEF-asc") is None

    def test_scan(self, tmpdir):
        # we can scan empty directories
        keystore = pgp.DirectoryKeyStore(str(tmpdir))
        keystore.scan()
        assert list(keystore._ring) == []

    def test_scan_single_key(self, tmpdir):
        # we can detect valid key files
        keystore = pgp.DirectoryKeyStore(str(tmpdir))
        with open(PUBKEY_PATH_ALICE) as fp:
            (tmpdir / ("OpenPGP_0x%s.asc" % FPR_ALICE[-16:])).write(fp.read())
        keystore.scan()
        assert FPR_ALICE in keystore._ring.fingerprints()

    def test_scan_file_not_key(self, tmpdir):
        # we ignore files that are not keys, silently
        keystore = pgp.DirectoryKeyStore(str(tmpdir))
        (tmpdir / ("OpenPGP_0x%s.asc" % FPR_ALICE[-16:])).write("not-a-key")
        keystore.scan()
        assert list(keystore._ring) == []

    def test_scan_file_directory(self, tmpdir):
        # in scans we ignore directories
        keystore = pgp.DirectoryKeyStore(str(tmpdir))
        tmpdir.join("foo").ensure(dir=True)
        tmpdir.join("bar").write("baz")
        keystore.scan()
        assert list(keystore._ring) == []


class TestKeyManager(object):

    def test_get_recipients_keys(self):
        # we can get keys for recipients
        key_mgr = pgp.KeyManager()
        found = key_mgr.get_recipients_keys("alice@sample.net")
        assert found == {'alice@sample.net': None}
        key, _ = pgpy.PGPKey.from_file(PUBKEY_PATH_ALICE)
        key_mgr.add_key(key)
        found = key_mgr.get_recipients_keys("alice@sample.net")
        assert found["alice@sample.net"].fingerprint == FPR_ALICE


class TestHKPLookup(object):

    def test_init(self):
        # we construct valid URLs on initialization
        assert pgp.HKPLookup("myhost").url == (
            "https://myhost/pks/lookup?op={op}&options=mr&search={search}")
        assert pgp.HKPLookup("myhost", tls=True).url == (
            "https://myhost/pks/lookup?op={op}&options=mr&search={search}")
        assert pgp.HKPLookup("myhost", tls=False).url == (
            "http://myhost/pks/lookup?op={op}&options=mr&search={search}")
        assert pgp.HKPLookup("myhost", port=42).url == (
            "https://myhost:42/pks/lookup?op={op}&options=mr&search={search}")

    def test_get(self, fake_hkp_server):
        # we can get real keys from HKP servers.
        hkp = pgp.HKPLookup("keys.openpgp.org")
        key = hkp.get("uli@gnufix.de")
        assert isinstance(key, pgpy.PGPKey)


def test_parse_raw(tpath):
    # we can turn raw messages into Message objects
    headers = [
        (b"Return-Path", b"<lauren@foobar.com>"),
        (
            b"Received",
            b"from foobar.com (localhost [127.0.0.1])"
            b"\n	by hemholt.foobar.com (8.9.3/8.8.7) with ESMTP id SAA03001;"
            b"\n	Mon, 29 Jan 2001 18:08:41 -0500",
        ),
        (b"Sender", b"lauren@foobar.com"),
        (b"Message-ID", b"<3A75F7F6.CBF9E75@foobar.com>"),
        (b"Date", b"Mon, 29 Jan 2001 18:08:39 -0500"),
        (b"From", b"Lauren Hemholz <lauren@foobar.com>"),
        (b"Organization", b"Hemholtz Family"),
        (b"X-Mailer", b"Mozilla 4.76 [en] (X11; U; Linux 2.2.16-3 i586)"),
        (b"X-Accept-Language", b"en"),
        (b"MIME-Version", b"1.0"),
        (b"To", b"Jriser13@aol.com"),
        (b"Subject", b"Re: P.B.S kids"),
        (b"References", b"<e4.1045e74c.27a7018b@aol.com>"),
        (
            b"Content-Type",
            b"multipart/alternative;"
            b'\n boundary="------------7EC2082FC4F651D73FCD6FE1"',
        ),
        (b"Status", b"O"),
    ]
    body = (tpath / "samples/full-mail01").read_bytes().split(b"\n\n\n")[-1]
    parsed = pgp.parse_raw(headers, body)
    assert isinstance(parsed, Message)


class TestProtectedHeaders(object):
    # Test memory hole functionality

    headerfields = dict([
        ("From", "alice@sample.org"), ("To", "bob@sample.org"),
        ("Subject", "Contract with FooCorp"),
        ("Date", "Mon, 29 Jan 2001 18:08:39 -0500"),
        ("Message-Id", "real-msgid"), ("References", "ref-id-01"),
        ("In-Reply-To", "other-msgid"), ("X-Mailer", "foo"),
        ("User-Agent", "Funky Mailer")
    ])

    def test_default(self):
        # Default values are applied, other headers are kept unchanged
        part = MIMEText("Some Test")
        msg = deepcopy(part)
        for key, val in self.headerfields.items():
            msg[key] = val
        new_msg, new_part = pgp.memory_hole(msg, part)
        assert new_msg["From"] == msg["From"]       # unchanged
        assert new_msg["Subject"] != msg["..."]     # changed
        assert "In-Reply-To" not in new_msg.keys()  # removed
        assert sorted(new_msg.keys()) == [
                'Content-Transfer-Encoding',
                'Content-Type',
                'Date',
                'From',
                'MIME-Version',
                'Message-Id',
                'Subject',
                'To',
                'X-Mailer',
                ]
        assert mime_structure(new_part) == (
                '└┬multipart/mixed 485 bytes \n'
                ' ├─text/rfc822-headers (us-ascii) 179 bytes \n'
                ' └─text/plain (us-ascii) 105 bytes \n'
                )

    def test_empty(self):
        # No header changes happen when the replacement table is empty
        # (although we create an rfc822-headers part)
        part = MIMEText("Some Test")
        msg = deepcopy(part)
        for key, val in self.headerfields.items():
            msg[key] = val
        replaced_headers = dict()
        new_msg, new_part = pgp.memory_hole(
                msg, part, replaced_headers=replaced_headers)
        assert sorted(new_msg.items()) == sorted(msg.items())
        assert mime_structure(new_part) == (
                '└┬multipart/mixed 393 bytes \n'
                ' ├─text/rfc822-headers (us-ascii) 87 bytes \n'
                ' └─text/plain (us-ascii) 105 bytes \n'
                )

    def test_nested(self):
        # we cope with nested structures
        part = MIMEMultipart("alternative")
        part.attach(MIMEText("Some ASCII text"))
        part.attach(MIMEText("Some utf-8 text: äöü"))
        msg = deepcopy(part)
        for key, val in self.headerfields.items():
            msg[key] = val
        new_msg, new_part = pgp.memory_hole(msg, part)
        assert mime_structure(new_part) == (
                '└┬multipart/mixed 844 bytes \n'
                ' ├─text/rfc822-headers (us-ascii) 179 bytes \n'
                ' └┬multipart/alternative 464 bytes \n'
                '  ├─text/plain (us-ascii) 111 bytes \n'
                '  └─text/plain (utf-8) 128 bytes \n'
                )

    def test_memory_hole(self, tpath):
        with (tpath / "samples" / "full-mail04").open() as fp:
            msg = Parser(policy=default_policy).parse(fp)
        part = pgp.get_encryptable_payload(deepcopy(msg))
        msg, new_part = pgp.memory_hole(msg, part)
        new_part.set_boundary("---BOUNDARY---")
        assert new_part.as_string() == (
            'Content-Type: multipart/mixed; boundary="---BOUNDARY---"\n'
            '\n'
            '-----BOUNDARY---\n'
            'Content-Type: text/rfc822-headers; charset="us-ascii"\n'
            'Content-Transfer-Encoding: 7bit\n'
            '\n'
            'Subject: Saying Hello\n'
            'Date: Fri, 21 Nov 1997 09:55:06 -0600\n'
            'Message-ID: <1234@local.machine.example>\n'
            '\n'
            '-----BOUNDARY---\n'
            '\n'
            'This is a message just to say hello.\n'
            'So, "Hello".\n'
            '\n'
            '-----BOUNDARY-----\n'
            )
        assert msg["Subject"] == "..."

    def test_memory_hole_w_mime_msg(self, tpath):
        # we can header-protect a mime msg
        with (tpath / "samples" / "full-mail02").open() as fp:
            msg = Parser(policy=default_policy).parse(fp)
        part = pgp.get_encryptable_payload(deepcopy(msg))
        msg, new_part = pgp.memory_hole(msg, part)
        new_part.set_boundary("---BOUNDARY---")
        assert new_part.as_string() == (
            'Content-Type: multipart/mixed; boundary="---BOUNDARY---"\n'
            '\n'
            '-----BOUNDARY---\n'
            'Content-Type: text/rfc822-headers; charset="us-ascii"\n'
            'Content-Transfer-Encoding: 7bit\n'
            '\n'
            'Date: Tue, 30 Apr 2019 21:21:28 +0200\n'
            'Subject: Subject\n'
            'Message-ID: <20190430211128.h24b7qbx7evr4sdz@tigger>\n'
            '\n'
            '-----BOUNDARY---\n'
            'Content-Type: text/plain; charset=us-ascii\n'
            'Content-Disposition: inline\n'
            '\n'
            'foo bar baz\n'
            '\n'
            '\n'
            '-----BOUNDARY-----\n'
            )
        assert msg["Subject"] == "..."


def test_pgp_mime_encrypt(tmpdir, tpath):
    # we can create PGP-MIME messages from MIME
    key, _ = pgpy.PGPKey.from_file(str(tpath / "alice.pub"))
    mime_msg = MIMEText(_text="meet me at dawn")
    result = pgp.pgp_mime_encrypt(mime_msg, [key, ])
    result.set_boundary("===============1111111111111111111==")
    expected = replace_pgp_msg(
        (tpath / "samples/mime-enc-body").read_text()
    )
    assert replace_pgp_msg(result.as_string()) == expected


def test_pgp_mime_encrypt_fullmail(tmpdir, tpath):
    # we can encrypt a complete message
    key, _ = pgpy.PGPKey.from_file(str(tpath / "alice.pub"))
    with (tpath / "samples/full-mail02").open() as fp:
        msg = Parser(policy=default_policy).parse(fp)
    result = pgp.pgp_mime_encrypt(msg, [key, ])
    assert result.keys() == [
        "Return-Path", "Received", "From", "To", "Date", "Subject",
        "Message-ID", "Content-Type", "MIME-Version",
        "Content-Disposition"]
    assert "multipart/encrypted" in result.as_string()
    assert "BEGIN PGP MESSAGE" in result.as_string()
    assert mime_structure(result) == (
            '└┬multipart/encrypted inline 1888 bytes  (Subject: ...)\n'
            ' ├─application/pgp-encrypted 102 bytes \n'
            ' └─application/octet-stream [encrypted.asc] 1146 bytes \n')


def test_get_encryptable_payload(tpath):
    # we can extract the encryptable part of a message
    with (tpath / "samples/full-mail02").open("r") as fp:
        msg = Parser(policy=default_policy).parse(fp)
    result = pgp.get_encryptable_payload(msg)
    want = (tpath / "samples/payload02").read_text()
    assert result.as_string() == want


def test_get_encryptable_payload_works_by_value(tpath):
    # proof that passed in messages are not changed.
    with (tpath / "samples/full-mail02").open("r") as fp:
        msg = Parser(policy=default_policy).parse(fp)
    headers_before = msg.items()
    pgp.get_encryptable_payload(msg)
    assert msg.items() == headers_before


def test_prepend_headerfields():
    # we can inject headerfields
    msg = Parser(policy=default_policy).parsestr(
        "To: foo\nSubject: bar\n\nMeet at dawni\n")
    msg.add_header("X-Foo", "baz")
    result = pgp.prepend_header_fields(msg, [("To", "foo"), ("From", "bar")])
    assert result.keys() == ["From", "To", "Subject", "X-Foo"]


def test_prepend_headerfields_encoded():
    # we cope with non-ascii encodings in raw strings
    msg = BytesParser(
        policy=default_policy).parsebytes('Subject: föö'.encode('utf-8'))
    assert msg.get_all("Subject")[0] == "föö"
    result = pgp.prepend_header_fields(msg, [("To", "foo"), ("From", "bar")])
    assert result.items() == [
        ('To', 'foo'),
        ('From', 'bar'),
        ('Subject', 'föö')]


def test_prepend_headerfields_as_header_objs():
    # we cope with email.header.Header instances as headerfields
    msg = BytesParser(
        policy=compat32).parsebytes('Subject: föö'.encode('utf-8'))
    assert not isinstance(msg.get_all("Subject")[0], str)
    result = pgp.prepend_header_fields(msg, [("To", "foo"), ("From", "bar")])
    assert result.items() == [
        ('To', 'foo'),
        ('From', 'bar'),
        ('Subject', '=?unknown-8bit?b?ZsO2w7Y=?=')]


def test_encrypt_msg(tmpdir, tpath):
    # we can encrypt a message
    key_mgr = pgp.KeyManager()
    key_mgr.add_key(pgpy.PGPKey.from_file(str(tpath / "alice3.pub"))[0])
    with (tpath / "samples/full-mail02").open("r") as fp:
        msg = Parser(policy=default_policy).parse(fp)
    result = pgp.encrypt_msg(msg, ["alice@sample.net"], key_mgr)
    assert result[0] is True
    enc_msg = result[1].as_string()
    assert "-----BEGIN PGP MESSAGE-----" in enc_msg
    assert result[1]['Content-Type'].startswith('multipart/encrypted')
    priv_key, _ = pgpy.PGPKey.from_file(str(tpath / "alice3.sec"))
    enc_msg = pgpy.PGPMessage.from_blob(enc_msg)
    dec_msg = priv_key.decrypt(enc_msg)
    assert dec_msg.is_encrypted is False
    assert (
        'Content-Type: text/plain; charset=us-ascii\n'
        'Content-Disposition: inline\n\nfoo bar baz\n\n') in dec_msg.message


def test_encrypt_msg_no_key(tmpdir, tpath):
    # without key, we cannot encrypt
    key_mgr = pgp.KeyManager()
    key, _ = pgpy.PGPKey.from_file(str(tpath / "alice.pub"))
    key_mgr.add_key(key)
    with (tpath / "samples/full-mail02").open("r") as fp:
        msg = Parser(policy=default_policy).parse(fp)
    changed, new_msg = pgp.encrypt_msg(msg, ["bob@sample.org"], key_mgr)
    assert changed is False
    assert new_msg is msg


def test_encrypt_msg_not_all_keys(tmpdir, tpath):
    # we do only encrypt if all keys are available
    key_mgr = pgp.KeyManager()
    key, _ = pgpy.PGPKey.from_file(str(tpath / "alice.pub"))
    key_mgr.add_key(key)
    with (tpath / "samples/full-mail02").open("r") as fp:
        msg = Parser(policy=default_policy).parse(fp)
    changed, new_msg = pgp.encrypt_msg(
        msg, ["bob@sample.org", "alice@sample.net"], key_mgr)
    assert changed is False
    assert new_msg is msg


def test_encrypt_msg_multi_rcpts(tmpdir, tpath):
    # we can encypt messages for multple recipients
    key_mgr = pgp.KeyManager()
    key1, _ = pgpy.PGPKey.from_file(str(tpath / "alice.pub"))
    key2, _ = pgpy.PGPKey.from_file(str(tpath / "bob.pub"))
    key_mgr.add_key(key1)
    key_mgr.add_key(key2)
    with (tpath / "samples/full-mail02").open("r") as fp:
        msg = Parser(policy=default_policy).parse(fp)
    changed, new_msg = pgp.encrypt_msg(
        msg, ["bob@sample.org", "alice@sample.net"], key_mgr)
    assert changed is True
    assert "-----BEGIN PGP MESSAGE-----" in new_msg.as_string()


def test_encrypt_msg_no_pgp_env(tmpdir, tpath):
    # without a key manager, we cannot encrypt
    with (tpath / "samples/full-mail02").open("r") as fp:
        msg = Parser(policy=default_policy).parse(fp)
    changed, new_msg = pgp.encrypt_msg(
        msg, ["bob@sample.org"], None)
    assert changed is False


def test_msg_encrypted(tpath):
    # we can detect already encrypted messages
    with (tpath / "samples/full-mail01-enc").open("r") as fp:
        mime_msg = Parser(policy=default_policy).parse(fp)
    assert pgp.msg_encrypted(mime_msg) is True


def test_msg_not_encrypted(tpath):
    # we detect not encrypted messages
    with (tpath / "samples/full-mail01").open("r") as fp:
        mime_msg = Parser(policy=default_policy).parse(fp)
    assert pgp.msg_encrypted(mime_msg) is False


def test_msg_encrypted_in_sub_part(tpath):
    # we can detect encrypted stuff in sub parts of MIME messages
    with (tpath / "samples/full-mail01-enc").open("r") as fp:
        mime_msg = Parser(policy=default_policy).parse(fp)
        # set wrong main type to enforce deeper digging
        mime_msg.set_type('multipart/related')
    assert pgp.msg_encrypted(mime_msg) is True
