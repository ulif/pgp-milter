# -*- coding: utf-8 -*-
#
# OpenPGP related stuff
#
import email.mime.text
import os
import pgpy
import re
from collections import namedtuple
from copy import deepcopy
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.parser import Parser
from email.policy import default as default_policy
from email.utils import parseaddr


# The format of keyfile names - OpenPGP_0x<16 uppercase hex digits>.asc
# Sample: OpenPGP_0x0123456789ABCDEF.asc
RE_KEYFILENAME = re.compile(r"^OpenPGP_0x[0-9A-F]{16}\.asc$")


Replace = namedtuple("Replace", ("forced_display", "replacement"))


# Header fields to be changed/obscured - fields can be changed in message
# header (`forced_display`=True) or be removed (`forced_display`=False) or be
# kept untouched (not mentioned in this dict).
REPLACED_HEADERS = {
        "subject": Replace(True, "..."),
        "message-id": Replace(True, "C@memoryhole.example"),
        "date": Replace(True, "Thu, 1 Jan 1970 00:00:00 +0000"),
        "in-reply-to": Replace(False, None),
        "references": Replace(False, None),
        "user-agent": Replace(False, None),
    }


class MemoryKeyStore(object):
    """Our common interface for handling keys.

    The basic `KeyStore` stores keys in memory.
    """
    def __init__(self):
        self._ring = pgpy.PGPKeyring()

    def get_recipients_keys(self, recipients):
        """Get keys for email addresses in `recipients`

        Looks up the local keys and returns a dict with email-key pairs for
        all emails contained in recipients.

        For emails not found we return `None`.

        For each requested email address we also return the last key created
        only, if there are multiple.
        """
        if not isinstance(recipients, list):
            recipients = [recipients]
        found = dict([(parseaddr(x)[1], None) for x in recipients])
        for fpr in self._ring.fingerprints("public", "primary"):
            with self._ring.key(fpr) as key:
                for uid in key.userids:
                    addr = parseaddr(uid.email)[1]
                    if addr not in found.keys():
                        continue
                    # we cannot enforce a certain order of keys in this loop
                    if not found[addr] or (                # pragma: no branch
                            found[addr].created < key.created):
                        found[addr] = key
                        break
        return found

    def add_key(self, key):
        """ Add new key.
        """
        self._ring.load(key)


class DirectoryKeyStore(MemoryKeyStore):
    """A key store that stores keys in a simple directory in `path`.

    Keyfiles are expected to be ASCII-armored public keys with a filename that
    matches `RE_KEYFILENAME` pattern. Other files or keyfiles that cannot be
    loaded are silently discarded.

    The `path` must exists beforehand and be a directory.
    """
    def __init__(self, path):
        super(DirectoryKeyStore, self).__init__()
        self.path = path

    def scan(self):
        """Scan instance `path` for PGP public keys.

        Found keys are added to local `pgpy.PGPKeyRing`.
        """
        for entry in os.scandir(self.path):
            if not entry.is_file():
                continue
            if not RE_KEYFILENAME.match(entry.name):
                continue
            path = os.path.join(os.path.abspath(self.path), entry.name)
            try:
                self._ring.load(os.path.abspath(path))
            except (ValueError, pgpy.errors.PGPError):
                pass


class KeyManager(object):
    def __init__(self, path=None):
        self._path = path
        if self._path is None:
            self._key_store = MemoryKeyStore()
            return
        self._path = os.path.abspath(path)
        self._key_store = DirectoryKeyStore(self._path)
        self._key_store.scan()

    def get_recipients_keys(self, recipients):
        """Get public keys of `recipients`
        """
        return self._key_store.get_recipients_keys(recipients)

    def add_key(self, key):
        self._key_store.add_key(key)


def parse_raw(headers, body):
    """Turn headers and body of an email into message
    object.
    """
    str_headers = b"\n".join([b"%s: %s" % (k, v) for k, v in headers])
    raw_msg = "%s\n\n\n%s" % (str_headers.decode(), body.decode())
    return Parser(policy=default_policy).parsestr(raw_msg)


def memory_hole(msg, part, replaced_headers=REPLACED_HEADERS):
    """Apply memory hole to obscure headers.

    `part` is expected to be the root part of the MIME message `msg`. This part
    is considered one of the new subparts of a fresh multipart/mixed part that
    can become the new root.

    Returns new MIME message with headers applied and a new part containing the
    old headers and the old root part of the message.

    See https://modernpgp.org/memoryhole/ and George Orwells "1984" for details.
    """
    msg = deepcopy(msg)
    headers = ""
    for header, value in msg.items():
        h = header.lower()
        if h in replaced_headers and replaced_headers[h].forced_display:
            headers += "%s: %s\n" % (header, value)
    headers_part = MIMEText(headers, "rfc822-headers")
    del headers_part["MIME-Version"]
    new_part = MIMEMultipart('mixed', _subparts=[headers_part, part])
    del new_part["MIME-Version"]
    for header, value in replaced_headers.items():
        if header in msg:
            del(msg[header])
            if value.replacement is not None:
                msg.add_header(header, value.replacement)
    return msg, new_part


def pgp_mime_encrypt(mime_msg, keys, replaced_headers=REPLACED_HEADERS):
    """Create PGP encrypted message from ordinary MIME message

    The returned multipart MIME container should conform to RFC 3156.
    The message will be encrypted with all keys passed in.
    """
    payload = get_encryptable_payload(mime_msg)
    mime_msg, protected_payload = memory_hole(
            mime_msg, payload, replaced_headers)
    headers = mime_msg.items()
    enc_msg = pgpy.PGPMessage.new(protected_payload.as_string())
    for key in keys:
        enc_msg = key.encrypt(enc_msg)
    multipart_container = MIMEMultipart(
        "encrypted", protocol="application/pgp-encrypted"
    )
    part1 = MIMEApplication(
        _data="Version: 1\n",
        _subtype="pgp-encrypted",
        _encoder=email.encoders.encode_7or8bit,
    )
    multipart_container.attach(part1)
    part2 = MIMEApplication(
        _data=str(enc_msg),
        _subtype="octet-stream; name=encrypted.asc",
        _encoder=email.encoders.encode_7or8bit,
    )
    multipart_container.attach(part2)
    multipart_container["Content-Disposition"] = "inline"
    multipart_container = prepend_header_fields(multipart_container, headers)
    return multipart_container


def get_encryptable_payload(msg):
    """Get the 'inner' content of a message.

    I.e. the part that should be encrypted when outward bound. Expects and
    returns an `email.message.EmailMessage` object.

    We simply remove all headers except "Content-", thus keeping a well-formed
    MIME-container (if the message was in MIME-format) or a raw inline message.
    """
    msg = deepcopy(msg)
    for k in msg.keys():  # remove headers not "encrypted".
        if k.lower().startswith("content-"):
            continue
        del msg[k]
    return msg


def prepend_header_fields(msg, headers):
    """Inject header fields in `headers` into `msg`.

    The fields are inserted at beginning, so that any existing header fields
    will become the last ones.
    Header fields from the "Content" family ("Content-Type", ....) are
    discarded before rebuildung message headers.
    """
    headers = [x for x in headers if not x[0].lower().startswith("content")]
    final_headers = headers + msg.items()
    for k, v in final_headers:
        if k in msg.keys():
            del msg[k]
        if not isinstance(v, str):
            v = v.encode()  # value looks like Header type.
        msg.add_header(k, v)
    return msg


def encrypt_msg(mime_msg, recipients, key_manager=None):
    """Encrypt `msg` for `recipients` with keys provided by `key_manager`.

    Returns, whether changes happened andi the  (possibly changed) message.

    If we cannot get keys for all recipients, the messag stays unchained.
    Otherwise the message is encrypted with the keys of each recipient.

    Returns a tuple (`changed`, `mime_msg`) where `changed` indicates if the
    message was changed.
    """
    if key_manager is None:
        return False, mime_msg
    keys = key_manager.get_recipients_keys(recipients)
    if None in keys.values():
        return False, mime_msg
    new_mime_msg = pgp_mime_encrypt(mime_msg, list(keys.values()))
    return (True, new_mime_msg)


def msg_encrypted(mime_msg):
    """Detect already encrypted MIME messages.

    A message is MIME-OpenPGP-encrypted according to RFC 2015 if it is
    multipart and contains parts with certain content types. This is, what we
    check here.

    This function also accepts single MIME parts of messages.
    """
    if mime_msg.get_content_type() in [
            "multipart/encrypted", "application/pgp-encrypted"]:
        return True
    for part in mime_msg.iter_parts():
        if msg_encrypted(part):
            return True
    return False
