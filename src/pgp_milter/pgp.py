# -*- coding: utf-8 -*-
#
# OpenPGP related stuff
#
import gnupg
import email.mime.text
import os
import pathlib
import pgpy
import re
import sys
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.parser import Parser
from email.policy import default as default_policy
from email.utils import parseaddr


# The format of keyfiles
RE_KEYFILENAME = re.compile(r"^OpenPGP_0x[0-9A-F]{16}\.asc$")


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
    def __init__(self, path):
        super(DirectoryKeyStore, self).__init__()
        self.path = path

    def scan(self):
        for entry in os.scandir(self.path):
            if not entry.is_file():
                continue
            if not RE_KEYFILENAME.match(entry.name):
                continue
            path = os.path.join(os.path.abspath(self.path), entry.name)
            try:
                self._ring.load(os.path.abspath(path))
            except ValueError:
                pass


class KeyManager(object):
    def __init__(self):
        self._key_store = MemoryKeyStore()

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


def get_gpg(gpg_env_path):
    """Get a GPG environment located in `gpg_env_path`.

    The directory must exist before calling although it does not have to be
    populated. If no gpg environment can be created, `None` is returned.
    """
    gpg_env_path = gpg_env_path and pathlib.Path(gpg_env_path).expanduser()
    if gpg_env_path is None or not gpg_env_path.is_dir():
        return None
    return gnupg.GPG(gnupghome=str(gpg_env_path))


def gpg_encrypt(gpg_env, text, fpr):
    """Encrypt `text` for fingerprint `fpr`.
    """
    return gpg_env.encrypt(text, fpr, always_trust=True)


def pgp_mime_encrypt(mime_msg, keys):
    """Create PGP encrypted message from ordinary MIME message

    The returned multipart MIME container should conform to RFC 3156.
    The message will be encrypted with all keys passed in.
    """
    headers = mime_msg.items()
    payload = get_encryptable_payload(mime_msg).as_string()
    enc_msg = pgpy.PGPMessage.new(payload)
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
    """
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


def get_fingerprints(gpg_env, recipients):
    """Get the recipients fingerprints.

    We only return those fingerprints, that match passed email addresses
    completely and at most one fingerprint per given email.
    """
    if not isinstance(recipients, list):
        recipients = [recipients]
    email_addrs = [parseaddr(x)[1] for x in recipients]
    result = []
    for addr in email_addrs:
        addr_results = []
        gpg_keys = gpg_env.list_keys(keys=[addr])
        for gpg_key in gpg_keys:
            for uid in gpg_key["uids"]:
                name, uid_addr = parseaddr(uid)
                if uid_addr == addr:
                    addr_results.append(gpg_key)
                    break
        if len(addr_results):
            result.append(
                sorted(
                    addr_results, key=lambda x: x['date'])[-1]["fingerprint"])
    return result


def encrypt_msg(msg, recipients, key_manager=None):
    """Encrypt `msg` for `recipients` with keys provided by `key_manager`.

    Returns, whether changes happened andi the  (possibly changed) message.

    If we cannot get keys for all recipients, the messag stays unchained.
    Otherwise the message is encrypted with the keys of each recipient.
    """
    changed = False
    if key_manager is None:
        return changed, msg
    keys = key_manager.get_recipients_keys(recipients)
    if None in keys.values():
        return False, msg
    new_msg = pgp_mime_encrypt(msg, list(keys.values()))
    return (True, new_msg)


def prepare_pgp_lookups(conf):
    """Ensure, all preconditions are met for looking up PGP keys.
    """
    pgphome = pathlib.Path(conf.pgphome).expanduser()
    if not pgphome.is_dir():
        print("No such directory: %s" % pgphome)
        sys.exit(os.EX_USAGE)


def contains_encrypted(mime_msg):
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
        if contains_encrypted(part):
            return True
    return False
