# -*- coding: utf-8 -*-
#
# OpenPGP related stuff
#
import gnupg
import email.mime.text
import os.path
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.parser import Parser
from email.policy import default as default_policy
from email.utils import parseaddr


def parse_raw(headers, body):
    """Turn headers and body of an email into message
    object.
    """
    str_headers = b"\n".join([b"%s: %s" % (k, v) for k, v in headers])
    raw_msg = "%s\n\n\n%s" % (str_headers.decode(), body.decode())
    return Parser(policy=default_policy).parsestr(raw_msg)


def gpg_encrypt(gpg_env, text, fpr):
    """Encrypt `text` for fingerprint `fpr`.
    """
    return gpg_env.encrypt(text, fpr, always_trust=True)


def pgp_mime_encrypt(gpg_env, mime_msg, fpr):
    """Create PGP encrypted message from ordinary MIME message

    The returned multipart MIME container should conform to RFC 3156.
    """
    headers = mime_msg.items()
    to_encrypt = get_encryptable_payload(mime_msg)
    enc_msg = gpg_encrypt(gpg_env, to_encrypt.as_string(), fpr)
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
            result.append(sorted(addr_results, key=lambda x: x['date'])[-1]["fingerprint"])
    return result


def encrypt_msg(msg, recipients, gpg_env_path=None):
    """Encrypt `msg` for `recipients` with gpg-env in `gpg_env_path`.

    Returns, whether changes happened and (possibly changed) message created.
    """
    changed = False
    if gpg_env_path is None or not os.path.isdir(gpg_env_path):
        return changed, msg
    gpg = gnupg.GPG(gnupghome=gpg_env_path)
    fprs = get_fingerprints(gpg, recipients)
    return (True, msg)
