"""Tests for the CouchDB password-hash verifier (``nosqlmap.couchdb.verify_couch``)."""

from binascii import b2a_hex
from hashlib import sha1
from pbkdf2 import PBKDF2

from nosqlmap.couchdb import verify_couch


def test_verify_couch_sha1_pre_13():
    # dbVer < 1.3 uses the legacy SHA-1 scheme.
    salt = "0123456789abcdef"
    enc = sha1(("mypw" + salt).encode()).hexdigest()
    assert verify_couch("mypw", salt, enc, "1.2.0") is True
    assert verify_couch("nope", salt, enc, "1.2.0") is False


def test_verify_couch_pbkdf2_13_plus():
    # dbVer >= 1.3 uses PBKDF2 (20-byte key, 10 iterations).
    salt = "0123456789abcdef"
    digest = PBKDF2(b"mypw", salt.encode(), 10).read(20)
    enc = b2a_hex(digest).decode()
    assert verify_couch("mypw", salt, enc, "1.3.0") is True
    assert verify_couch("nope", salt, enc, "1.3.0") is False


def test_verify_couch_version_boundary():
    # "1.3" is NOT < 1.3, so it must route to PBKDF2, not SHA-1.
    # A SHA-1 hash therefore must not verify under the 1.3 (PBKDF2) path.
    salt = "salt"
    sha1_enc = sha1(("pw" + salt).encode()).hexdigest()
    assert verify_couch("pw", salt, sha1_enc, "1.3.0") is False
