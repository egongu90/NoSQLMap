"""Tests for the MongoDB MD5 auth verifier (``nosqlmap.mongodb.verify_md5``)."""

from hashlib import md5

from nosqlmap.mongodb import verify_md5


def _mongo_hash(user, password):
    """The hash MongoDB stores: md5(user:mongo:password)."""
    return md5((user + ":mongo:" + password).encode()).hexdigest()


def test_verify_md5_correct_password():
    enc = _mongo_hash("admin", "s3cret")
    assert verify_md5("admin", "s3cret", enc) is True


def test_verify_md5_wrong_password():
    enc = _mongo_hash("admin", "s3cret")
    assert verify_md5("admin", "wrong", enc) is False


def test_verify_md5_wrong_user():
    enc = _mongo_hash("admin", "s3cret")
    assert verify_md5("other", "s3cret", enc) is False
