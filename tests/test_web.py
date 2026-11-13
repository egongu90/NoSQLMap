"""Tests for the random-string builders in ``nosqlmap.web``."""

import re
import string

from nosqlmap import web


def test_build_random_string_alphanumeric():
    s = web.build_random_string("1", 20)
    assert len(s) == 20
    assert set(s) <= set(string.ascii_letters + string.digits)


def test_build_random_string_letters_only():
    s = web.build_random_string("2", 20)
    assert len(s) == 20
    assert set(s) <= set(string.ascii_letters)


def test_build_random_string_digits_only():
    s = web.build_random_string("3", 20)
    assert len(s) == 20
    assert set(s) <= set(string.digits)


def test_build_random_string_email():
    # format "4" -> <size chars>@<size chars>.com
    s = web.build_random_string("4", 6)
    assert re.fullmatch(r"[A-Za-z0-9]{6}@[A-Za-z0-9]{6}\.com", s)


def test_rand_inj_string_rejects_invalid_then_accepts(monkeypatch):
    # Feed an invalid choice first, then a valid one; it must loop until valid.
    values = iter(["9", "1"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(values))
    assert web.randInjString(5) == "1"
