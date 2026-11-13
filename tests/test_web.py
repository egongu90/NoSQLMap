"""Tests for the random-string builders in ``nosqlmap.web``."""

import re
import string
import urllib.parse
from types import SimpleNamespace

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


# ---------------------------------------------------------------------------
# ``buildUri`` payload-format tests
#
# ``buildUri`` builds the module-global ``uriArray``: one URL per injection
# payload, URL-encoded with ``quote_plus``. These tests pin the *format* of
# every payload so a refactor cannot silently change what the tool sends. The
# array is a global, so each test rebuilds it first via ``_build_array``.
# ---------------------------------------------------------------------------


def _build_array(uri="http://host/path?a=1&b=2", rand="randval", params="1"):
    """Run ``buildUri`` and return the resulting ``uriArray`` (21 URLs)."""
    web.buildUri(uri, rand, SimpleNamespace(params=params))
    return web.uriArray


def _decode(url):
    """Inverse of the builder's ``quote_plus``: decode the query string."""
    return urllib.parse.unquote_plus(url)


def test_build_uri_array_has_twenty_one_payloads():
    assert len(_build_array()) == 21


def test_build_uri_every_entry_keeps_base_path():
    for url in _build_array():
        assert url.startswith("http://host/path?")


def test_build_uri_non_injected_param_keeps_original_value():
    # ``b`` is not selected for injection, so it must keep its value ``2`` in
    # every payload (the tool only rewrites the selected parameter).
    for url in _build_array():
        assert "b=2" in _decode(url)


def test_build_uri_baseline_rewrites_selected_param():
    # Index 0 is the random baseline: selected param ``a`` -> random value,
    # ``b`` untouched.
    assert _decode(_build_array()[0]) == "http://host/path?a=randval&b=2"


def test_build_uri_encodes_brackets_and_dollar():
    # The builder URL-encodes the query; ``a[$ne]=`` must be percent-encoded
    # (``[`` -> %5B, ``$`` -> %24, ``]`` -> %5D).
    assert "a%5B%24ne%5D" in _build_array()[1]


def test_build_uri_ne_operator_payload():
    # ``$ne`` uses an empty value (consistent with the other operators); an
    # empty value reliably matches every record (none equal the empty string).
    assert "a[$ne]=" in _decode(_build_array()[1])


def test_build_uri_gt_operator_payload():
    assert "a[$gt]=" in _decode(_build_array()[8])


def test_build_uri_extended_operator_payloads():
    # Indices 19-20 are the added associative-array operators. Both use empty
    # values: an empty value is the reliable bypass for these operators (a
    # non-empty random value often matches nothing).
    assert "a[$regex]=" in _decode(_build_array()[19])
    assert "a[$exists]=" in _decode(_build_array()[20])


def test_build_uri_where_find_string_escape():
    assert "a=a'; return db.a.find(); var dummy='!" in _decode(_build_array()[2])


def test_build_uri_where_findone_string_escape():
    assert "a=a'; return db.a.findOne(); var dummy='!" in _decode(_build_array()[4])


def test_build_uri_where_return_true_no_equals():
    # Index 14 appends the payload directly (no ``=``), so it reads ``aa'; ...``
    assert "aa'; return true; var dum='a" in _decode(_build_array()[14])


def test_build_uri_timing_payloads_contain_sleep_loop():
    for idx in (9, 13, 18):
        decoded = _decode(_build_array()[idx])
        assert "new Date()" in decoded
        assert "while" in decoded


def test_build_uri_db_attack_templates_keep_placeholder():
    # Indices 16/17 are templates whose ``---`` is replaced later by
    # ``getDBInfo``; the placeholder must survive ``buildUri`` intact.
    assert "a=a'; ---" in _decode(_build_array()[16])
    assert "a=1; if ---" in _decode(_build_array()[17])


def test_build_uri_all_payloads_decode_to_nonempty_query():
    # Every entry must be a base path plus a non-empty, decodable query string.
    for url in _build_array():
        base, sep, query = url.partition("?")
        assert sep == "?"
        assert _decode(query)
