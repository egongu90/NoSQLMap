"""Tests for ``nosqlmap.brute`` — the shared brute-force primitives."""

import string

from nosqlmap import brute


def test_genbrute_single_char():
    assert list(brute.genBrute("a", 3)) == ["a", "aa", "aaa"]


def test_genbrute_two_chars_length_two():
    # length 1: a, b ; length 2: aa, ab, ba, bb
    assert list(brute.genBrute("ab", 2)) == ["a", "b", "aa", "ab", "ba", "bb"]


def test_genbrute_max_len_one():
    assert list(brute.genBrute("abc", 1)) == ["a", "b", "c"]


def test_genbrute_exhaustive_count():
    # 3 chars, maxLen 2 -> 3 (len 1) + 9 (len 2) = 12 candidates
    assert len(list(brute.genBrute("abc", 2))) == 12


def test_genbrute_candidates_use_only_given_chars():
    for cand in brute.genBrute("ab", 3):
        assert set(cand) <= {"a", "b"}
        assert 1 <= len(cand) <= 3


def test_charsets_contents():
    assert brute.CHARSETS["1"] == string.ascii_lowercase
    assert brute.CHARSETS["2"] == string.ascii_uppercase
    assert brute.CHARSETS["3"] == string.ascii_letters
    assert brute.CHARSETS["4"] == string.digits
    assert brute.CHARSETS["5"] == string.ascii_letters + string.digits
    # Charset 6 is a superset of letters + digits (plus specials).
    assert set(brute.CHARSETS["6"]) >= set(string.ascii_letters + string.digits)
