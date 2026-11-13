"""Tests for the pure request-building helpers in ``nosqlmap.cli``."""

from nosqlmap.cli import build_post_data, build_request_headers


def test_build_request_headers_pairs():
    result = build_request_headers("Host,example.com,User-Agent,nsr/0.8")
    assert result == {"Host": "example.com", "User-Agent": "nsr/0.8"}


def test_build_request_headers_single_pair():
    assert build_request_headers("X-Custom,val") == {"X-Custom": "val"}


def test_build_request_headers_empty():
    assert build_request_headers("") == {}


def test_build_post_data_pairs():
    result = build_post_data("user,admin,pass,secret")
    assert result == {"user": "admin", "pass": "secret"}


def test_build_post_data_empty():
    assert build_post_data("") == {}
