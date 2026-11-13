"""Vulnerable NoSQL-injection demo app (Flask port of the original PHP app).

This app intentionally exposes NoSQL-injection flaws so that NoSQLMap can be
tested against it. Each endpoint passes user input straight to a MongoDB query
without sanitization.

Endpoints:
  /acct         -- operator injection (customers.paymentinfo)
  /userdata     -- $where string escape (appUserData.users, quoted context)
  /orderdata    -- $where string escape (shop.orders, quoted context)
  /numericdata  -- $where integer escape (shop.orders, numeric context)
  /             -- landing page

Run locally (with MongoDB reachable at MONGO_URI):
    python app.py
or in Docker:
    cd vuln_apps && docker compose up -d --build
"""

import os
import re

from flask import Flask, Response, request
from pymongo import MongoClient

app = Flask(__name__)

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://root:prisma@mongo:27017")
_client = None


def get_client():
    """Return a shared MongoClient (created lazily on first use)."""
    global _client
    if _client is None:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    return _client


def parse_php_query(args):
    """Parse PHP-style bracket notation into nested dicts.

    PHP automatically parses ``?account_id[$ne]=`` into
    ``$_GET['account_id'] = ['$ne' => '']``. Flask's ``request.args`` does not
    do this, so this helper replicates the behaviour for the operator-injection
    case.

    Examples:
        ``account_id[$ne]=``  ->  ``{'account_id': {'$ne': ''}}``
        ``a[b][c]=1``         ->  ``{'a': {'b': {'c': '1'}}}``
        ``account_id=42``     ->  ``{'account_id': '42'}``
    """
    result = {}
    for raw_key, value in args.items():
        # Split 'a[b][c]' into ['a', 'b', 'c'].
        parts = re.findall(r"[^\[\]]+", raw_key)
        if not parts:
            continue
        d = result
        for part in parts[:-1]:
            d = d.setdefault(part, {})
        d[parts[-1]] = value
    return result


def _render_payment(obj):
    return (
        f"Name: {obj['name']}<br/>\n"
        f"Customer ID: {obj['id']}<br/>\n"
        f"Card Number: {obj['cc']}<br/>\n"
        f"CVV2 Code: {obj['cvv2']}<br/>\n"
        f"<br/>\n"
    )


def _render_user(obj):
    return (
        f"Name: {obj['name']}<br/>\n"
        f"Username: {obj['username']}<br/>\n"
        f"Email: {obj['email']}<br/>\n"
        f"<br/>\n"
    )


def _render_order(obj):
    return (
        f"Order ID: {obj['id']}<br/>\n"
        f"Name: {obj['name']}<br/>\n"
        f"Item: {obj['item']}<br/>\n"
        f"Quantity: {obj['quantity']}<br/>\n"
        f"<br/>\n"
    )


@app.route("/acct")
def acct():
    """Operator injection: pass the parsed (possibly nested) value to the filter.

    A normal lookup (``?account_id=42``) returns one record. An operator payload
    (``?account_id[$ne]=``) injects a BSON operator and dumps the whole
    collection.
    """
    parsed = parse_php_query(request.args)
    account_id = parsed.get("account_id")
    if account_id is None:
        return "No account ID provided.", 400
    try:
        client = get_client()
        cursor = client["customers"]["paymentinfo"].find({"id": account_id})
        rows = [_render_payment(obj) for obj in cursor]
        count = len(rows)
        rows.append(f"{count} document(s) found. <br/>\n")
        return Response("".join(rows))
    except Exception as e:
        return f"Error: {e}", 500


@app.route("/userdata")
def userdata():
    """$where string escape (quoted context).

    The input is embedded in a quoted string inside the $where JavaScript
    function. A crafted payload breaks out of the quotes and injects JS.
    """
    name = request.args.get("name", "")
    if not name:
        return "No name provided.", 400
    js = f"function () {{ var query = '{name}'; return this.username == query;}}"
    try:
        client = get_client()
        cursor = client["appUserData"]["users"].find({"$where": js})
        rows = [_render_user(obj) for obj in cursor]
        count = len(rows)
        rows.append(f"{count} user(s) found. <br/>\n")
        return Response("".join(rows))
    except Exception as e:
        return f"Error: {e}", 500


@app.route("/orderdata")
def orderdata():
    """$where string escape (quoted context, shop.orders)."""
    order = request.args.get("order", "")
    if not order:
        return "No order provided.", 400
    js = f"function () {{ var query = '{order}'; return this.id == query;}}"
    try:
        client = get_client()
        cursor = client["shop"]["orders"].find({"$where": js})
        rows = [_render_order(obj) for obj in cursor]
        count = len(rows)
        rows.append(f"{count} order(s) found. <br/>\n")
        return Response("".join(rows))
    except Exception as e:
        return f"Error: {e}", 500


@app.route("/numericdata")
def numericdata():
    """$where integer escape (numeric context, no quotes).

    The input is embedded in an unquoted numeric context inside the $where
    JavaScript function. A crafted payload (e.g. ``1; return true;``) injects
    JS without needing to break out of quotes.
    """
    order = request.args.get("order", "")
    if not order:
        return "No order provided.", 400
    js = f"function () {{ var query = {order}; return this.id == query;}}"
    try:
        client = get_client()
        cursor = client["shop"]["orders"].find({"$where": js})
        rows = [_render_order(obj) for obj in cursor]
        count = len(rows)
        rows.append(f"{count} order(s) found. <br/>\n")
        return Response("".join(rows))
    except Exception as e:
        return f"Error: {e}", 500


INDEX_HTML = """<html>
    <head>
        <title>Customer Info</title>
    </head>

    <body>
        <h1>Customer Information</h1>
        <p>
            This demo application exposes lookups, each backed by a MongoDB
            query that is vulnerable to NoSQL injection.
        </p>

        <h2>1. Account lookup</h2>
        <h3>Enter your customer ID to show your account information:</h3>
        <form method="get" action="acct">
            Customer ID:
            <input type="text" name="account_id" value="" />
            <br />
            <input type="submit" />
        </form>

        <h2>2. User lookup</h2>
        <h3>Search a user profile by name:</h3>
        <form method="get" action="userdata">
            Name:
            <input type="text" name="name" value="" />
            <br />
            <input type="submit" />
        </form>

        <h2>3. Order lookup</h2>
        <h3>Use the Order ID to locate your order:</h3>
        <form method="get" action="orderdata">
            Order:
            <input type="text" name="order" value="" />
            <br />
            <input type="submit" />
        </form>

        <h2>4. Numeric order lookup</h2>
        <h3>Use the Order ID (numeric context) to locate your order:</h3>
        <form method="get" action="numericdata">
            Order:
            <input type="text" name="order" value="" />
            <br />
            <input type="submit" />
        </form>
    </body>
</html>"""


@app.route("/")
def index():
    return Response(INDEX_HTML, content_type="text/html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
