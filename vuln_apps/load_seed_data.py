#!/usr/bin/env python3
"""Re-seed the NoSQLMap vulnerable-app data in an already-running MongoDB.

The compose stack loads this seed automatically on first Mongo boot (the Mongo
image ships the script in ``/docker-entrypoint-initdb.d/``), so you normally do
not need to run this. Use it to reset an existing stack back to its initial
vulnerable state without recreating the container:

    python vuln_apps/load_seed_data.py

It is idempotent (drops and re-inserts the seed collections). It reads the same
seed file the image uses (``docker/mongo/mongo.nosql``) and connects to the
host-exposed Mongo port.
"""

import json
import re
from pathlib import Path

from pymongo import MongoClient

MONGO_URI = "mongodb://root:prisma@localhost:27017/"
SEED_FILE = Path(__file__).parent / "docker" / "mongo" / "mongo.nosql"

# A line that switches the working database, e.g. ``db = db.getSiblingDB('shop')``.
DB_RE = re.compile(r"^db\s*=\s*db\.getSiblingDB\(['\"](\w+)['\"]\)")
# A line that inserts one document, e.g. ``db.orders.insertOne({...})``.
INSERT_RE = re.compile(r"^db\.(\w+)\.insertOne\((\{.*\})\)\s*$")


def parse_seed(path):
    """Yield ``(db, collection, doc)`` tuples from the mongosh seed file."""
    db = None
    for line in path.read_text().splitlines():
        line = line.strip()
        m = DB_RE.match(line)
        if m:
            db = m.group(1)
            continue
        m = INSERT_RE.match(line)
        if m and db:
            yield db, m.group(1), json.loads(m.group(2))


def main():
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command("ping")

    data = {}
    for db, coll, doc in parse_seed(SEED_FILE):
        data.setdefault((db, coll), []).append(doc)

    print("Re-seeding", MONGO_URI)
    for (db, coll), docs in data.items():
        collection = client[db][coll]
        collection.delete_many({})  # idempotent reset
        collection.insert_many(docs)
        print(f"  {db}.{coll}: {len(docs)} docs")

    client.close()


if __name__ == "__main__":
    main()
