"""Shared password-cracking primitives (dictionary + brute force).

Both the MongoDB and CouchDB platform modules drive their password attacks
through :func:`crack`, supplying only a platform-specific ``verifier``
callable. This keeps the cracking loop, character-set menu and dictionary
loading in one place instead of duplicating it per platform.
"""

import itertools
import string

from .exceptions import NoSQLMapException


def genBrute(chars, maxLen):
    """Yield every candidate string from length 1 up to ``maxLen``."""
    return (
        "".join(candidate)
        for candidate in itertools.chain.from_iterable(
            itertools.product(chars, repeat=i) for i in range(1, maxLen + 1)
        )
    )


# Character-set choices shared by the brute-force menu.
CHARSETS = {
    "1": string.ascii_lowercase,
    "2": string.ascii_uppercase,
    "3": string.ascii_letters,
    "4": string.digits,
    "5": string.ascii_letters + string.digits,
    "6": string.ascii_letters + string.digits + "!@#$%^&*()-_+={}[]|~`':;<>,.?/",
}


def prompt_charset():
    """Show the character-set menu and return the selected charset string."""
    print("1-Lower case letters")
    print("2-Upper case letters")
    print("3-Upper + lower case letters")
    print("4-Numbers only")
    print("5-Alphanumeric (upper and lower case)")
    print("6-Alphanumeric + special characters")
    selection = input("\nSelect character set to use:")
    return CHARSETS[selection]


def load_dict():
    """Prompt for a dictionary file and return its lines (newline stripped)."""
    while True:
        dictionary = input("Enter path to password dictionary: ")
        try:
            with open(dictionary) as f:
                return [line.split("\n")[0] for line in f.readlines()]
        except (OSError, NoSQLMapException):
            print(" Couldn't load file.")


def _run_dict(verifier, found_prefix):
    print("Running dictionary attack...")
    for candidate in load_dict():
        if verifier(candidate):
            print(found_prefix + candidate)
            break


def _run_brute(verifier, found_prefix):
    print("\n")
    maxLen = input("Enter the maximum password length to attempt: ")
    chainSet = prompt_charset()
    count = 0
    print("\n", end=" ")
    for attempt in genBrute(chainSet, int(maxLen)):
        print("\rCombinations tested: " + str(count) + "\r")
        count += 1
        if verifier(attempt):
            print("\n" + found_prefix + attempt)
            break


def crack(verifier, found_prefix="Found - "):
    """Run a dictionary or brute-force cracking session.

    ``verifier`` is a callable ``candidate -> bool`` that checks a candidate
    password against the stored hash. ``found_prefix`` is printed before the
    cracked candidate.
    """
    select = True
    print("Select password cracking method: ")
    print("1-Dictionary Attack")
    print("2-Brute Force")
    print("3-Exit")

    while select:
        select = input("Selection: ")
        if select == "1":
            select = False
            _run_dict(verifier, found_prefix)
        elif select == "2":
            select = False
            _run_brute(verifier, found_prefix)
        elif select == "3":
            return
    return
