#!/usr/bin/python3
"""Create a corpus of HKP requests/responses

as delivered by real HKP keyservers.
"""
import os
import requests
import json

HOSTS = ["keys.openpgp.org", "keyserver.ubuntu.com"]
OPS = ["get", "index"]
SEARCH_TERMS = [  # search term, special status
        # special terms are only requested with `index` operation.
        ("snowden@nsa.gov", False),
        ("uli@gnufix.de", False),
        # This key is very large (many signatures)
        # ("tails@boum.org", False),
        # The tails@boum.org key id
        # ("0x09F6BC8FEEC9D8EE005DBAA41D2975EDF93E735F", False),
        # The snowden@nsa.gov key id
        ("0x4271f64cb3b9bc51", False),
        ("nobody@boum.org", True),
        ("invalid-id", True),
        ]


def call_hkp_curl(host, op, search, num=0):
    """Call `curl` to call HKP servers

    returns the used commandline and the servers response including headers
    (`curl` option `-i`).
    """
    url = "https://%s/pks/lookup?op=%s&options=mr&search=%s" % (
                host, op, search)
    cmdline = "curl -i '%s'" % url
    out = os.popen(cmdline).read()
    return cmdline, out


def create_files():
    """Create the files of the corpus.
    """
    num = 1
    for host in HOSTS:
        for op in OPS:
            for search, special in SEARCH_TERMS:
                if special and op == "get":
                    continue
                print("Fetching %s - %s - %s" % (host, op, search))
                cmd, out = call_hkp_curl(host, op, search, num)
                open("hkp-sample-requests", "a").write(
                        ("%02d " % num) + cmd + '\n')
                open("hkp-sample-%02d-%s-%s-%s" % (
                    num, host, op, search), "w").write(out)
                num += 1


def call_hkp_requests(host, op, search):
    """Call HKP servers using `requests` lib.
    """
    url = "https://%s/pks/lookup?op=%s&options=mr&search=%s" % (
                host, op, search)
    r = requests.get(url)
    return {
            'call': url,
            'status_code': r.status_code,
            'reason': r.reason,
            'headers': dict(r.headers),
            'body': r.text}


def create_json_calls():
    """Create a JSON file "hkp-samples.json"

    that contains the requests and responses of the corpus in a format easier
    to process.
    """
    calls = []
    for host in HOSTS:
        for op in OPS:
            for search, special in SEARCH_TERMS:
                if special and op == "get":
                    continue
                print("Fetching %s - %s - %s" % (host, op, search))
                calls.append(call_hkp_requests(host, op, search))
    out = json.dumps(calls)
    open("hkp-samples.json", "w").write(out)


create_json_calls()
create_files()
