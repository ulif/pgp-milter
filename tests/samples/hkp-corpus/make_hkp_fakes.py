#!/usr/bin/python3
"""Create fake HKP requests/responses

that mimic real HKP responses.
"""
import pathlib
import json


SAMPLE_KEY_DIR = pathlib.Path(__file__).absolute().parent.parent.parent
FAKE_DATA = [
        ("keys.openpgp.org", "alice@sample.net",
            "FC576D66A075141F41770B15F028476ACE63FE41", "alice1.pub"),
        ("keys.openpgp.org", "bob@sample.net",
            "FDBE48E6FE58D021A5C8BE3B982AD46FA8789D5C", "bob.pub"),
        ]


def fake_hkp_requests(fake_entry):
    """Create HTTP response that mimics real HKP servers.
    """
    host, email, fpr, filename = fake_entry
    url = "https://%s/pks/lookup?op=get&options=mr&search=%s" % (host, email)
    attchmnt = "attachment; filename*=US-ASCII''%s.asc" % fpr
    path = SAMPLE_KEY_DIR / filename
    body = path.read_text()
    return {
            'call': url,
            'status_code': 200,
            'reason': "OK",
            'headers': {
                "Server": "nginx/1.14.2",
                "Date": "Sun, 14 Nov 2021 03:04:58 GMT",
                "Content-Type": "application/pgp-keys",
                "Content-Length": len(body),
                "Last-Modified": "Sat, 14 Aug 2021 01:39:45 GMT",
                "Connection": "keep-alive",
                "Content-Disposition": attchmnt,
                "Cache-Control": "no-cache",
                },
            'body': body

            }


def create_fake_json_calls():
    """Create a JSON file "hkp-samples-fake.json"

    that contains the requests and responses of the fake requests in a format
    easier to process.
    """
    calls = []
    for entry in FAKE_DATA:
        calls.append(fake_hkp_requests(entry))
    out = json.dumps(calls)
    print("Writing fake request data to hkp-samples-fake.json")
    open("hkp-samples-fake.json", "w").write(out)


create_fake_json_calls()
