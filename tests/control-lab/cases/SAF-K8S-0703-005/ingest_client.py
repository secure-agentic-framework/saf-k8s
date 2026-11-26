"""Fixed 4/5-byte same-record HTTP acceptance and readback comparison."""
import hashlib
import json
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler

BASE = "http://saf-0703-005-ingest:8081"
opener = build_opener(ProxyHandler({}))


def call(path, method="GET", body=None):
    request = Request(BASE + path, data=body, method=method)
    try:
        with opener.open(request, timeout=3) as response:
            status, content = response.status, response.read()
    except HTTPError as response:
        status, content = response.code, response.read()
    return status, json.loads(content)


def read_record():
    status, value = call("/records/fixture-one")
    if status != 200 or value.get("id") != "fixture-one":
        raise SystemExit("record read failed")
    data = bytes.fromhex(value["record_hex"])
    return value["revision"], data


initial_revision, initial_record = read_record()
if initial_revision != 0 or initial_record != b"INIT":
    raise SystemExit("unexpected initial fixture record")

accepted_status, accepted = call("/records/fixture-one/ingest", "POST", b"TEST")
accepted_revision, accepted_record = read_record()
if accepted_status != 202 or accepted != {"accepted": True, "revision": 1}:
    raise SystemExit("four-byte request was not accepted as expected")
if accepted_revision != 1 or accepted_record != b"TEST":
    raise SystemExit("accepted record readback did not match")

rejected_status, rejected = call("/records/fixture-one/ingest", "POST", b"ABCDE")
rejected_revision, rejected_record = read_record()
if rejected_status != 413 or rejected != {"error": "input-too-large", "limit_bytes": 4}:
    raise SystemExit("five-byte request was not rejected as expected")
if rejected_revision != accepted_revision or rejected_record != accepted_record:
    raise SystemExit("rejected request changed the fixture record")

print(json.dumps({
    "single_record_id": "fixture-one",
    "initial_read_verified": True,
    "accepted_http_status": accepted_status,
    "accepted_input_bytes": 4,
    "accepted_readback_verified": True,
    "accepted_readback_sha256": hashlib.sha256(accepted_record).hexdigest(),
    "rejected_http_status": rejected_status,
    "rejected_input_bytes": 5,
    "rejected_readback_unchanged": True,
    "rejected_readback_sha256": hashlib.sha256(rejected_record).hexdigest(),
}, sort_keys=True))
