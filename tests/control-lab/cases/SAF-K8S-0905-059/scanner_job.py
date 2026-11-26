"""Bounded structure-only scanner for the case-owned inert source endpoint."""
import hashlib
import json
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

SOURCE = "http://model-source:8080/model.json"
EXPECTED = {"kind": "inert-synthetic-model", "format": "fixture-v1"}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


with build_opener(ProxyHandler({}), NoRedirect()).open(SOURCE, timeout=5) as response:
    if response.status != 200:
        raise RuntimeError("owned source returned an unexpected status")
    if response.geturl() != SOURCE:
        raise RuntimeError("source response changed endpoint")
    raw = response.read(4097)
    if len(raw) > 4096:
        raise RuntimeError("owned source exceeded the fixture size bound")
parsed = json.loads(raw)
status = "pass" if parsed == EXPECTED else "fail"
receipt = {"scan_result": {"scanner": "fixture-json-structure-v1", "status": status,
                           "source_digest": "sha256:" + hashlib.sha256(raw).hexdigest()},
           "source_bytes_bounded": len(raw) <= 4096}
print(json.dumps(receipt, sort_keys=True))
if status != "pass":
    raise SystemExit(1)
