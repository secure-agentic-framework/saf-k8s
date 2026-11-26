"""Read only one existing case-owned OCI marker; emit status and digest predicate."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

REPO = "saf-test/audit-model"
ACTOR = "fixture-publisher"
password = Path("/auth/password").read_text().strip()
identity = base64.b64encode(f"{ACTOR}:{password}".encode()).decode()
url = f"{sys.argv[1]}/v2/{REPO}/manifests/{sys.argv[2]}"
request = Request(url, headers={"Authorization": "Basic " + identity,
                                "Accept": "application/vnd.oci.image.manifest.v1+json"})
deadline = time.monotonic() + 18
while True:
    try:
        with urlopen(request, timeout=8) as response:
            body, status = response.read(), response.status
        break
    except HTTPError as error:
        status, body = error.code, b""
        break
    except URLError as error:
        if not isinstance(error.reason, ConnectionRefusedError) or time.monotonic() >= deadline:
            raise
        time.sleep(0.25)
print(json.dumps({"status": status,
                  "digest_matches": status == 200 and "sha256:" + hashlib.sha256(body).hexdigest() == sys.argv[3]},
                 sort_keys=True))
