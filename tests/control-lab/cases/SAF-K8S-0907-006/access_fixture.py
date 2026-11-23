"""Synthetic public-marker seeder and observer for the PVC/API access case."""
import json
import base64
import os
from pathlib import Path
import ssl
import sys
import urllib.error
import urllib.request

NS = "saf-test"
API_NAMES = {"alpha": "fixture-training-alpha", "beta": "fixture-training-beta"}
MARKERS = {"alpha": "public-fixture-alpha-v1", "beta": "public-fixture-beta-v1"}
GROUPS = {"alpha": 21001, "beta": 21002}


def seed():
    root = Path("/datasets")
    for key, marker in MARKERS.items():
        directory = root / key
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / "marker.txt"
        target.write_text(marker + "\n", encoding="ascii")
        os.chown(directory, 0, GROUPS[key])
        os.chmod(directory, 0o750)
        os.chown(target, 0, GROUPS[key])
        os.chmod(target, 0o440)


def api_read(key):
    port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
    path = f"/api/v1/namespaces/{NS}/configmaps/{API_NAMES[key]}"
    token = Path("/var/run/secrets/kubernetes.io/serviceaccount/token").read_text().strip()
    ca = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    request = urllib.request.Request("https://kubernetes.default.svc:" + port + path,
                                     headers={"Authorization": "Bearer " + token})
    context = ssl.create_default_context(cafile=ca)
    try:
        with urllib.request.urlopen(request, context=context, timeout=8) as reply:
            body = json.loads(reply.read())
            return {"status": reply.status, "marker": body.get("data", {}).get("marker")}
    except urllib.error.HTTPError as error:
        return {"status": error.code}


def file_read(key):
    try:
        marker = (Path("/datasets") / key / "marker.txt").read_text(encoding="ascii").strip()
        return {"allowed": True, "marker": marker}
    except PermissionError:
        return {"allowed": False, "error": "permission-denied"}


def probe(mode):
    keys = ("alpha", "beta")
    token = Path("/var/run/secrets/kubernetes.io/serviceaccount/token").read_text().strip()
    encoded_claims = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(encoded_claims + "=" * (-len(encoded_claims) % 4)))
    print(json.dumps({
        "identity": claims.get("sub"),
        "api": {key: api_read(key) for key in keys},
        "files": {key: file_read(key) for key in keys},
    }, sort_keys=True))


if __name__ == "__main__":
    command = sys.argv[1]
    if command == "seed":
        seed()
    elif command == "probe":
        probe(sys.argv[2])
    elif command == "sleep":
        import time
        time.sleep(3600)
