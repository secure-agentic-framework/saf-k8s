"""Mock checkpoint reader/restorer. Emits only booleans, HTTP codes, and hashes."""
import base64
import hashlib
import json
import os
import ssl
import sys
import urllib.error
import urllib.request


NAMESPACE = os.environ["POD_NAMESPACE"]
TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
HOST = os.environ["KUBERNETES_SERVICE_HOST"]
PORT = os.environ["KUBERNETES_SERVICE_PORT_HTTPS"]
BASE = f"https://{HOST}:{PORT}/api/v1/namespaces/{NAMESPACE}"
CONTEXT = ssl.create_default_context(cafile=CA_PATH)
TOKEN = open(TOKEN_PATH, encoding="ascii").read().strip()
FIXTURE = "/fixture/fixture.json"


def request(method, path, body=None):
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Authorization": f"Bearer {TOKEN}", "Accept": "application/json",
                 "Content-Type": ("application/merge-patch+json" if method == "PATCH"
                                  else "application/json")},
    )
    try:
        with urllib.request.urlopen(req, context=CONTEXT, timeout=12) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, None


def expected_fixture():
    with open(FIXTURE, encoding="utf-8") as stream:
        return json.load(stream)


def check_source(name, expected):
    status, secret = request("GET", f"/secrets/{name}")
    if status != 200 or not secret:
        return {"get_status": status, "valid": False}
    data = secret.get("data", {})
    try:
        checkpoint = base64.b64decode(data["checkpoint"], validate=True)
        optimizer = base64.b64decode(data["optimizer"], validate=True)
        manifest_status, manifest = request("GET", f"/configmaps/{expected['manifest_name']}")
        hashes = json.loads(manifest["data"]["sha256"]) if manifest_status == 200 else {}
        hashes_match = (
            hashlib.sha256(checkpoint).hexdigest() == hashes.get("checkpoint")
            and hashlib.sha256(optimizer).hexdigest() == hashes.get("optimizer")
        )
        valid = (
            hashes_match
            and checkpoint == expected["checkpoint_bytes"].encode()
            and json.loads(optimizer) == expected["optimizer"]
        )
        return {"get_status": status, "manifest_status": manifest_status, "valid": valid,
                "hashes_match": hashes_match,
                "checkpoint_sha256": hashlib.sha256(checkpoint).hexdigest(),
                "optimizer_sha256": hashlib.sha256(optimizer).hexdigest(),
                "checkpoint": checkpoint, "optimizer_bytes": optimizer,
                "secret": secret}
    except (KeyError, ValueError, TypeError, json.JSONDecodeError):
        return {"get_status": status, "valid": False}


def restore_if_valid(source, expected):
    if not source.get("valid"):
        return {"attempted": False, "put_status": None}
    path = f"/secrets/{expected['restore_name']}"
    status, target = request("GET", path)
    if status != 200 or target is None:
        return {"attempted": False, "put_status": status}
    target["data"] = source["secret"]["data"]
    target["metadata"].pop("managedFields", None)
    status, _ = request("PUT", path, target)
    return {"attempted": True, "put_status": status}


def trainer():
    expected = expected_fixture()
    good = check_source(expected["checkpoint_name"], expected)
    good_restore = restore_if_valid(good, expected)
    bad = check_source(expected["tampered_name"], expected)
    bad_restore = restore_if_valid(bad, expected)
    print(json.dumps({
        "valid_checkpoint": bool(good.get("valid")),
        "valid_checkpoint_sha256": good.get("checkpoint_sha256"),
        "valid_optimizer_sha256": good.get("optimizer_sha256"),
        "restore_update_status": good_restore["put_status"],
        "tampered_checkpoint_rejected": bad.get("valid") is False,
        "tampered_get_status": bad.get("get_status"),
        "tampered_manifest_status": bad.get("manifest_status"),
        "restore_attempted_for_tampered_source": bad_restore["attempted"],
    }, sort_keys=True), flush=True)


def unauthorized():
    expected = expected_fixture()
    read_status, _ = request("GET", f"/secrets/{expected['checkpoint_name']}")
    # A valid merge patch exercises the write authorization check without
    # including checkpoint, optimizer, or key material in its body.
    write_status, _ = request("PATCH", f"/secrets/{expected['restore_name']}",
                              {"metadata": {"annotations": {"saf-k8s.example/probe": "synthetic"}}})
    print(json.dumps({"checkpoint_get_status": read_status,
                      "restore_patch_status": write_status}, sort_keys=True), flush=True)


def observer():
    expected = expected_fixture()
    status, secret = request("GET", f"/secrets/{expected['restore_name']}")
    exact = False
    checkpoint_sha = optimizer_sha = None
    if status == 200 and secret:
        try:
            checkpoint = base64.b64decode(secret["data"]["checkpoint"], validate=True)
            optimizer = base64.b64decode(secret["data"]["optimizer"], validate=True)
            checkpoint_sha = hashlib.sha256(checkpoint).hexdigest()
            optimizer_sha = hashlib.sha256(optimizer).hexdigest()
            exact = (checkpoint == expected["checkpoint_bytes"].encode()
                     and json.loads(optimizer) == expected["optimizer"])
        except (KeyError, ValueError, TypeError, json.JSONDecodeError):
            exact = False
    print(json.dumps({"get_status": status, "exact_restore": exact,
                      "checkpoint_sha256": checkpoint_sha,
                      "optimizer_sha256": optimizer_sha}, sort_keys=True), flush=True)


mode = sys.argv[1]
{"trainer": trainer, "unauthorized": unauthorized, "observer": observer}[mode]()
