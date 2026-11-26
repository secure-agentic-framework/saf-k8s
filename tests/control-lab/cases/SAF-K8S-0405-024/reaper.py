"""Retire one approved fixture grant and credential anchor after its deadline."""
import json
from pathlib import Path
import ssl
import time
from urllib.error import HTTPError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

BASE = "https://kubernetes.default.svc"
NS = "saf-test"
ROOT = Path("/var/run/secrets/kubernetes.io/serviceaccount")
SCHEDULE = f"/api/v1/namespaces/{NS}/configmaps/fixture-retirement-schedule"
BINDING = f"/apis/rbac.authorization.k8s.io/v1/namespaces/{NS}/rolebindings/fixture-expiring-reader"
ANCHOR = f"/api/v1/namespaces/{NS}/secrets/fixture-routine-credential-anchor"


def run():
    client = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context(cafile=str(ROOT/"ca.crt"))))

    def request(path, method):
        token = (ROOT/"token").read_text().strip()
        query = Request(BASE+path, method=method, headers={"Authorization": "Bearer "+token})
        try:
            response = client.open(query, timeout=4)
        except HTTPError as error:
            response = error
        with response:
            return response.status, json.loads(response.read())

    wait_until = time.monotonic() + 85
    while time.monotonic() < wait_until:
        status, obj = request(SCHEDULE, "GET")
        if status != 200:
            raise SystemExit(f"Unable to read fixture deadline (HTTP {status})")
        approved = obj["data"]["deadline"]
        if approved != "pending":
            deadline = int(approved)
            if time.time() >= deadline:
                started = time.time()
                binding_status, _ = request(BINDING, "DELETE")
                anchor_status, _ = request(ANCHOR, "DELETE")
                print(json.dumps({"approved_deadline_reached": started >= deadline,
                                  "scoped_binding_deleted": binding_status == 200,
                                  "credential_anchor_deleted": anchor_status == 200}))
                return 0 if binding_status == anchor_status == 200 else 1
        time.sleep(.5)
    raise SystemExit("The fixture deadline was not reached within the allowed window")


if __name__ == "__main__":
    raise SystemExit(run())
