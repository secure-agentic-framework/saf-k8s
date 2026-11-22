"""Query this fixture Pod's own effective permissions and permitted marker."""
from http.client import HTTPSConnection
import json
from pathlib import Path
import ssl
import sys


MOUNT = Path("/var/run/secrets/kubernetes.io/serviceaccount")
NAMESPACE = "saf-test"
FIXTURES = {"saf-0402-019-alpha-fixture", "saf-0402-019-beta-fixture"}
REVIEW_PATH = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"


def request(method, path, document=None):
    context = ssl.create_default_context(cafile=str(MOUNT / "ca.crt"))
    connection = HTTPSConnection("kubernetes.default.svc", timeout=5, context=context)
    headers = {"Authorization": "Bearer " + (MOUNT / "token").read_text().strip()}
    if document is not None:
        headers["Content-Type"] = "application/json"
    try:
        connection.request(method, path, body=document, headers=headers)
        response = connection.getresponse()
        return response.status, json.load(response)
    finally:
        connection.close()


def main():
    mode, name = sys.argv[1:3]
    if name not in FIXTURES:
        raise SystemExit("unknown synthetic fixture")
    if mode == "review":
        review = {
            "apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
            "spec": {"resourceAttributes": {"namespace": NAMESPACE, "verb": "get",
                                            "resource": "configmaps", "name": name}},
        }
        status, result = request("POST", REVIEW_PATH, json.dumps(review))
        decision = result.get("status", {}).get("allowed")
        print(status, "allowed" if decision is True else "denied" if decision is False else "missing-decision")
    elif mode == "read":
        status, result = request("GET", f"/api/v1/namespaces/{NAMESPACE}/configmaps/{name}")
        print(status, "expected-marker" if result.get("data", {}).get("marker") == sys.argv[3] else "missing-marker")
    else:
        raise SystemExit("unknown fixture mode")


if __name__ == "__main__":
    main()
