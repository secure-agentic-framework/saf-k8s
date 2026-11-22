"""Report a fixture Pod's own authorization decision or workspace marker."""
from http.client import HTTPSConnection
import json
from pathlib import Path
import ssl
import sys


MOUNT = Path("/var/run/secrets/kubernetes.io/serviceaccount")
TENANT = "saf-0702-024-enrolled"
OTHER = "saf-0702-024-synthetic"
RECORD = "tenant-record"


def main():
    mode, namespace = sys.argv[1:]
    if mode == "review" and namespace in {TENANT, OTHER}:
        method = "POST"
        path = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
        body = json.dumps({
            "apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
            "spec": {"resourceAttributes": {"namespace": namespace, "verb": "get",
                                            "resource": "configmaps", "name": RECORD}},
        })
    elif mode == "read" and namespace == TENANT:
        method = "GET"
        path = f"/api/v1/namespaces/{namespace}/configmaps/{RECORD}"
        body = None
    else:
        raise SystemExit("unsupported fixture operation")

    context = ssl.create_default_context(cafile=str(MOUNT / "ca.crt"))
    connection = HTTPSConnection("kubernetes.default.svc", timeout=8, context=context)
    headers = {"Authorization": "Bearer " + (MOUNT / "token").read_text().strip(),
               "Content-Type": "application/json"}
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        result = json.load(response)
        if mode == "review":
            status = result.get("status", {})
            observation = {"code": response.status, "allowed": status.get("allowed"),
                           "evaluation_error": bool(status.get("evaluationError"))}
        else:
            observation = {"code": response.status, "marker": result.get("data", {}).get("marker")}
        print(json.dumps(observation))
    finally:
        connection.close()


if __name__ == "__main__":
    main()
