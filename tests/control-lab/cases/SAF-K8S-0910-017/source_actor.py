"""Perform only the case-owned marker patch and harmless placement create."""
import json
from pathlib import Path
import ssl
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

BASE = "https://kubernetes.default.svc"
TOKEN = Path("/identity/token")
CA = Path("/identity/ca.crt")
NAMESPACE = "saf-test"
PLAN = "fixture-cross-cluster-placement"
WORKLOAD = "fixture-cross-cluster-workload"
IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)


def call(method, path, value):
    body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    request = Request(BASE + path, data=body, method=method, headers={
        "Authorization": "Bearer " + TOKEN.read_text().strip(),
        "Content-Type": "application/merge-patch+json" if method == "PATCH" else "application/json",
    })
    try:
        with urlopen(request, timeout=8, context=ssl.create_default_context(cafile=str(CA))) as reply:
            reply.read(2048)
            return reply.status
    except HTTPError as error:
        error.read(2048)
        return error.code


def main(source):
    patch_status = call("PATCH", f"/api/v1/namespaces/{NAMESPACE}/configmaps/{PLAN}",
                        {"data": {"action": f"fixture-approved-placement-{source}"}})
    workload = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": WORKLOAD, "namespace": NAMESPACE,
                      "labels": {"saf-fixture": "cross-cluster-audit"}},
        "spec": {"replicas": 1,
                 "selector": {"matchLabels": {"app": WORKLOAD}},
                 "template": {"metadata": {"labels": {"app": WORKLOAD}},
                              "spec": {"automountServiceAccountToken": False,
                                       "terminationGracePeriodSeconds": 3,
                                       "containers": [{
                                           "name": "fixture", "image": IMAGE,
                                           "command": ["sleep", "3600"],
                                           "securityContext": {
                                               "allowPrivilegeEscalation": False,
                                               "privileged": False,
                                               "runAsNonRoot": True,
                                               "runAsUser": 65534,
                                               "seccompProfile": {"type": "RuntimeDefault"},
                                           },
                                       }]}}},
    }
    create_status = call("POST", f"/apis/apps/v1/namespaces/{NAMESPACE}/deployments", workload)
    print(json.dumps({"source": source, "marker_patch_status": patch_status,
                      "placement_create_status": create_status}, sort_keys=True))
    if patch_status != 200 or create_status != 201:
        raise SystemExit(2)


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"a", "b"}:
        raise SystemExit("invalid fixture mode")
    main(sys.argv[1])
