"""Write one release record from the live, case-owned Argo/Kubernetes state."""
import json
import os
from pathlib import Path
import re
import ssl
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener


API = "https://kubernetes.default.svc"
TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
SOURCE_INDEX = os.environ["SOURCE_INDEX"]
APP = os.environ["APP_NAME"]
NAMESPACE = os.environ["APP_NAMESPACE"]
DEPLOYMENT = os.environ["DEPLOYMENT_NAME"]
VERSION = os.environ["PACKAGE_VERSION"]
EXPECTED_RECORD = os.environ["RELEASE_RECORD"]
REPOSITORY = os.environ["SOURCE_REPOSITORY"]


class FixtureError(Exception):
    pass


def api(method, path, token, payload=None):
    body = None if payload is None else json.dumps(payload, sort_keys=True).encode()
    headers = {"Authorization": "Bearer " + token,
               "Accept": "application/json",
               "Content-Type": "application/json"}
    request = Request(API + path, data=body, headers=headers, method=method)
    try:
        with build_opener(ProxyHandler({}), HTTPSHandler(
                context=ssl.create_default_context(cafile=CA_PATH))).open(request, timeout=5) as response:
            raw = response.read(1_000_000)
            if len(raw) >= 1_000_000:
                raise FixtureError("bounded API response exceeded the fixture limit")
            return response.status, (json.loads(raw) if raw else {})
    except HTTPError as error:
        # Do not read or stringify the response body or request headers.
        raise FixtureError(f"API returned HTTP {error.code}") from None
    except (OSError, URLError, ssl.SSLError, ValueError):
        raise FixtureError("authenticated API operation failed") from None


def get(path, token):
    status, value = api("GET", path, token)
    if status != 200:
        raise FixtureError(f"read returned HTTP {status}")
    return value


def observe_release(token, release):
    app_path = f"/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/{APP}"
    app = get(app_path, token)
    app_status = app.get("status", {})
    app_spec = app.get("spec", {})
    destination = app_spec.get("destination", {})
    app_source = app_spec.get("source", {})
    operation = app_status.get("operationState", {})
    commit = operation.get("syncResult", {}).get("revision")
    if (operation.get("phase") not in {"Running", "Succeeded"}
            or commit != release.get("commit")
            or app_source.get("targetRevision") != commit
            or app_source.get("repoURL") != REPOSITORY
            or app_source.get("path") != "chart"
            or destination.get("namespace") != NAMESPACE):
        raise FixtureError("Argo operation has not resolved this exact release")

    deployment = get(f"/apis/apps/v1/namespaces/{NAMESPACE}/deployments/{DEPLOYMENT}", token)
    spec = deployment.get("spec", {})
    template = spec.get("template", {})
    metadata = template.get("metadata", {})
    pod_spec = template.get("spec", {})
    containers = pod_spec.get("containers", [])
    if len(containers) != 1 or metadata.get("labels", {}).get("app.kubernetes.io/version") != VERSION:
        raise FixtureError("live Deployment version does not match this release")
    env = {entry.get("name"): entry.get("value") for entry in containers[0].get("env", [])}
    if env.get("PACKAGE_VERSION") != VERSION or spec.get("replicas") != 1:
        raise FixtureError("live Deployment metadata does not match the release")

    selector = quote(f"app.kubernetes.io/name=release-fixture,app.kubernetes.io/version={VERSION}", safe="")
    pods = get(f"/api/v1/namespaces/{NAMESPACE}/pods?labelSelector={selector}", token).get("items", [])
    ready = []
    for pod in pods:
        status = pod.get("status", {})
        ready_condition = any(c.get("type") == "Ready" and c.get("status") == "True"
                              for c in status.get("conditions", []))
        if pod.get("metadata", {}).get("deletionTimestamp") or status.get("phase") != "Running" or not ready_condition:
            continue
        pod_containers = pod.get("spec", {}).get("containers", [])
        states = status.get("containerStatuses", [])
        if len(pod_containers) != 1 or len(states) != 1 or states[0].get("name") != "fixture":
            continue
        image_id = states[0].get("imageID", "")
        digest = re.search(r"sha256:[0-9a-f]{64}$", image_id)
        if digest:
            ready.append({"version": VERSION, "image": pod_containers[0].get("image"),
                          "runtime_digest": digest.group(0)})
    if len(ready) != 1 or ready[0]["image"] != containers[0].get("image"):
        raise FixtureError("exactly one ready release Pod with a runtime digest is required")

    return commit, ready[0]


def run():
    token = TOKEN_PATH.read_text(encoding="utf-8").strip()
    if not token or "\n" in token:
        raise FixtureError("projected service identity is unavailable")

    index = get(f"/api/v1/namespaces/{NAMESPACE}/configmaps/{SOURCE_INDEX}", token)
    source = json.loads(index["data"]["releases.json"])
    release = source["releases"].get(VERSION)
    if not release or release.get("record") != EXPECTED_RECORD:
        raise FixtureError("version is absent from the immutable source index")

    deadline = time.monotonic() + 40
    while True:
        try:
            commit, ready = observe_release(token, release)
            break
        except FixtureError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.5)

    record = {
        "package": {"name": "release-fixture", "type": "helm-chart", "version": VERSION},
        "artifact": {"identity_type": "git-chart-tree-object", "repository": REPOSITORY,
                     "path": "chart", "git_commit": commit, "git_tree_oid": release["tree_oid"]},
        "workload_image": ready,
        "environment": {"cluster": source["cluster"], "namespace": NAMESPACE},
    }
    record_object = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": EXPECTED_RECORD,
                     "labels": {"saf.example/release-record": "true",
                                "saf.example/release-version": VERSION,
                                "saf.example/record-writer": "argo-postsync"}},
        "immutable": True,
        "data": {"release.json": json.dumps(record, sort_keys=True)},
    }
    status, _ = api("POST", f"/api/v1/namespaces/{NAMESPACE}/configmaps", token, record_object)
    if status != 201:
        raise FixtureError(f"record creation returned HTTP {status}")
    return {"status": "created", "release": VERSION, "record": EXPECTED_RECORD}


if __name__ == "__main__":
    try:
        print(json.dumps(run(), sort_keys=True, separators=(",", ":")), flush=True)
    except FixtureError as error:
        # FixtureError messages are controlled constants and integer status codes.
        print(json.dumps({"status": "failed", "reason": str(error)}), flush=True)
        sys.exit(1)
    except (OSError, KeyError, ValueError, TypeError):
        print('{"status":"failed","reason":"fixture-gate"}', flush=True)
        sys.exit(1)
