"""Verify namespace RBAC and a promotion-record-backed admission policy."""
import json
import runpy
import os
from pathlib import Path
import subprocess
import time

SCOPE = (
    "Disposable kind Kubernetes v1.36.1 cluster. Tests namespace-scoped Deployment "
    "authorization with a short-lived fixture ServiceAccount token, then a "
    "ValidatingAdmissionPolicy parameterized by a protected namespace-local "
    "ConfigMap promotion record. Deployments have zero replicas and inert images."
)
RELEASE = "saf-model-release"
STAGING = "saf-model-staging"
ACCOUNT = "model-deployer"
POLICY = "saf-model-promotion-policy"
BINDING = "saf-model-promotion-binding"
MODEL_ID = "fixture-model-a"
PROMOTION_ID = "promotion-fixture-001"
IMAGE = "example.invalid/saf/fixture-model-a@sha256:" + "a" * 64


def manifest(name, model_id=MODEL_ID, promotion_id=PROMOTION_ID, image=IMAGE, namespace=RELEASE):
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {
            "name": name, "namespace": namespace,
            "annotations": {
                "saf.example.com/model-id": model_id,
                "saf.example.com/promotion-record": promotion_id,
            },
        },
        "spec": {
            "replicas": 0,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {"containers": [{"name": "model", "image": image}]},
            },
        },
    }


def _client(lab, config, namespace, *args, payload=None):
    return lab.command("kubectl", "--kubeconfig", str(config), "--context", "fixture",
                       "--namespace", namespace, "--request-timeout=15s", *args,
                       payload=json.dumps(payload) if payload is not None else None,
                       timeout=25, allow_failure=True)


def _fixture_config(lab):
    admin = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}"]
    result = subprocess.run(
        [*admin, "--namespace", RELEASE, "create", "token", ACCOUNT, "--duration=10m"],
        text=True, capture_output=True, env=lab.env, timeout=25,
    )
    if result.returncode:
        lab.block("Could not mint a short-lived token for the case-owned ServiceAccount")
    token = result.stdout.strip()
    if not token or any(ch.isspace() for ch in token):
        lab.block("kubectl create token returned an invalid token value")
    view = subprocess.run([*admin, "config", "view", "--minify", "--flatten", "--raw", "-o", "json"],
                          text=True, capture_output=True, env=lab.env, timeout=25)
    if view.returncode:
        lab.block("Could not read the case-owned API endpoint and its CA")
    source = json.loads(view.stdout)["clusters"][0]["cluster"]
    cluster = {"server": source["server"], "certificate-authority-data": source["certificate-authority-data"]}
    credential = {"apiVersion": "v1", "kind": "Config", "current-context": "fixture",
                  "clusters": [{"name": "fixture", "cluster": cluster}],
                  "contexts": [{"name": "fixture", "context": {"cluster": "fixture", "user": "fixture"}}],
                  "users": [{"name": "fixture", "user": {"token": token}}]}
    path = lab.kubeconfig.with_name("fixture-credential")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump(credential, output)
    return path


def _denied(result, *expected_details):
    caller = f'User "system:serviceaccount:{RELEASE}:{ACCOUNT}"'
    return (result.returncode != 0 and "(Forbidden)" in result.stderr and caller in result.stderr
            and all(detail in result.stderr for detail in expected_details))


def _admission_denied(result, detail):
    return (result.returncode != 0 and "ValidatingAdmissionPolicy" in result.stderr
            and POLICY in result.stderr and BINDING in result.stderr and detail in result.stderr)


def _created(result, name):
    return result.returncode == 0 and result.stdout.strip() == f"deployment.apps/{name}"


def _create_release_resource(lab, resource):
    lab.kubectl("-n", RELEASE, "create", "-f", "-", payload=json.dumps(resource))


def run(lab):
    here = Path(__file__).resolve().parent
    lab.kubectl("create", "namespace", RELEASE)
    lab.kubectl("create", "namespace", STAGING)
    lab.kubectl("label", "namespace", RELEASE, "saf.example.com/model-release=true")
    lab.kubectl("create", "serviceaccount", ACCOUNT, "-n", RELEASE)

    record = json.loads((here / "promotion-record.json").read_text())
    record["metadata"]["namespace"] = RELEASE
    _create_release_resource(lab, record)
    api = "rbac.authorization.k8s.io/v1"
    _create_release_resource(lab, {
        "apiVersion": api, "kind": "Role",
        "metadata": {"name": "model-deployer", "namespace": RELEASE},
        "rules": [{"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["create"]},
                  {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["model-promotion"],
                   "verbs": ["get"]}],
    })
    _create_release_resource(lab, {
        "apiVersion": api, "kind": "RoleBinding",
        "metadata": {"name": "model-deployer", "namespace": RELEASE},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "model-deployer"},
        "subjects": [{"kind": "ServiceAccount", "name": ACCOUNT, "namespace": RELEASE}],
    })
    config = _fixture_config(lab)
    result = _client(lab, config, RELEASE, "auth", "whoami", "-o", "json")
    username = json.loads(result.stdout)["status"]["userInfo"]["username"] if result.returncode == 0 else None
    lab.check("positive", "API authenticates the caller as the enrolled fixture ServiceAccount",
              username == f"system:serviceaccount:{RELEASE}:{ACCOUNT}", {"username": username})

    # With the release principal authorized but admission inactive, a false promotion
    # annotation reaches and is accepted by the API server.
    red_name = "baseline-wrong-promotion"
    unapproved = manifest(red_name, promotion_id="promotion-unapproved-999")
    red = _client(lab, config, RELEASE, "create", "-f", "-", "-o", "name", "--dry-run=server",
                  payload=unapproved)
    lab.check("red", "Before admission policy, a release-authorized principal can submit an unapproved promotion reference",
              _created(red, red_name), red.stdout.strip() if red.returncode == 0 else red.stderr.strip())

    policy = json.loads((here / "admission-policy.json").read_text())
    binding = json.loads((here / "admission-binding.json").read_text())
    lab.create(policy)
    lab.create(binding)

    deadline = time.monotonic() + 25
    detail = "promotion record reference does not match"
    while True:
        denied = _client(lab, config, RELEASE, "create", "-f", "-", "-o", "name", "--dry-run=server",
                         payload=unapproved)
        if denied.returncode != 0 or time.monotonic() >= deadline:
            break
        time.sleep(0.3)
    lab.check("green", "Admission rejects the same unapproved promotion reference in the release namespace",
              _admission_denied(denied, detail), denied.stderr.strip())

    good_name = "approved-fixture-model"
    good = _client(lab, config, RELEASE, "create", "-f", "-", "-o", "name",
                   payload=manifest(good_name))
    lab.check("positive", "The authorized principal can create a digest-pinned Deployment matching the protected promotion record",
              _created(good, good_name), good.stdout.strip() if good.returncode == 0 else good.stderr.strip())

    wrong_model = _client(lab, config, RELEASE, "create", "-f", "-", "-o", "name",
                          payload=manifest("blocked-wrong-model", model_id="fixture-model-b"))
    lab.check("green", "Admission rejects a model ID that differs from the promotion record",
              _admission_denied(wrong_model, "model ID does not match the promotion record"),
              wrong_model.stderr.strip())

    wrong_digest = "example.invalid/saf/fixture-model-a@sha256:" + "b" * 64
    digest = _client(lab, config, RELEASE, "create", "-f", "-", "-o", "name",
                     payload=manifest("blocked-wrong-digest", image=wrong_digest))
    lab.check("green", "Admission rejects an image digest that differs from the promotion record",
              _admission_denied(digest, "model image digest does not match the promotion record"),
              digest.stderr.strip())

    cross_namespace = _client(lab, config, STAGING, "create", "-f", "-", "-o", "name",
                              payload=manifest("blocked-staging", namespace=STAGING))
    lab.check("green", "The same principal cannot deploy into the staging namespace without a RoleBinding there",
              _denied(cross_namespace, 'cannot create resource "deployments"', f'in the namespace "{STAGING}"'),
              cross_namespace.stderr.strip())

    record_write = _client(lab, config, RELEASE, "patch", "configmap/model-promotion",
                           "--type=merge", "-p", '{"data":{"status":"revoked"}}', "-o", "name")
    lab.check("green", "The deployment principal cannot change the promotion record it relies on",
              _denied(record_write, f'cannot patch resource "configmaps"'), record_write.stderr.strip())

    runtime = runpy.run_path(str(Path(__file__).with_name("registry_runtime.py")))
    runtime["run"](lab)

SCOPE += " A separate namespace and private TLS registry isolate the actual runtime pull authorization comparison."
