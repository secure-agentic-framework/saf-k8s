"""Exercise the published exception fixture at an actual admission consumer."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import runpy
import time
import uuid

HERE = Path(__file__).resolve().parent
NS = "saf-test"
KYVERNO_NS = "kyverno"
APPROVER = "fixture-exception-approver"
POLICY = "saf-lab-1006-010-runtime-exception"
CHART_VERSION = "3.10.0"
CHART_SHA256 = "55961392dc0821eb367323f0e9585c061dd4407ef7ada921bd56ea1642c2a301"
EXPIRY_SECONDS = 45
MAX_WAIT_AFTER_EXPIRY = 75
DENIAL = "SAF-LAB-1006-010: fixture exception expired"
def _admin(lab, *args, namespace=NS, timeout=60, allow_failure=False, payload=None):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "--namespace", namespace, f"--request-timeout={timeout - 5}s", *args,
        timeout=timeout, allow_failure=allow_failure, payload=payload,
    )


def _install_kyverno(lab):
    helm_home = Path(lab.kubeconfig).parent / "helm"
    for directory in ("cache", "config", "data"):
        (helm_home / directory).mkdir(parents=True, exist_ok=True)

    def helm(*args, timeout=220):
        return lab.command(
            "env", f"HELM_CACHE_HOME={helm_home / 'cache'}",
            f"HELM_CONFIG_HOME={helm_home / 'config'}",
            f"HELM_REGISTRY_CONFIG={helm_home / 'registry.json'}",
            f"HELM_DATA_HOME={helm_home / 'data'}", "helm", *args, timeout=timeout,
        )

    directory = Path(lab.kubeconfig).parent
    helm("pull", "oci://ghcr.io/kyverno/charts/kyverno", "--version", CHART_VERSION,
         "--destination", str(directory), timeout=90)
    chart = directory / f"kyverno-{CHART_VERSION}.tgz"
    digest = sha256(chart.read_bytes()).hexdigest()
    if digest != CHART_SHA256:
        lab.block(f"Pinned Kyverno chart SHA-256 mismatch: {digest}")
    helm("upgrade", "--install", "kyverno", str(chart),
         "--kubeconfig", str(lab.kubeconfig), "--kube-context", f"kind-{lab.cluster}",
         "--namespace", KYVERNO_NS, "--create-namespace", "--wait", "--timeout", "180s",
         "--set", "webhooksCleanup.enabled=false",
         "--set", "features.generateValidatingAdmissionPolicy.enabled=false")
    _admin(lab, "rollout", "status", "deployment/kyverno-admission-controller", "--timeout=90s",
           namespace=KYVERNO_NS, timeout=100)


def _fixture_client(lab, config, *args, payload=None, allow_failure=False, timeout=35):
    return lab.command(
        "kubectl", "--kubeconfig", str(config), "--context", "fixture", "--namespace", NS,
        f"--request-timeout={timeout - 5}s", *args, timeout=timeout,
        allow_failure=allow_failure,
        payload=json.dumps(payload, separators=(",", ":")) if payload is not None else None,
    )


def _server_time(lab, prefix):
    """Read UTC assigned by the API server to a new, inert evidence ConfigMap."""
    name = f"{prefix}-{uuid.uuid4().hex[:10]}"
    result = _admin(lab, "create", "configmap", name, "--from-literal=purpose=clock-sample",
                    "-o", "json", timeout=25)
    stamp = json.loads(result.stdout).get("metadata", {}).get("creationTimestamp")
    if not stamp or not stamp.endswith("Z"):
        lab.block("API server did not return a UTC creationTimestamp for the clock sample")
    try:
        value = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        lab.block(f"API server returned an invalid RFC3339 UTC creationTimestamp: {stamp}")
    if value.tzinfo != timezone.utc:
        lab.block("API server clock sample was not UTC")
    return stamp, value


def _wait_until_server_time(lab, expiry):
    deadline = time.monotonic() + MAX_WAIT_AFTER_EXPIRY
    last = None
    while time.monotonic() < deadline:
        stamp, value = _server_time(lab, "expiry-observed")
        last = (stamp, value)
        if value > expiry:
            return stamp, value
        time.sleep(0.5)
    lab.block(f"API-server UTC did not pass the bounded exception expiry; last sample={last}")


def _workload():
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {
            "name": "saf-ai-exception-workload", "namespace": NS,
            "labels": {"saf-lab.example/purpose": "exception-governance-fixture"},
            "annotations": {"saf-lab.example/policy-exception": "exact-approved"},
        },
        "spec": {
            "replicas": 0,
            "selector": {"matchLabels": {"app": "saf-ai-exception-workload"}},
            "template": {"metadata": {"labels": {
                "app": "saf-ai-exception-workload",
                "saf-lab.example/purpose": "exception-governance-fixture",
            }}, "spec": {"automountServiceAccountToken": False,
                "containers": [{"name": "inert-fixture",
                    "image": "registry.k8s.io/pause:3.10.1@sha256:"
                            "278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c",
                    "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                  "limits": {"cpu": "20m", "memory": "32Mi"}}}]}}},
    }


def _dry_run(lab, config, workload):
    return _fixture_client(lab, config, "create", "-f", "-", "-o", "json",
                          "--dry-run=server", payload=workload, allow_failure=True)


def _admitted(result, workload):
    if result.returncode:
        return False
    try:
        obj = json.loads(result.stdout)
    except json.JSONDecodeError:
        return False
    return (obj.get("kind") == "Deployment"
            and obj.get("metadata", {}).get("name") == workload["metadata"]["name"]
            and obj.get("metadata", {}).get("namespace") == NS)


def _expired_denial(result):
    return (result.returncode != 0 and POLICY in result.stderr and DENIAL in result.stderr
            and "admission webhook" in result.stderr)


def _consumer_ready(lab):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        result = _admin(lab, "get", "validatingpolicies.policies.kyverno.io", POLICY, "-o", "json",
                        allow_failure=True)
        if result.returncode == 0:
            status = json.loads(result.stdout).get("status", {}).get("conditionStatus", {})
            if status.get("ready") is True:
                return
        time.sleep(0.5)
    lab.block("Kyverno runtime exception policy did not become Ready")


def _grant(lab, name, group, resource, verb, account, namespace, resource_name=None):
    rule = {"apiGroups": [group], "resources": [resource], "verbs": [verb]}
    if resource_name is not None:
        rule["resourceNames"] = [resource_name]
    lab.create({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": name}, "rules": [rule],
    })
    lab.kubectl("create", "rolebinding", name, f"--role={name}",
                f"--serviceaccount={namespace}:{account}")


def _install_access(lab):
    result = _admin(lab, "get", "deployment", "kyverno-admission-controller",
                    "--namespace", KYVERNO_NS, "-o", "json")
    pod = json.loads(result.stdout)["spec"]["template"]["spec"]
    images = [container["image"] for container in pod["containers"]]
    pinned = bool(images) and all(image.rsplit(":", 1)[-1] == "v1.20.0" for image in images)
    lab.check("positive", "The running policy consumer uses the reviewed Kyverno release",
              pinned, {"images": images, "expected_tag": "v1.20.0"})
    _grant(lab, "fixture-consumer-read", "saf-lab.example", "policyexceptions", "get",
           pod["serviceAccountName"], KYVERNO_NS, "exact-approved")


def _named_webhook_refusal(result):
    return result.returncode != 0 and "admission webhook" in result.stderr and POLICY in result.stderr


def run(lab, approver, exact):
    # The record fixture and scoped credential are the ones already exercised by the
    # base admission test. The base used dry-run for records and an inert placeholder.
    lab.kubectl("delete", "deployment", exact["spec"]["scope"]["name"], "--wait=true")
    _grant(lab, "fixture-approved-workload-create", "apps", "deployments", "create", APPROVER, NS)
    _install_kyverno(lab)
    _install_access(lab)
    workload = _workload()
    unguarded = _admitted(_dry_run(lab, approver, workload), workload)
    lab.check("red", "Before the consumer policy the harmless request is admitted without the exception",
              unguarded, {"unprotected_request_admitted": unguarded})

    lab.apply(HERE / "expiry-consumer-policy.yaml")
    _consumer_ready(lab)
    missing_result = _dry_run(lab, approver, workload)
    missing_refused = (_named_webhook_refusal(missing_result)
                       and "SAF-LAB-1006-010: scoped fixture exception is missing" in missing_result.stderr)
    lab.check("green", "The active consumer refuses the request when its scoped record is absent",
              missing_refused, {"consumer_reports_missing_record": missing_refused})

    start_stamp, start_time = _server_time(lab, "expiry-start")
    expiry = start_time + timedelta(seconds=EXPIRY_SECONDS)
    expiry_stamp = expiry.isoformat(timespec="seconds").replace("+00:00", "Z")
    cutoff_patch = json.dumps({"data": {"cutoff": start_stamp}})
    lab.kubectl("patch", "configmap", "fixture-exception-clock", "--type=merge", "-p", cutoff_patch)
    exception = json.loads(json.dumps(exact))
    exception["spec"]["expiresAt"] = expiry_stamp
    created = _fixture_client(lab, approver, "create", "-f", "-", "-o", "json", payload=exception)
    created_record = json.loads(created.stdout)
    record_ok = (created_record.get("metadata", {}).get("name") == "exact-approved"
                 and created_record.get("spec") == exception["spec"])
    lab.check("positive", "The published admission policy accepts the exact attributed record",
              record_ok, {"approved_record_admitted": record_ok, "expiry_seconds": EXPIRY_SECONDS})

    before_stamp, before_time = _server_time(lab, "decision-before")
    before_result = _dry_run(lab, approver, workload)
    before_end_stamp, before_end = _server_time(lab, "decision-before-end")
    before_matched = before_time < expiry and before_end < expiry and _admitted(before_result, workload)
    lab.check("positive", "The active consumer admits the exact request within the approved time window",
              before_matched, {"request_admitted_before_expiry": before_matched})

    after_stamp, after_time = _wait_until_server_time(lab, expiry)
    after_result = _dry_run(lab, approver, workload)
    after_end_stamp, after_end = _server_time(lab, "decision-after-end")
    after_matched = expiry < after_time <= after_end and _expired_denial(after_result)
    recorded = lab.kubectl("get", "policyexceptions.saf-lab.example", "exact-approved", "-o", "json")
    final_record = json.loads(recorded.stdout)
    unchanged = all(final_record["metadata"][field] == created_record["metadata"][field]
                    for field in ("uid", "resourceVersion"))
    lab.check("green", "The consumer refuses the identical request after the unchanged exception expires",
              after_matched and unchanged, {"consumer_expired_denial": after_matched, "record_unchanged": unchanged})
    (lab.evidence / "runtime-expiry-observations.json").write_text(json.dumps({
        "clock_anchor": "API-server assigned ConfigMap creation timestamps",
        "utc_start": start_stamp,
        "utc_expiry": expiry_stamp,
        "utc_allow_bracket": [before_stamp, before_end_stamp],
        "utc_deny_bracket": [after_stamp, after_end_stamp],
        "record_unchanged": unchanged,
        "missing_record_native_denial": missing_result.stderr.strip(),
        "expired_record_native_denial": after_result.stderr.strip(),
    }, indent=2) + "\n")

    # Run after the published expiry check so its unchanged-record assertion stays
    # attached to the original record. The lifecycle reuses the same CRD, workload,
    # and running Kyverno consumer, then makes a distinct close decision.
    lifecycle = runpy.run_path(str(HERE / "lifecycle.py"))
    lifecycle["run"](lab, approver, exact, workload)
