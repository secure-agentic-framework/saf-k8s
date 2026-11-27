"""Collect native, scoped Kubernetes evidence and demonstrate its freshness states."""
from datetime import datetime, timezone
import json
import hashlib
from pathlib import Path
import runpy
import time

HERE = Path(__file__).resolve().parent
NAMESPACE_PREFIX = "saf-1006-004"
NAME = "saf-1006-004-capture"
IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
         "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
COLLECTOR = HERE / "collector.py"
PSA_PREFIX = "pod-security.kubernetes.io/"

SCOPE = (
    "One disposable Kind Kubernetes v1.36.1 cluster and two isolated synthetic namespaces. "
    "A digest-pinned, non-root Python Job uses a dedicated ServiceAccount with read-only "
    "API permissions to GET its Namespace and LIST RoleBindings and NetworkPolicies in "
    "that namespace. It emits raw, nonsecret selected source objects with resourceVersion, "
    "UID, timestamp and collector provenance. The case distinguishes missing, fresh, stale, "
    "and refreshed evidence and checks that the identity cannot GET the other namespace. "
    "This does not establish production or cluster-wide evidence coverage, network dataplane "
    "enforcement, framework mapping accuracy, GRC integration, dashboard alerting, audit "
    "readiness, or regulatory conformity."
)


def create(lab, resource):
    ns = resource["metadata"].get("namespace")
    args = (f"--namespace={ns}",) if ns else ()
    return lab.kubectl(*args, "create", "-f", "-", payload=json.dumps(resource))


def get_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def metadata(name, namespace=None, labels=None):
    result = {"name": name}
    if namespace:
        result["namespace"] = namespace
    if labels:
        result["labels"] = labels
    return result


def labels_for(profile):
    return {key: value for key, value in profile["labels"].items()}


def fixture_objects(profile):
    namespace = profile["name"]
    fixture_labels = {"saf.example/control-id": "SAF-K8S-1006-004",
                      "saf.example/fixture": profile["labels"]["saf.example/fixture"]}
    return [
        {"apiVersion": "v1", "kind": "ServiceAccount",
         "metadata": metadata("mock-workload", namespace, fixture_labels),
         "automountServiceAccountToken": False},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
         "metadata": metadata(profile["binding"]["roleRef"]["name"], namespace, fixture_labels),
         "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["synthetic-marker"], "verbs": ["get"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
         "metadata": metadata(profile["binding"]["name"], namespace, fixture_labels),
         "subjects": profile["binding"]["subjects"], "roleRef": profile["binding"]["roleRef"]},
        {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
         "metadata": metadata(profile["network_policy"]["name"], namespace, fixture_labels),
         "spec": profile["network_policy"]["spec"]},
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": metadata("synthetic-marker", namespace, fixture_labels),
         "data": {"classification": "synthetic", "evidence_ref": "saf-lab://SAF-K8S-1006-004/mock"}},
    ]


def collector_rbac(profile):
    ns = profile["name"]
    sa = "capture-reader"
    labels = {"saf.example/control-id": "SAF-K8S-1006-004", "saf.example/component": "collector"}
    return [
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": metadata(sa, ns, labels)},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
         "metadata": metadata("capture-reader", ns, labels),
         "rules": [{"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["rolebindings"], "verbs": ["get", "list"]},
                   {"apiGroups": ["networking.k8s.io"], "resources": ["networkpolicies"], "verbs": ["get", "list"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
         "metadata": metadata("capture-reader", ns, labels),
         "subjects": [{"kind": "ServiceAccount", "name": sa, "namespace": ns}],
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "capture-reader"}},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
         "metadata": metadata("capture-namespace-reader-" + ns, labels=labels),
         "rules": [{"apiGroups": [""], "resources": ["namespaces"], "resourceNames": [ns], "verbs": ["get"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
         "metadata": metadata("capture-namespace-reader-" + ns, labels=labels),
         "subjects": [{"kind": "ServiceAccount", "name": sa, "namespace": ns}],
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                     "name": "capture-namespace-reader-" + ns}},
    ]


def pod(profile, other_namespace, name):
    ns = profile["name"]
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": metadata(name, ns, {"saf.example/control-id": "SAF-K8S-1006-004"}),
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 60, "ttlSecondsAfterFinished": 300,
                 "template": {"metadata": {"labels": {"app": "saf-1006-004-capture"}}, "spec": {
                     "restartPolicy": "Never", "serviceAccountName": "capture-reader",
                     "automountServiceAccountToken": True,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "collector", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                                     "command": ["python", "/case/collector.py"],
                                     "env": [{"name": "FIXTURE_NAMESPACE", "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}}},
                                             {"name": "FIXTURE_POD", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}},
                                             {"name": "FIXTURE_POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}},
                                             {"name": "OTHER_NAMESPACE", "value": other_namespace}],
                                     "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                                   "limits": {"cpu": "100m", "memory": "64Mi"}},
                                     "securityContext": {"allowPrivilegeEscalation": False,
                                                         "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}},
                                     "volumeMounts": [{"name": "collector-code", "mountPath": "/case", "readOnly": True}]}],
                     "volumes": [{"name": "collector-code", "configMap": {"name": NAME, "defaultMode": 292}}],
                 }}},
    }


def run_collector(lab, profile, other_namespace, label):
    ns = profile["name"]
    job_name = f"{NAME}-{label}"
    create(lab, pod(profile, other_namespace, job_name))
    lab.kubectl("-n", ns, "wait", "--for=condition=Complete", f"job/{job_name}", "--timeout=70s", timeout=80)
    jobs = get_json(lab, "-n", ns, "get", "pods", "-l", f"batch.kubernetes.io/job-name={job_name}")["items"]
    if len(jobs) != 1:
        lab.block(f"Expected one collector Pod for {job_name}; saw {len(jobs)}")
    pod_name = jobs[0]["metadata"]["name"]
    raw = lab.kubectl("-n", ns, "logs", pod_name).stdout.strip()
    try:
        capture = json.loads(raw)
    except json.JSONDecodeError as error:
        lab.block(f"Collector did not emit one JSON capture: {error}")
    return capture, raw, {"job": job_name, "pod": pod_name,
                          "pod_uid": jobs[0]["metadata"].get("uid")}


def freshness(capture, now=None, max_age=8):
    if capture is None:
        return "missing", None
    timestamp = datetime.fromisoformat(capture["provenance"]["captured_at"].replace("Z", "+00:00"))
    age = ((now or datetime.now(timezone.utc)) - timestamp).total_seconds()
    return ("fresh" if 0 <= age <= max_age else "stale"), age


def valid_content_digest(capture):
    body = json.loads(json.dumps(capture))
    expected = body["provenance"].pop("content_sha256", None)
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return expected == hashlib.sha256(canonical).hexdigest()


def read_only_permissions(lab, namespace):
    identity = f"system:serviceaccount:{namespace}:capture-reader"
    queries = {
        "get_namespace": ("get", f"namespaces/{namespace}"),
        "list_rolebindings": ("list", "rolebindings", "-n", namespace),
        "list_networkpolicies": ("list", "networkpolicies", "-n", namespace),
        "create_rolebinding": ("create", "rolebindings", "-n", namespace),
        "patch_namespace": ("patch", f"namespaces/{namespace}"),
        "read_secret": ("get", "secrets", "-n", namespace),
    }
    observed = {}
    for key, args in queries.items():
        result = lab.kubectl("auth", "can-i", *args, "--as", identity, allow_failure=True)
        decision = result.stdout.strip()
        if (decision, result.returncode) not in {("yes", 0), ("no", 1)}:
            lab.block(f"Unexpected authorization review for {key}: {result.stderr.strip()}")
        observed[key] = decision
    expected = {"get_namespace": "yes", "list_rolebindings": "yes",
                "list_networkpolicies": "yes", "create_rolebinding": "no",
                "patch_namespace": "no", "read_secret": "no"}
    return observed, observed == expected


def verified_source(lab, capture, profile, observed_run):
    ns = profile["name"]
    provenance = capture["provenance"]
    if provenance["collector_pod_uid"] != observed_run["pod_uid"] or provenance["collector_pod"] != observed_run["pod"]:
        return False
    sources = [
        (get_json(lab, "get", "namespace", ns)["metadata"],
         provenance["namespace_uid"], provenance["namespace_resource_version"]),
    ]
    for key, kind in (("network_policies", "networkpolicy"), ("role_bindings", "rolebinding")):
        for row in capture[key]:
            item = row["metadata"]
            actual = get_json(lab, "-n", ns, "get", kind, item["name"])["metadata"]
            sources.append((actual, item["uid"], item["resourceVersion"]))
    return all((actual["uid"], actual["resourceVersion"]) == (uid, rv)
               for actual, uid, rv in sources)


def expected_capture(capture, profile):
    labels = capture["namespace_pod_security_and_case_labels"]
    expected_labels = {k: v for k, v in profile["labels"].items()
                       if k.startswith(PSA_PREFIX) or k.startswith("saf.example/")}
    bindings = capture["role_bindings"]
    policies = capture["network_policies"]
    return (
        labels == expected_labels
        and len(bindings) == 1
        and bindings[0]["metadata"]["name"] == profile["binding"]["name"]
        and bindings[0]["subjects"] == profile["binding"]["subjects"]
        and bindings[0]["roleRef"] == profile["binding"]["roleRef"]
        and len(policies) == 1
        and policies[0]["metadata"]["name"] == profile["network_policy"]["name"]
        and policies[0]["spec"] == profile["network_policy"]["spec"]
        and capture["provenance"]["cross_namespace_namespace_get"] == {"status": 403, "reason": "Forbidden"}
        and capture["provenance"]["namespace_uid"]
        and all(row["metadata"].get("uid") and row["metadata"].get("resourceVersion")
                for row in bindings + policies)
        and valid_content_digest(capture)
    )


def run(lab):
    fixture = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
    profiles = fixture["namespaces"]
    server = json.loads(lab.kubectl("get", "--raw=/version").stdout).get("gitVersion")
    lab.check("positive", "The disposable API server is Kubernetes v1.36.1",
              server == "v1.36.1", {"gitVersion": server})
    lab.check("positive", "Fixture freshness policy is explicit and bounded",
              fixture["freshness_limit_seconds"] == 8,
              {"freshness_limit_seconds": fixture["freshness_limit_seconds"]})
    for profile in profiles.values():
        ns = profile["name"]
        lab.kubectl("create", "namespace", ns)
        lab.kubectl("label", "namespace", ns,
                    *(f"{key}={value}" for key, value in labels_for(profile).items()))
        for resource in fixture_objects(profile):
            create(lab, resource)
        for resource in collector_rbac(profile):
            create(lab, resource)
        create(lab, {"apiVersion": "v1", "kind": "ConfigMap", "metadata": metadata(NAME, ns),
                     "immutable": True, "data": {"collector.py": COLLECTOR.read_text(encoding="utf-8")}})

    state, _ = freshness(None, max_age=fixture["freshness_limit_seconds"])
    lab.check("red", "The evidence ledger reports missing before any collector has run",
              state == "missing", {"capture_state": state, "capture_present": False})

    primary = profiles["primary"]
    observed_permissions, read_only = read_only_permissions(lab, primary["name"])
    lab.check("positive", "The collector identity has the intended read scope and no tested write or Secret access",
              read_only, {"identity": f"system:serviceaccount:{primary['name']}:capture-reader",
                          "can_i": observed_permissions})
    primary_capture, primary_raw, primary_run = run_collector(
        lab, primary, profiles["positive"]["name"], "primary")
    state, age = freshness(primary_capture, max_age=fixture["freshness_limit_seconds"])
    primary_ok = expected_capture(primary_capture, primary)
    primary_provenance = verified_source(lab, primary_capture, primary, primary_run)
    lab.check("green", "Read-only API collection returns exact primary namespace evidence with provenance",
              state == "fresh" and primary_ok and primary_provenance,
              {"capture_state": state, "source_matches_fixture": primary_ok,
               "provenance_matches_live_objects": primary_provenance})

    raw_evidence = [{"namespace": primary["name"], "raw_json": primary_raw,
                     "collector_execution": primary_run, "assessment": {"state": state, "age_seconds": age}}]
    time.sleep(fixture["freshness_limit_seconds"] + 1)
    stale_state, stale_age = freshness(primary_capture, max_age=fixture["freshness_limit_seconds"])
    lab.check("red", "The unchanged captured API response is detected as stale after the fixture freshness window",
              stale_state == "stale" and stale_age > fixture["freshness_limit_seconds"],
              {"capture_state": stale_state,
               "max_age_seconds": fixture["freshness_limit_seconds"], "source_capture_unchanged": True})

    refreshed_capture, refreshed_raw, refreshed_run = run_collector(
        lab, primary, profiles["positive"]["name"], "primary-refresh")
    refreshed_state, refreshed_age = freshness(refreshed_capture, max_age=fixture["freshness_limit_seconds"])
    refreshed_ok = (expected_capture(refreshed_capture, primary)
                    and verified_source(lab, refreshed_capture, primary, refreshed_run))
    refreshed_after_stale = (refreshed_capture["provenance"]["captured_at"]
                             > primary_capture["provenance"]["captured_at"])
    lab.check("green", "A new API collection restores fresh evidence for the previously stale namespace",
              refreshed_state == "fresh" and refreshed_ok and refreshed_after_stale
              and refreshed_capture["provenance"]["namespace_uid"] == primary_capture["provenance"]["namespace_uid"],
              {"capture_state": refreshed_state,
               "source_matches_fixture": refreshed_ok, "captured_after_stale_observation": refreshed_after_stale,
               "same_namespace_uid": refreshed_capture["provenance"]["namespace_uid"] == primary_capture["provenance"]["namespace_uid"]})
    raw_evidence.append({"namespace": primary["name"], "raw_json": refreshed_raw,
                         "collector_execution": refreshed_run,
                         "assessment": {"state": refreshed_state, "age_seconds": refreshed_age}})

    positive = profiles["positive"]
    positive_capture, positive_raw, positive_run = run_collector(
        lab, positive, primary["name"], "positive")
    positive_state, positive_age = freshness(positive_capture, max_age=fixture["freshness_limit_seconds"])
    positive_ok = (expected_capture(positive_capture, positive)
                   and verified_source(lab, positive_capture, positive, positive_run))
    lab.check("positive", "An independent namespace produces a fresh, distinct, complete capture",
              positive_state == "fresh" and positive_ok
              and positive_capture["provenance"]["namespace_uid"] != primary_capture["provenance"]["namespace_uid"],
              {"capture_state": positive_state,
               "source_matches_fixture": positive_ok,
               "different_namespace_uid": positive_capture["provenance"]["namespace_uid"] != primary_capture["provenance"]["namespace_uid"]})
    raw_evidence.append({"namespace": positive["name"], "raw_json": positive_raw,
                         "collector_execution": positive_run,
                         "assessment": {"state": positive_state, "age_seconds": positive_age}})
    (lab.evidence / "raw-captures.json").write_text(
        json.dumps(raw_evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # Synthetic crosswalk import/report oracle only; it asserts no real framework coverage.
    runpy.run_path(str(HERE / "crosswalk_oracle.py"))["run"](lab)
    runpy.run_path(str(HERE / "crosswalk_oracle.py"))["run_canonical"](lab)
