"""Passively assess synthetic Kubernetes posture, drift, and owned-policy recovery."""
import hashlib
import json
import os
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
OWNED_NAMESPACE = "saf-1007-004-owned"
NEIGHBOR_NAMESPACE = "saf-1007-004-neighbor"
NETWORK_POLICY = "owned-default-deny"
ROLE = "posture-reader"
DEPLOYMENT = "mock-inference"
CONFIG_MAP = "posture-fixture"
SCOPE = (
    "Disposable Kind v1.36.1 cluster. Creates an owned namespace, one digest-pinned synthetic mock workload, "
    "a default-deny NetworkPolicy, and a named-object read-only Role. Captures API-visible posture, detects "
    "controlled changes to Pod Security Admission labels, NetworkPolicy rules and Role verbs, reapplies the "
    "desired manifests, and verifies recovery from live API reads. Joins an offline fictional advisory fixture "
    "to a synthetic component observation. Pinned offline OSV-Scanner reads the inert package metadata in a "
    "case-built runnable image, and the posture result binds to the exact image observed in Kind. "
    "Benchmark coverage, actual advisory feeds, managed and accelerator settings, and deployed "
    "monitoring and alerting have separate evidence requirements. A scoped authenticated Role stream "
    "compares fixture metadata updates, rule widening and restoration with exact API event revisions. "
    "A separately authorized NetworkPolicy watcher matches metadata, ingress widening and restoration "
    "to the selected object's UID and API resource versions. The NetworkPolicy comparison uses API "
    "observations only; CNI enforcement and ongoing monitoring require separate evidence. The watcher "
    "also emits fixture-scoped Warning Events for drift transitions, bound to policy revisions and "
    "observer Pod identity; this does not establish durable or external alert delivery. A separate "
    "disposable Kind profile tests stale NetworkPolicy resourceVersion recovery with a one-resource "
    "cache bypass and bounded compaction cadence; the original profile retains its defaults."
)


def read_fixture():
    return json.loads((HERE / "fixtures.json").read_text())


def owned_resources(fixture):
    profile = fixture["profile"]
    namespace = {
        "apiVersion": "v1", "kind": "Namespace",
        "metadata": {"name": OWNED_NAMESPACE, "labels": {
            **profile["pod_security"],
            "saf-k8s.example/control-1007-004": "synthetic-owned",
        }},
    }
    config = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": CONFIG_MAP, "namespace": OWNED_NAMESPACE,
                     "labels": {"saf-k8s.example/control-1007-004": "synthetic-owned"}},
        "data": {"fixture_notice": fixture["fixture_notice"]},
    }
    network_policy = {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": NETWORK_POLICY, "namespace": OWNED_NAMESPACE,
                     "labels": {"saf-k8s.example/control-1007-004": "synthetic-owned"}},
        "spec": profile["network_policy"],
    }
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": ROLE, "namespace": OWNED_NAMESPACE,
                     "labels": {"saf-k8s.example/control-1007-004": "synthetic-owned"}},
        "rules": profile["role_rules"],
    }
    workload = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": DEPLOYMENT, "namespace": OWNED_NAMESPACE,
                     "labels": {"saf-k8s.example/control-1007-004": "synthetic-owned"}},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": DEPLOYMENT}},
            "template": {
                "metadata": {"labels": {"app": DEPLOYMENT}},
                "spec": {
                    "automountServiceAccountToken": profile["workload"]["automountServiceAccountToken"],
                    "securityContext": {
                        "runAsNonRoot": profile["workload"]["runAsNonRoot"],
                        "runAsUser": 10001,
                        "seccompProfile": {"type": profile["workload"]["seccompProfile"]},
                    },
                    "containers": [{
                        "name": "mock-inference", "image": profile["workload"]["image"],
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "-c", "import time; time.sleep(3600)"],
                        "securityContext": {
                            "allowPrivilegeEscalation": profile["workload"]["allowPrivilegeEscalation"],
                            "readOnlyRootFilesystem": profile["workload"]["readOnlyRootFilesystem"],
                            "capabilities": {"drop": profile["workload"]["dropCapabilities"]},
                        },
                        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                      "limits": {"cpu": "100m", "memory": "64Mi"}},
                    }],
                },
            },
        },
    }
    return {"namespace": namespace, "configmap": config, "networkpolicy": network_policy,
            "role": role, "deployment": workload}


def apply_resource(lab, resource):
    namespace = resource["metadata"].get("namespace")
    selector = ("-n", namespace) if namespace else ()
    lab.kubectl(*selector, "apply", "-f", "-", payload=json.dumps(resource))


def get_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def live_owned(lab):
    return {
        "namespace": get_json(lab, "get", "namespace", OWNED_NAMESPACE),
        "networkpolicy": get_json(lab, "-n", OWNED_NAMESPACE, "get", "networkpolicy", NETWORK_POLICY),
        "role": get_json(lab, "-n", OWNED_NAMESPACE, "get", "role", ROLE),
        "deployment": get_json(lab, "-n", OWNED_NAMESPACE, "get", "deployment", DEPLOYMENT),
    }


def posture_view(objects, fixture):
    labels = objects["namespace"]["metadata"].get("labels", {})
    pod = objects["deployment"]["spec"]["template"]["spec"]
    container = pod["containers"][0]
    return {
        "pod_security_labels": {key: labels.get(key) for key in fixture["profile"]["pod_security"]},
        "network_policy_spec": objects["networkpolicy"].get("spec", {}),
        "role_rules": objects["role"].get("rules", []),
        "workload_security": {
            "automountServiceAccountToken": pod.get("automountServiceAccountToken"),
            "runAsNonRoot": pod.get("securityContext", {}).get("runAsNonRoot"),
            "runAsUser": pod.get("securityContext", {}).get("runAsUser"),
            "seccompProfile": pod.get("securityContext", {}).get("seccompProfile", {}).get("type"),
            "container": {
                "image": container.get("image"),
                "imagePullPolicy": container.get("imagePullPolicy"),
                "allowPrivilegeEscalation": container.get("securityContext", {}).get(
                    "allowPrivilegeEscalation"),
                "readOnlyRootFilesystem": container.get("securityContext", {}).get(
                    "readOnlyRootFilesystem"),
                "dropCapabilities": container.get("securityContext", {}).get(
                    "capabilities", {}).get("drop", []),
            },
        },
    }


def desired_view(objects, fixture):
    return {
        "pod_security_labels": fixture["profile"]["pod_security"],
        "network_policy_spec": objects["networkpolicy"]["spec"],
        "role_rules": objects["role"]["rules"],
        "workload_security": {
            "automountServiceAccountToken": fixture["profile"]["workload"]["automountServiceAccountToken"],
            "runAsNonRoot": fixture["profile"]["workload"]["runAsNonRoot"],
            "runAsUser": 10001,
            "seccompProfile": fixture["profile"]["workload"]["seccompProfile"],
            "container": {
                "image": fixture["profile"]["workload"]["image"],
                "imagePullPolicy": "IfNotPresent",
                "allowPrivilegeEscalation": fixture["profile"]["workload"]["allowPrivilegeEscalation"],
                "readOnlyRootFilesystem": fixture["profile"]["workload"]["readOnlyRootFilesystem"],
                "dropCapabilities": fixture["profile"]["workload"]["dropCapabilities"],
            },
        },
    }


def save_raw(lab, name, value):
    (lab.evidence / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def fingerprint(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def assess_advisory_fixture(fixture):
    matches = []
    for asset in fixture["asset_observations"]:
        for component in asset["components"]:
            for advisory in fixture["offline_advisories"]:
                if (component["name"], component["version"]) == (advisory["component"], advisory["version"]):
                    matches.append({
                        "asset_id": asset["asset_id"], "image": asset["image"],
                        "component": component["name"], "version": component["version"],
                        "advisory_id": advisory["advisory_id"], "source_id": advisory["source_id"],
                        "severity": advisory["severity"], "fixture_type": advisory["record_type"],
                    })
    return matches


def run(lab):
    fixture = read_fixture()
    resources = owned_resources(fixture)
    for key in ("namespace", "configmap", "networkpolicy", "role", "deployment"):
        apply_resource(lab, resources[key])
    lab.kubectl("-n", OWNED_NAMESPACE, "rollout", "status", f"deployment/{DEPLOYMENT}",
                "--timeout=150s", timeout=160)

    baseline = live_owned(lab)
    baseline_view = posture_view(baseline, fixture)
    save_raw(lab, "posture-baseline.raw.json", baseline)
    for asset in fixture["asset_observations"]:
        if (asset["namespace"] != baseline["deployment"]["metadata"]["namespace"]
                or asset["workload"] != baseline["deployment"]["metadata"]["name"]
                or asset["image"] != baseline_view["workload_security"]["container"]["image"]):
            lab.block("Offline advisory asset fixture was not bound to the live mock Deployment")
    initial_matches = assess_advisory_fixture(fixture)
    unmatched = sorted({advisory["advisory_id"] for advisory in fixture["offline_advisories"]}
                       - {match["advisory_id"] for match in initial_matches})
    save_raw(lab, "offline-advisory-assessment.raw.json", {
        "fixture_notice": fixture["fixture_notice"],
        "matches": initial_matches,
        "unmatched_advisory_ids": unmatched,
    })
    lab.check("green", "Owned resources begin at the declared restricted baseline",
              baseline_view == desired_view(resources, fixture),
              {"pod_security_labels_match": baseline_view["pod_security_labels"] == fixture["profile"]["pod_security"],
               "network_policy_match": baseline_view["network_policy_spec"] == fixture["profile"]["network_policy"],
               "role_rules_match": baseline_view["role_rules"] == fixture["profile"]["role_rules"],
               "workload_security_match": baseline_view["workload_security"] ==
               desired_view(resources, fixture)["workload_security"],
               "mock_image_digest_pinned": "@sha256:" in
               baseline_view["workload_security"]["container"]["image"]})

    lab.check("positive", "Offline fictional component metadata joins exactly and the version near miss stays unmatched",
              len(initial_matches) == 1
              and initial_matches[0]["advisory_id"] == "SYNTH-ADVISORY-1007-004-A"
              and initial_matches[0]["fixture_type"] == "fictional-benchmark-metadata",
              {"synthetic_exact_matches": [m["advisory_id"] for m in initial_matches],
               "near_miss_advisory_unmatched": "SYNTH-ADVISORY-1007-004-B" not in
               [m["advisory_id"] for m in initial_matches]})

    # Controlled API edits simulate drift on resources owned by this fixture.
    lab.kubectl("label", "namespace", OWNED_NAMESPACE,
                "pod-security.kubernetes.io/enforce=privileged", "--overwrite")
    lab.kubectl("-n", OWNED_NAMESPACE, "patch", "networkpolicy", NETWORK_POLICY,
                "--type=merge", "-p", json.dumps({"spec": {"ingress": [{}]}}))
    lab.kubectl("-n", OWNED_NAMESPACE, "patch", "role", ROLE,
                "--type=merge", "-p", json.dumps({"rules": [{
                    "apiGroups": [""], "resources": ["configmaps"],
                    "resourceNames": [CONFIG_MAP], "verbs": ["get", "list"]}]}))
    drifted = live_owned(lab)
    drifted_view = posture_view(drifted, fixture)
    detected = {
        "pod_security_enforce_changed": drifted_view["pod_security_labels"].get(
            "pod-security.kubernetes.io/enforce") != fixture["profile"]["pod_security"][
                "pod-security.kubernetes.io/enforce"],
        "network_policy_ingress_widened": drifted_view["network_policy_spec"].get("ingress") == [{}],
        "role_verb_widened": drifted_view["role_rules"] != fixture["profile"]["role_rules"],
    }
    save_raw(lab, "posture-drift.raw.json", {"resources": drifted, "detected_drift": detected})
    lab.check("red", "Posture assessment detects each controlled owned-resource regression",
              all(detected.values()), detected)

    # Clear the extra allow rule and reconcile the exact owned desired state.
    lab.kubectl("-n", OWNED_NAMESPACE, "patch", "networkpolicy", NETWORK_POLICY,
                "--type=merge", "-p", json.dumps({"spec": {"ingress": None}}))
    for key in ("namespace", "networkpolicy", "role", "deployment"):
        apply_resource(lab, resources[key])
    lab.kubectl("-n", OWNED_NAMESPACE, "rollout", "status", f"deployment/{DEPLOYMENT}",
                "--timeout=150s", timeout=160)
    recovered = live_owned(lab)
    recovered_view = posture_view(recovered, fixture)
    save_raw(lab, "posture-recovered.raw.json", recovered)
    lab.check("green", "Reapplying the owned desired state restores API-observed posture",
              recovered_view == desired_view(resources, fixture),
              {"pod_security_labels_restored": recovered_view["pod_security_labels"] == fixture["profile"]["pod_security"],
               "network_policy_restored": recovered_view["network_policy_spec"] == fixture["profile"]["network_policy"],
               "role_rules_restored": recovered_view["role_rules"] == fixture["profile"]["role_rules"],
               "workload_security_restored": recovered_view["workload_security"] ==
               desired_view(resources, fixture)["workload_security"]})

    # The separate case-owned comparator lies outside the assessment's selector.
    lab.kubectl("create", "namespace", NEIGHBOR_NAMESPACE)
    neighbor_policy = {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "neighbor-policy", "namespace": NEIGHBOR_NAMESPACE},
        "spec": {"podSelector": {}, "policyTypes": ["Ingress"]},
    }
    apply_resource(lab, neighbor_policy)
    before_neighbor_change = fingerprint(posture_view(live_owned(lab), fixture))
    lab.kubectl("-n", NEIGHBOR_NAMESPACE, "patch", "networkpolicy", "neighbor-policy",
                "--type=merge", "-p", json.dumps({"spec": {"ingress": [{}]}}))
    neighbor = get_json(lab, "-n", NEIGHBOR_NAMESPACE, "get", "networkpolicy", "neighbor-policy")
    after_neighbor_change = fingerprint(posture_view(live_owned(lab), fixture))
    save_raw(lab, "out-of-scope-neighbor.raw.json", {
        "neighbor_networkpolicy": neighbor,
        "owned_fingerprint_before": before_neighbor_change,
        "owned_fingerprint_after": after_neighbor_change,
    })
    lab.check("positive", "Changes outside the explicitly owned fixture scope do not alter its assessment",
              neighbor["spec"].get("ingress") == [{}]
              and before_neighbor_change == after_neighbor_change,
              {"out_of_scope_neighbor_changed": neighbor["spec"].get("ingress") == [{}],
               "owned_assessment_fingerprint_stable": before_neighbor_change == after_neighbor_change})

    cases_root = Path(os.environ.get("SAF_CONTROL_CASES_ROOT", HERE.parent)).resolve()
    runpy.run_path(str(HERE / "scanner_posture_addon.py"))["run"](lab, cases_root)
    runpy.run_path(str(HERE / "role_watch_addon.py"))["run"](
        lab, HERE, OWNED_NAMESPACE, ROLE, resources["role"]["rules"])
    runpy.run_path(str(HERE / "network_policy_watch_addon.py"))["run"](
        lab, HERE, OWNED_NAMESPACE, NETWORK_POLICY, resources["networkpolicy"]["spec"],
        NEIGHBOR_NAMESPACE)
    runpy.run_path(str(HERE / "expired_watch_profile.py"))["run"](lab, HERE)
