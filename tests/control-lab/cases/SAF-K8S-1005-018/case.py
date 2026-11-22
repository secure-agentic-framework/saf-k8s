"""Gate promotion of an inert recovery fixture on release and readiness evidence."""
import copy
import hashlib
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
FIXTURE_DIR = HERE / "fixtures"
NAMESPACE = "saf-test"
CONTROL_ID = "SAF-K8S-1005-018"
LABEL_KEY = "saf-k8s.example/control"
LABEL_VALUE = "1005-018"
FIXTURE_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
RELEASE_RECORD_SHA256 = "76a996fc8d16212f12b4ab3b77657bb92986a4403849a3d21b4404bfc79561f0"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
SCOPE = (
    "One disposable Kind v1.36.1 cluster and a namespace-isolated mock recovery. The case checks a "
    "synthetic release identity, exact two-Deployment component inventory, SHA-256 identity of one "
    "inert case-owned marker, pinned image references, and post-promotion Deployment/Pod readiness "
    "read back from the Kubernetes API. Independent comparators cover matching digest, mismatching "
    "digest, and missing evidence. This does not verify a real signature, registry trust, production "
    "release approval, compromised assets, node OS or GPU driver integrity, AI model safety, "
    "production readiness, or organization-wide recovery coverage."
)

RELEASE_ID = "SYNTH-RELEASE-1005-018-01"
COMPONENTS = {
    "mock-inference": "saf-1005-018-inference",
    "mock-policy": "saf-1005-018-policy",
}


def load_fixtures():
    release_bytes = (FIXTURE_DIR / "release.json").read_bytes()
    release_sha256 = hashlib.sha256(release_bytes).hexdigest()
    if release_sha256 != RELEASE_RECORD_SHA256:
        raise ValueError("synthetic release record differs from the case-pinned identity")
    record = json.loads(release_bytes.decode("utf-8"))
    marker = (FIXTURE_DIR / "component-marker.txt").read_bytes()
    program = (FIXTURE_DIR / "mock_component.py").read_text(encoding="utf-8")
    digest = hashlib.sha256(marker).hexdigest()
    if digest != record["artifact"]["sha256"]:
        raise ValueError("case-owned inert marker does not match the recorded fixture digest")
    if record.get("release_id") != RELEASE_ID:
        raise ValueError("synthetic release identity does not match the case allowlist")
    for item in record.get("components", []):
        if item.get("image") != FIXTURE_IMAGE:
            raise ValueError("synthetic component does not use the pinned mock image")
    return record, marker.decode("utf-8"), program, digest, release_sha256


def prepare_kind(_lab, temporary):
    """Select one control-plane node while the runner pins NODE_IMAGE."""
    config = temporary / "kind.yaml"
    config.write_text(
        "kind: Cluster\n"
        "apiVersion: kind.x-k8s.io/v1alpha4\n"
        "nodes:\n"
        "- role: control-plane\n",
        encoding="utf-8",
    )
    return config


def _expected_inventory(record):
    return {item["id"]: item for item in record.get("components", [])}


def _gate(record, evidence, marker_sha256, *, enabled=True):
    """Evaluate synthetic pre-promotion evidence; no real identity is represented."""
    expected = _expected_inventory(record)
    observed = {row.get("component_id"): row for row in evidence or []
                if isinstance(row, dict) and row.get("component_id")}
    inventory_exact = (set(expected) == set(COMPONENTS)
                       and all(expected[item].get("deployment") == COMPONENTS.get(item)
                               for item in expected)
                       and len(observed) == len(evidence or [])
                       and set(observed) == set(expected))
    release_exact = (record.get("fixture_only") is True
                     and record.get("control_id") == CONTROL_ID
                     and record.get("release_id") == RELEASE_ID
                     and record.get("release_identity", {}).get("status") == "verified"
                     and record.get("release_identity", {}).get("reference")
                     == "urn:example:saf:release:1005-018-01")
    comparisons = {}
    for component_id, component in expected.items():
        row = observed.get(component_id)
        comparisons[component_id] = {
            "evidence_present": row is not None,
            "image_matches": bool(row and row.get("image") == component.get("image") == FIXTURE_IMAGE),
            "digest_matches": bool(row and row.get("sha256") == marker_sha256
                                    == record.get("artifact", {}).get("sha256")),
            "status_verified": bool(row and row.get("status") == "verified"),
        }
    integrity_ok = all(all(checks.values()) for checks in comparisons.values())
    accepted = (not enabled) or (release_exact and inventory_exact and integrity_ok)
    return {
        "accepted": accepted,
        "gate_enabled": enabled,
        "release_identity_exact": release_exact,
        "inventory_exact": inventory_exact,
        "integrity_ok": integrity_ok,
        "components": comparisons,
    }


def _evidence(record, marker_sha256):
    return [{"component_id": item["id"], "image": item["image"],
             "sha256": marker_sha256, "status": "verified"}
            for item in record["components"]]


def _deployment(component, marker, program):
    name = component["deployment"]
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": {LABEL_KEY: LABEL_VALUE, "saf-k8s.example/component": component["id"]}},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"saf-k8s.example/component": component["id"]}},
            "template": {
                "metadata": {"labels": {LABEL_KEY: LABEL_VALUE,
                                         "saf-k8s.example/component": component["id"]}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "volumes": [{"name": "fixture", "configMap": {"name": "saf-1005-018-fixture",
                                                                       "items": [
                                                                           {"key": "component-marker.txt",
                                                                            "path": "component-marker.txt"},
                                                                           {"key": "mock_component.py",
                                                                            "path": "mock_component.py"},
                                                                       ]}}],
                    "containers": [{
                        "name": "mock", "image": component["image"],
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "-B", "/fixture/mock_component.py"],
                        "env": [{"name": "COMPONENT_ID", "value": component["id"]},
                                {"name": "RELEASE_ID", "value": RELEASE_ID}],
                        "ports": [{"name": "ready", "containerPort": 8080}],
                        "readinessProbe": {"httpGet": {"path": "/ready", "port": "ready"},
                                           "periodSeconds": 2, "failureThreshold": 15},
                        "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                                      "limits": {"cpu": "100m", "memory": "64Mi"}},
                        "securityContext": {"allowPrivilegeEscalation": False,
                                            "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]}},
                        "volumeMounts": [{"name": "fixture", "mountPath": "/fixture",
                                          "readOnly": True}],
                    }],
                },
            },
        },
    }


def _wait_ready(lab, component, marker_sha256):
    name = component["deployment"]
    deadline = time.monotonic() + 100
    deployment = None
    while time.monotonic() < deadline:
        deployment = json.loads(lab.kubectl("-n", NAMESPACE, "get", "deployment", name,
                                            "-o", "json", timeout=20).stdout)
        status = deployment.get("status", {})
        if (status.get("observedGeneration") == deployment["metadata"].get("generation")
                and status.get("availableReplicas") == 1
                and status.get("readyReplicas") == 1):
            break
        time.sleep(1)
    else:
        lab.block(f"Mock component {component['id']} did not become Available and Ready")

    pods = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pods", "-l",
                                  f"saf-k8s.example/component={component['id']}",
                                  "-o", "json").stdout)["items"]
    ready_pods = [pod for pod in pods if any(condition.get("type") == "Ready"
                                             and condition.get("status") == "True"
                                             for condition in pod.get("status", {}).get("conditions", []))]
    if len(pods) != 1 or len(ready_pods) != 1:
        lab.block(f"Mock component {component['id']} has no unique Ready Pod")
    pod = ready_pods[0]
    statuses = pod.get("status", {}).get("containerStatuses", [])
    spec_images = [container.get("image") for container in pod.get("spec", {}).get("containers", [])]
    if (spec_images != [component["image"]] or len(statuses) != 1
            or statuses[0].get("ready") is not True):
        lab.block(f"Mock component {component['id']} observed image or container readiness differs")
    startup = lab.kubectl("-n", NAMESPACE, "logs", f"pod/{pod['metadata']['name']}",
                          "-c", "mock").stdout.strip()
    try:
        startup_observation = json.loads(startup.splitlines()[0])
    except (IndexError, json.JSONDecodeError):
        lab.block(f"Mock component {component['id']} did not report its mounted marker identity")
    if (startup_observation.get("component_id") != component["id"]
            or startup_observation.get("release_id") != RELEASE_ID
            or startup_observation.get("marker_sha256") != marker_sha256):
        lab.block(f"Mock component {component['id']} startup identity differs from approved fixture")
    return {
        "component_id": component["id"], "deployment": name,
        "deployment_uid": deployment["metadata"].get("uid"),
        "observed_generation": deployment["status"].get("observedGeneration"),
        "generation": deployment["metadata"].get("generation"),
        "available_replicas": deployment["status"].get("availableReplicas"),
        "ready_replicas": deployment["status"].get("readyReplicas"),
        "pod_uid": pod["metadata"].get("uid"),
        "pod_ready": True, "container_ready": statuses[0].get("ready"),
        "spec_images": spec_images,
        "status_image": statuses[0].get("image"),
        "image_id": statuses[0].get("imageID"),
        "startup_observation": startup_observation,
    }


def _deployments(lab):
    return json.loads(lab.kubectl(
        "get", "deployments", "-l", f"{LABEL_KEY}={LABEL_VALUE}", "-o", "json",
    ).stdout)["items"]


def _promote(lab, record, evidence, marker, program, marker_sha256, *, enabled=True):
    decision = _gate(record, evidence, marker_sha256, enabled=enabled)
    if decision["accepted"]:
        for component in record["components"]:
            lab.create(_deployment(component, marker, program))
    return decision


def run(lab):
    record, marker, program, marker_sha256, release_sha256 = load_fixtures()
    approved = _evidence(record, marker_sha256)

    fixture_config = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "saf-1005-018-fixture", "namespace": NAMESPACE,
                     "labels": {LABEL_KEY: LABEL_VALUE}},
        "immutable": True,
        "data": {"release.json": json.dumps(record, sort_keys=True),
                 "component-marker.txt": marker, "mock_component.py": program},
    }
    existing = lab.kubectl("-n", NAMESPACE, "get", "configmap", "saf-1005-018-fixture",
                           "-o", "json", "--ignore-not-found")
    if existing.stdout.strip():
        lab.block("Refusing to overwrite a pre-existing case fixture ConfigMap")
    lab.create(fixture_config)
    observed_fixture = json.loads(lab.kubectl("-n", NAMESPACE, "get", "configmap",
                                              "saf-1005-018-fixture", "-o", "json").stdout)
    if (observed_fixture.get("immutable") is not True
            or observed_fixture.get("metadata", {}).get("labels", {}).get(LABEL_KEY) != LABEL_VALUE
            or observed_fixture.get("data", {}).get("component-marker.txt") != marker
            or observed_fixture.get("data", {}).get("release.json")
            != json.dumps(record, sort_keys=True)
            or observed_fixture.get("data", {}).get("mock_component.py") != program):
        lab.block("Case-owned immutable fixture bytes failed Kubernetes API readback")

    changed = copy.deepcopy(approved)
    changed[0]["sha256"] = "0" * 64
    missing = approved[:-1]

    bypass = _promote(lab, record, changed, marker, program, marker_sha256, enabled=False)
    bypass_names = sorted(row["metadata"]["name"] for row in _deployments(lab))
    lab.check("red", "Bypassing the fixture gate creates deployments with mismatching evidence",
              bypass["accepted"] and not bypass["integrity_ok"]
              and bypass_names == sorted(COMPONENTS.values()),
              {"gate": bypass, "created": bypass_names})
    lab.kubectl("delete", "deployments", *bypass_names, "--cascade=foreground", timeout=70)

    denied_mismatch = _promote(lab, record, changed, marker, program, marker_sha256)
    mismatch_names = sorted(row["metadata"]["name"] for row in _deployments(lab))
    denied_missing = _promote(lab, record, missing, marker, program, marker_sha256)
    missing_names = sorted(row["metadata"]["name"] for row in _deployments(lab))
    lab.check("green", "The enabled gate skips promotion for mismatching and missing evidence",
              not denied_mismatch["accepted"] and not denied_missing["accepted"]
              and not denied_mismatch["components"][record["components"][0]["id"]]["digest_matches"]
              and not denied_missing["components"][record["components"][-1]["id"]]["evidence_present"]
              and not mismatch_names and not missing_names,
              {"different_digest": denied_mismatch, "missing_evidence": denied_missing,
               "mismatching_deployments": mismatch_names, "missing_evidence_deployments": missing_names})

    gate = _promote(lab, record, approved, marker, program, marker_sha256)
    lab.check("positive", "Matching release evidence permits the fixture promotion",
              gate["accepted"] and gate["release_identity_exact"] and gate["inventory_exact"]
              and gate["integrity_ok"], gate)
    observed_inventory = [_wait_ready(lab, component, marker_sha256)
                          for component in record["components"]]
    api_deployments = _deployments(lab)
    actual_names = {row["metadata"]["name"] for row in api_deployments}
    expected_names = set(COMPONENTS.values())
    actual_spec = {row["metadata"]["name"]: row.get("spec", {}).get("template", {})
                   .get("spec", {}).get("containers", []) for row in api_deployments}
    exact_inventory = (actual_names == expected_names
                       and len(api_deployments) == len(expected_names)
                       and len(observed_inventory) == len(expected_names)
                       and all([container.get("name") for container in actual_spec[name]] == ["mock"]
                               and [container.get("image") for container in actual_spec[name]] == [FIXTURE_IMAGE]
                               for name in expected_names)
                       and {row["component_id"] for row in observed_inventory}
                       == set(COMPONENTS))
    all_ready = all(row["pod_ready"] and row["container_ready"]
                    and row["available_replicas"] == row["ready_replicas"] == 1
                    and row["spec_images"] == [FIXTURE_IMAGE]
                    for row in observed_inventory)
    evidence = {
        "notice": "Synthetic recovery evidence only; no secrets, real feeds, incidents, or targets.",
        "release_id": record["release_id"],
        "release_record_sha256": release_sha256,
        "release_identity": gate["release_identity_exact"],
        "marker_sha256": marker_sha256,
        "fixture_configmap_uid": observed_fixture["metadata"].get("uid"),
        "gate": gate,
        "bypass_gate": bypass,
        "bypass_deployments": bypass_names,
        "denied_mismatch": denied_mismatch,
        "denied_missing": denied_missing,
        "inventory_exact": exact_inventory,
        "restored_components": observed_inventory,
    }
    (lab.evidence / "recovery-gate.raw.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    stable_readiness = [
        {key: row[key] for key in ("component_id", "deployment", "generation",
                                    "observed_generation", "available_replicas",
                                    "ready_replicas", "pod_ready", "container_ready",
                                    "spec_images", "startup_observation")}
        for row in observed_inventory
    ]
    lab.check("positive", "The promoted mock inventory became ready and reported the exact mounted digest",
              exact_inventory and all_ready and gate["accepted"]
              and all(row["observed_generation"] == row["generation"] for row in observed_inventory),
              {"inventory_exact": exact_inventory, "observed_components": stable_readiness})
