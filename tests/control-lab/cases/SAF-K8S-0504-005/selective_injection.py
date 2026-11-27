"""Observe Istio's per-Pod sidecar selection with inert case-owned Pods."""

import importlib.util
import json
from pathlib import Path

EXCLUDED = "saf-0504-005-selective-optout"


def proxy_count(pod_json):
    spec = pod_json.get("spec", {})
    rows = list(spec.get("containers", []))
    rows.extend(row for row in spec.get("initContainers", [])
                if row.get("restartPolicy") == "Always")
    return sum(row.get("name") == "istio-proxy" for row in rows)


def run(lab, *, pod_factory, resource, wait_ready, snapshot, sidecar_resources,
        observed_requests, assert_check, pinned_proxy, client_sleep, expected_resources, kubectl):
    # The namespace remains injection-enabled. Only this inert Pod carries the
    # documented Pod-template label that opts it out; no request is sent from it.
    excluded = pod_factory(EXCLUDED, client_sleep, annotations=pinned_proxy)
    excluded["metadata"]["labels"]["sidecar.istio.io/inject"] = "false"
    excluded["metadata"]["labels"]["saf-k8s.example/fixture-purpose"] = "non-networked-optout-reference"
    gate_path = Path(__file__).with_name("mesh_exemption.py")
    gate_spec = importlib.util.spec_from_file_location("saf_0504_005_mesh_exemption", gate_path)
    if gate_spec is None or gate_spec.loader is None:
        lab.block("Could not load the case-local opt-out exception admission gate")
    gate_module = importlib.util.module_from_spec(gate_spec)
    gate_spec.loader.exec_module(gate_module)
    gate = gate_module.prepare(lab, excluded, kubectl=kubectl)
    excluded = gate["approved_pod"]
    resource(lab, excluded)
    wait_ready(lab, EXCLUDED)

    excluded_pod = snapshot(lab, EXCLUDED)
    meshed_pod = snapshot(lab, "saf-0504-005-backend")
    namespace = json.loads(kubectl(lab, "get", "namespace", "saf-test", "-o", "json").stdout)
    rows, authenticated = observed_requests(lab, "selective-participation-route")
    excluded_count = proxy_count(excluded_pod)
    meshed_count = proxy_count(meshed_pod)
    observed = {
        "namespace_injection_enabled": namespace.get("metadata", {}).get("labels", {}).get(
            "istio-injection") == "enabled",
        "optout_label_exact": excluded_pod.get("metadata", {}).get("labels", {}).get(
            "sidecar.istio.io/inject") == "false",
        "optout_proxy_count": excluded_count,
        "meshed_proxy_count": meshed_count,
        "meshed_proxy_resources_tuned": sidecar_resources(meshed_pod) == expected_resources,
        "meshed_authenticated_requests": len(rows),
        "meshed_requests_exact_200": all(
            row == {"status": 200, "path": "/owned/inference-fixture",
                    "fixture": "saf-0504-005-owned"} for row in rows
        ),
        "meshed_peer_logged": authenticated,
    }
    assert_check(
        lab, "positive",
        "The documented per-Pod opt-out omits the proxy only on its inert Pod while the tuned mTLS route stays active",
        observed["namespace_injection_enabled"] and observed["optout_label_exact"]
        and excluded_count == 0 and meshed_count == 1
        and observed["meshed_proxy_resources_tuned"]
        and len(rows) == 3 and observed["meshed_requests_exact_200"]
        and authenticated,
        observed,
    )
    gate_module.finish(
        lab, gate, excluded, excluded_pod, meshed_pod, rows,
        authenticated, assert_check,
    )
    observed["exception_admission"] = gate["normalized"]
    return observed
