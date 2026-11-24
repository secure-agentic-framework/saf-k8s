"""Bind inert accelerator inventory fixtures to an observed Kubernetes workload identity."""
from copy import deepcopy
from hashlib import sha256
import json
import re

from fixtures import container, pod, ready

POD = "accelerator-inventory-witness"
SYNTHETIC_ADVISORY = "SAF-FIXTURE-CUDA-0905-029-001"
FIXTURE_TIME = "2026-11-23T12:00:00Z"
SCOPE = (
    "A disposable Kubernetes v1.36.1 Kind cluster runs one restricted, non-GPU Pod in the "
    "runner's default saf-test namespace. The case binds synthetic offline software SBOM "
    "components (CUDA Toolkit, cuDNN and NCCL) and a separate synthetic native-host report "
    "(driver and device-plugin inventory) to the actual Pod UID, service account, node name "
    "and imageID read from the Kubernetes API. An immutable fixture triage record retains the "
    "correlated findings and rechecks as each inventory is corrected. All component versions "
    "and the advisory are synthetic. Actual GPU software, runtime drivers, advisory ingestion "
    "and production remediation remain deployment evidence."
)

COMPONENTS_AFFECTED = [
    {"type": "library", "bom-ref": "fixture-cuda-toolkit", "name": "CUDA Toolkit",
     "version": "0.0.0-fixture.1"},
    {"type": "library", "bom-ref": "fixture-cudnn", "name": "cuDNN",
     "version": "0.0.0-fixture.1"},
    {"type": "library", "bom-ref": "fixture-nccl", "name": "NCCL",
     "version": "0.0.0-fixture.1"},
]
COMPONENTS_PATCHED = [
    {"type": "library", "bom-ref": "fixture-cuda-toolkit", "name": "CUDA Toolkit",
     "version": "0.0.0-fixture.2"},
    {"type": "library", "bom-ref": "fixture-cudnn", "name": "cuDNN",
     "version": "0.0.0-fixture.2"},
    {"type": "library", "bom-ref": "fixture-nccl", "name": "NCCL",
     "version": "0.0.0-fixture.2"},
]
HOST_AFFECTED = {
    "record_type": "synthetic-native-host-inventory",
    "node_name": None,
    "components": [
        {"kind": "host-driver", "name": "GPU driver", "version": "0.0.0-fixture.1"},
        {"kind": "host-device-plugin", "name": "GPU device plugin", "version": "0.0.0-fixture.1"},
    ],
}
HOST_PATCHED = {
    "record_type": "synthetic-native-host-inventory",
    "node_name": None,
    "components": [
        {"kind": "host-driver", "name": "GPU driver", "version": "0.0.0-fixture.2"},
        {"kind": "host-device-plugin", "name": "GPU device plugin", "version": "0.0.0-fixture.2"},
    ],
}
ADVISORY = {
    "id": SYNTHETIC_ADVISORY,
    "summary": "Synthetic fixture match; not a real vulnerability advisory",
    "affected": {
        "software": {"fixture-cudnn": ["0.0.0-fixture.1"]},
        "host": {"GPU driver": ["0.0.0-fixture.1"]},
    },
}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value):
    return "sha256:" + sha256(value).hexdigest()


def _sbom(components):
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"timestamp": FIXTURE_TIME,
                     "component": {"type": "application", "name": "inert-accelerator-fixture",
                                   "version": "0.0.0-fixture"}},
        "components": deepcopy(components),
    }


def _identity(pod_object):
    statuses = pod_object.get("status", {}).get("containerStatuses", [])
    if len(statuses) != 1 or not statuses[0].get("imageID"):
        raise ValueError("Kubernetes did not report one running container imageID")
    image_id = statuses[0]["imageID"]
    digest = re.search(r"sha256:[0-9a-f]{64}$", image_id)
    if digest is None:
        raise ValueError(f"Container imageID lacks a digest: {image_id!r}")
    spec = pod_object.get("spec", {})
    metadata = pod_object.get("metadata", {})
    observed = {
        "namespace": metadata.get("namespace"), "name": metadata.get("name"),
        "uid": metadata.get("uid"), "service_account": spec.get("serviceAccountName"),
        "node_name": spec.get("nodeName"), "image_id": image_id,
        "image_digest": digest.group(0),
    }
    if not all(observed.values()) or observed["name"] != POD or observed["namespace"] != "saf-test":
        raise ValueError(f"Kubernetes runtime identity is incomplete or out of scope: {observed}")
    return observed


def _report(identity, sbom, host_inventory):
    return {
        "schema": "saf-lab.example/accelerator-release-report/v1",
        "created": FIXTURE_TIME,
        "subject": deepcopy(identity),
        "software_sbom_sha256": _digest(_canonical(sbom)),
        "host_inventory_sha256": _digest(_canonical(host_inventory)),
        "software_sbom": deepcopy(sbom),
        "host_inventory": deepcopy(host_inventory),
    }


def _evaluate(report, expected_identity, *, enabled=True):
    if not enabled:
        return {"decision": "accepted-unchecked", "allowed": True,
                "findings": _findings(report), "reason": "fixture-policy-disabled"}
    if report is None or report.get("host_inventory") is None:
        return {"decision": "blocked", "allowed": False, "findings": [],
                "reason": "host-inventory-missing"}
    if report.get("subject") != expected_identity:
        return {"decision": "blocked", "allowed": False, "findings": [],
                "reason": "runtime-identity-mismatch"}
    sbom = report.get("software_sbom", {})
    host = report.get("host_inventory", {})
    if (sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.6"
            or host.get("record_type") != "synthetic-native-host-inventory"
            or host.get("node_name") != expected_identity["node_name"]):
        return {"decision": "blocked", "allowed": False, "findings": [],
                "reason": "inventory-invalid-or-unbound"}
    if report.get("software_sbom_sha256") != _digest(_canonical(sbom)):
        return {"decision": "blocked", "allowed": False, "findings": [],
                "reason": "software-inventory-digest-mismatch"}
    if report.get("host_inventory_sha256") != _digest(_canonical(host)):
        return {"decision": "blocked", "allowed": False, "findings": [],
                "reason": "host-inventory-digest-mismatch"}
    expected_software = {row["bom-ref"] for row in COMPONENTS_AFFECTED}
    expected_host = {row["kind"] for row in HOST_AFFECTED["components"]}
    if ({row["bom-ref"] for row in sbom.get("components", [])} != expected_software or
            {row["kind"] for row in host.get("components", [])} != expected_host):
        return {"decision": "blocked", "allowed": False, "findings": [],
                "reason": "inventory-incomplete"}
    findings = _findings(report)
    return {"decision": "blocked-findings" if findings else "allowed-clear",
            "allowed": not findings, "findings": findings,
            "reason": "synthetic-advisory-match" if findings else "no-fixture-match"}


def _findings(report):
    if report is None or not isinstance(report.get("software_sbom"), dict):
        return []
    software = report["software_sbom"].get("components", [])
    host_record = report.get("host_inventory") or {}
    host_components = host_record.get("components", [])
    found = []
    for component in software:
        versions = ADVISORY["affected"]["software"].get(component.get("bom-ref"), [])
        if component.get("version") in versions:
            found.append({"advisory": SYNTHETIC_ADVISORY, "inventory": "software-sbom",
                          "component_ref": component["bom-ref"],
                          "name": component["name"], "version": component["version"]})
    for component in host_components:
        versions = ADVISORY["affected"]["host"].get(component.get("name"), [])
        if component.get("version") in versions:
            found.append({"advisory": SYNTHETIC_ADVISORY, "inventory": "native-host-report",
                          "name": component["name"], "version": component["version"]})
    return sorted(found, key=lambda item: (item["inventory"], item["name"], item["version"]))


def _create_witness_pod(lab):
    item = pod(POD, [container("identity", command=["sh", "-c", "sleep 3600"])],
               automountServiceAccountToken=False,
               securityContext={"runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}})
    # Deliberately no GPU resource request, device node, hostPath, hostPID, or privilege.
    lab.create(item)
    ready(lab, POD)
    response = lab.kubectl("get", "pod", POD, "-o", "json")
    return response.stdout, json.loads(response.stdout)


def retain_triage(lab, name, value):
    created = lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                          "immutable": True, "data": {"report.json": _canonical(value).decode()}})
    observed = json.loads(lab.kubectl("get", "configmap", name, "-o", "json").stdout)
    matched = created["metadata"]["uid"] == observed["metadata"]["uid"] and observed["immutable"] and (
        json.loads(observed["data"]["report.json"]) == value)
    return observed["metadata"]["uid"], matched


def run(lab):
    raw_pod_json, pod_object = _create_witness_pod(lab)
    identity = _identity(pod_object)
    sbom_affected = _sbom(COMPONENTS_AFFECTED)
    sbom_patched = _sbom(COMPONENTS_PATCHED)
    host_affected = {**deepcopy(HOST_AFFECTED), "node_name": identity["node_name"]}
    host_patched = {**deepcopy(HOST_PATCHED), "node_name": identity["node_name"]}
    report_affected = _report(identity, sbom_affected, host_affected)
    report_patched = _report(identity, sbom_patched, host_patched)

    unchecked = _evaluate(report_affected, identity, enabled=False)
    unchecked_uid, unchecked_persisted = retain_triage(lab, "accelerator-unchecked-observation",
                                                        {"decision": unchecked, "subject": identity})
    lab.check(
        "red",
        "With policy disabled, the exact affected synthetic accelerator release is accepted unchecked",
        unchecked_persisted and unchecked == {
            "decision": "accepted-unchecked", "allowed": True,
            "findings": [
                {"advisory": SYNTHETIC_ADVISORY, "inventory": "native-host-report",
                 "name": "GPU driver", "version": "0.0.0-fixture.1"},
                {"advisory": SYNTHETIC_ADVISORY, "inventory": "software-sbom",
                 "component_ref": "fixture-cudnn", "name": "cuDNN",
                 "version": "0.0.0-fixture.1"},
            ], "reason": "fixture-policy-disabled",
        }, unchecked)

    missing_host = _evaluate({**report_affected, "host_inventory": None}, identity)
    mismatched_identity = _evaluate(
        {**report_affected, "subject": {**identity, "uid": "stale-fixture-uid"}}, identity)
    tampered_host = _evaluate(
        {**report_affected,
         "host_inventory": {**host_affected, "components": []}}, identity)
    affected = _evaluate(report_affected, identity)
    host_open = _evaluate(_report(identity, sbom_patched, host_affected), identity)
    library_open = _evaluate(_report(identity, sbom_affected, host_patched), identity)
    incomplete = _evaluate(_report(identity, _sbom(COMPONENTS_PATCHED[:-1]), host_patched), identity)
    green_expected_findings = [
        {"advisory": SYNTHETIC_ADVISORY, "inventory": "native-host-report",
         "name": "GPU driver", "version": "0.0.0-fixture.1"},
        {"advisory": SYNTHETIC_ADVISORY, "inventory": "software-sbom",
         "component_ref": "fixture-cudnn", "name": "cuDNN",
         "version": "0.0.0-fixture.1"},
    ]
    green = {
        "missing_host": missing_host,
        "mismatched_identity": mismatched_identity,
        "tampered_host": tampered_host,
        "affected": affected,
        "host-open": host_open,
        "library-open": library_open,
        "incomplete": incomplete,
    }
    triage_uid, triage_persisted = retain_triage(lab, "accelerator-open-triage",
                                                 {"subject": identity, "initial": affected,
                                                  "after_library_update": host_open,
                                                  "after_host_update": library_open})
    lab.check(
        "green",
        "Enabled policy blocks absent native evidence, stale identity, and exact synthetic findings",
        triage_persisted and missing_host == {"decision": "blocked", "allowed": False, "findings": [],
                         "reason": "host-inventory-missing"}
        and mismatched_identity == {"decision": "blocked", "allowed": False, "findings": [],
                                    "reason": "runtime-identity-mismatch"}
        and tampered_host == {"decision": "blocked", "allowed": False, "findings": [],
                              "reason": "host-inventory-digest-mismatch"}
        and affected == {"decision": "blocked-findings", "allowed": False,
                         "findings": green_expected_findings,
                         "reason": "synthetic-advisory-match"}
        and host_open["findings"] == green_expected_findings[:1] and not host_open["allowed"]
        and library_open["findings"] == green_expected_findings[1:] and not library_open["allowed"]
        and incomplete["reason"] == "inventory-incomplete" and not incomplete["allowed"],
        green,
    )

    accepted = _evaluate(report_patched, identity)
    remediated = {"subject": identity, "prior_triage_uid": triage_uid,
                  "report": report_patched, "decision": accepted}
    cleared_uid, cleared_persisted = retain_triage(lab, "accelerator-closed-triage", remediated)
    lab.check(
        "positive",
        "Patched software and native fixtures produce a clear report bound to the observed workload",
        cleared_persisted and len({unchecked_uid, triage_uid, cleared_uid}) == 3
        and accepted == {"decision": "allowed-clear", "allowed": True, "findings": [],
                     "reason": "no-fixture-match"}
        and report_patched["subject"] == identity
        and report_patched["software_sbom_sha256"] == _digest(_canonical(sbom_patched))
        and report_patched["host_inventory_sha256"] == _digest(_canonical(host_patched)),
        {"gate": accepted, "exact_subject": report_patched["subject"] == identity,
         "closed_triage_observed": cleared_persisted},
    )

    raw = {
        "kubernetes_pod_json": json.loads(raw_pod_json),
        "software_sbom_affected": sbom_affected,
        "software_sbom_patched": sbom_patched,
        "native_host_inventory_affected": host_affected,
        "native_host_inventory_patched": host_patched,
        "synthetic_advisory": ADVISORY,
        "reports": {"affected": report_affected, "patched": report_patched},
        "retained_receipts": {"unchecked": unchecked_uid, "open": triage_uid, "closed": cleared_uid},
        "closed_triage": remediated,
        "policy_observations": {"red": unchecked, "green": green, "positive": accepted},
    }
    normalized = {
        "format": "saf-lab-accelerator-inventory-witness/v1",
        "normalization": "Live workload, node and report identifiers remain in the raw receipt.",
        "control_id": "SAF-K8S-0905-029",
        "live_runtime_identity_observed": bool(identity["uid"] and identity["image_id"]),
        "inventory_boundary": {
            "software_sbom_components": [
                {"bom_ref": item["bom-ref"], "name": item["name"], "version": item["version"]}
                for item in sbom_affected["components"]],
            "native_host_components": [
                {"kind": item["kind"], "name": item["name"], "version": item["version"]}
                for item in host_affected["components"]],
            "fixture_only": True,
        },
        "fixture_findings": _findings(report_affected),
        "decisions": {"red": unchecked, "green": green, "positive": accepted},
        "sources": {
            "sbom_sha256": _digest(_canonical(sbom_affected)),
            "host_component_inventory_sha256": _digest(_canonical(host_affected["components"])),
            "advisory_sha256": _digest(_canonical(ADVISORY)),
        },
    }
    (lab.evidence / "accelerator-inventory-raw.json").write_text(
        json.dumps(raw, indent=2, sort_keys=True) + "\n")
    (lab.evidence / "accelerator-inventory-normalized.json").write_text(
        json.dumps(normalized, indent=2, sort_keys=True) + "\n")
