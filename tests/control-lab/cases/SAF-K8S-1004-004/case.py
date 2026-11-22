"""Exercise offline advisory integrity, expiry quarantine, and exact enrichment."""
import json
from pathlib import Path

from lab import NAMESPACE


HERE = Path(__file__).resolve().parent
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
WORKER_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
BUNDLE_SHA256 = "99b0a2d0515a4551e9038413265e1c0b972ccf20f294e6ed38c03327cc29917b"
JOB_NAME = "saf-1004-004-offline-fixture"
CONFIG_NAME = "saf-1004-004-offline-fixture"
AS_OF = "2026-11-21T12:00:00Z"
SCOPE = (
    "Offline, synthetic threat-intelligence fixture processing in a disposable Kubernetes v1.36.1 Kind cluster. "
    "Verifies SHA-256 pin quarantine, expiry quarantine, exact advisory enrichment for one approved mock "
    "observation, and quiet package-version/image-digest near misses. This does not exercise external feed "
    "connectivity, source authenticity, production ingestion freshness/completeness, threat-sharing participation, "
    "or deployed SIEM/SOAR rule operation."
)


def load(name):
    return (HERE / "fixtures" / name).read_bytes()


def expected_enrichment():
    observation = json.loads(load("observations.json"))[0]
    return {
        "observation_id": observation["observation_id"],
        "asset_ref": observation["asset_ref"],
        "match": {"image_digest": observation["image_digest"],
                  "package": observation["package"], "version": observation["version"]},
        "enrichment": {
            "bundle_id": "SYNTH-BUNDLE-1004-004-01",
            "source_id": "SYNTH-SOURCE-LOCAL-ONLY",
            "advisory_id": "SYNTH-ADVISORY-1004-004-001",
            "severity": "synthetic-high",
            "fixed_version": "1.0.1",
        },
    }


def run(lab):
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": CONFIG_NAME, "namespace": NAMESPACE,
                     "labels": {"saf-k8s.example/control-1004-004": "synthetic-fixture"}},
        "data": {
            "worker.py": load("worker.py").decode(),
            "approved-bundle.json": load("approved-bundle.json").decode(),
            "damaged-bundle.json": load("damaged-bundle.json").decode(),
            "observations.json": load("observations.json").decode(),
        },
    })
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": JOB_NAME, "namespace": NAMESPACE,
                     "labels": {"saf-k8s.example/control-1004-004": "synthetic-fixture"}},
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": 90,
            "template": {
                "metadata": {"labels": {"saf-k8s.example/control-1004-004": "synthetic-fixture"}},
                "spec": {
                    "restartPolicy": "Never",
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{
                        "name": "offline-fixture-worker", "image": WORKER_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "/case/worker.py"],
                        "env": [
                            {"name": "EXPECTED_BUNDLE_SHA256", "value": BUNDLE_SHA256},
                            {"name": "CASE_AS_OF", "value": AS_OF},
                        ],
                        "securityContext": {"allowPrivilegeEscalation": False,
                                             "readOnlyRootFilesystem": True,
                                             "capabilities": {"drop": ["ALL"]}},
                        "volumeMounts": [{"name": "fixture", "mountPath": "/case", "readOnly": True}],
                        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                      "limits": {"cpu": "250m", "memory": "64Mi"}},
                    }],
                    "volumes": [{"name": "fixture", "configMap": {"name": CONFIG_NAME,
                                                                       "defaultMode": 292}}],
                },
            },
        },
    })
    lab.kubectl("wait", f"job/{JOB_NAME}", "--for=condition=complete", "--timeout=120s", timeout=130)
    raw = lab.kubectl("logs", f"job/{JOB_NAME}").stdout.strip()
    (lab.evidence / "ingestion.raw.json").write_text(raw + "\n")
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as error:
        lab.block(f"Fixture worker returned no machine-readable result ({error})")

    baseline = result["baseline_unpinned"]
    lab.check("red", "An unpinned bundle is quarantined with no enrichment",
              baseline["accepted"] is False and baseline["quarantine_reason"] == "missing_digest_pin"
              and baseline["enrichments"] == [],
              {"accepted": baseline["accepted"], "reason": baseline["quarantine_reason"],
               "enrichment_count": len(baseline["enrichments"])})

    damaged = result["damaged"]
    lab.check("red", "A bundle changed after pinning is quarantined with no enrichment",
              damaged["accepted"] is False and damaged["quarantine_reason"] == "digest_mismatch"
              and damaged["enrichments"] == [],
              {"accepted": damaged["accepted"], "reason": damaged["quarantine_reason"],
               "enrichment_count": len(damaged["enrichments"]),
               "observed_sha256": damaged["bundle_sha256"]})

    expired = result["expired"]
    lab.check("red", "A correctly pinned but expired bundle is quarantined",
              expired["accepted"] is False and expired["quarantine_reason"] == "expired"
              and expired["enrichments"] == [],
              {"accepted": expired["accepted"], "reason": expired["quarantine_reason"],
               "enrichment_count": len(expired["enrichments"]),
               "bundle_sha256": expired["bundle_sha256"]})

    approved = result["approved"]
    lab.check("green", "The approved synthetic observation receives exact defensive enrichment",
              approved["accepted"] is True and approved["enrichments"] == [expected_enrichment()],
              approved["enrichments"])
    lab.check("positive", "Package-version and image-digest near misses remain quiet",
              approved["quiet_observation_ids"] == ["OBS-SYNTH-NEARMISS-VERSION",
                                                     "OBS-SYNTH-NEARMISS-IMAGE"],
              approved["quiet_observation_ids"])
