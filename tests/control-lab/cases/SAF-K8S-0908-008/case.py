"""Defensive, deterministic response-shaping check for SAF-K8S-0908-008.

The only served values are two hard-coded, invented feature vectors and their
fixed synthetic score vectors. No data or query values are collected or logged.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SIBLING = (Path(__file__).resolve().parents[1] / "SAF-K8S-0908-001" /
           "case.py")
BASE = "fixture-shaping-baseline"
APP = "fixture-shaping-protected"
CODE = "saf-privacy-shaping-code"
NS = "saf-test"
IMAGE_PULL = "Never"
SCOPE = (
    "Separate baseline and governed synthetic HTTP services test the same benign "
    "inputs. The governed response coarsens a normalized vector, removes raw scores "
    "and stays within a fixed utility bound. Deployment disclosure risk, actual model "
    "utility and a formal privacy guarantee require their own evidence."
)
CLAIM_RED = "The unshaped synthetic response exposes confidence scores at six-decimal precision"
CLAIM_GREEN = "The shaped response uses the approved schema and one-decimal probabilities"
CLAIM_POSITIVE = "The fixed benign fixture retains top-one utility within the predefined bound"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load required case module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_runtime(lab):
    """Reuse the published sibling's verified local runtime setup."""
    if not SIBLING.is_file():
        lab.block("Required published sibling case SAF-K8S-0908-001/case.py is unavailable")
    sibling = _load_module("saf_k8s_0908_001_case", SIBLING)
    return sibling.load_runtime(lab)


def _create(lab, kind, name, api="v1", **fields):
    metadata = {"name": name}
    if kind != "Namespace":
        metadata["namespace"] = NS
    return lab.create({
        "apiVersion": api,
        "kind": kind,
        "metadata": metadata,
        **fields,
    })


def _start_service(lab, image, name, mode):
    pod_spec = {
        "restartPolicy": "Never",
        "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{
            "name": "fixture",
            "image": image,
            "imagePullPolicy": IMAGE_PULL,
            "command": ["python", "/fixture/response_fixture.py", "serve", mode],
            "ports": [{"name": "http", "containerPort": 8080}],
            "readinessProbe": {"httpGet": {"path": "/health", "port": 8080},
                               "periodSeconds": 1, "failureThreshold": 30},
            "securityContext": {"allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "volumeMounts": [{"name": "code", "mountPath": "/fixture",
                              "readOnly": True}],
            "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                          "limits": {"cpu": "100m", "memory": "64Mi"}},
        }],
        "volumes": [{"name": "code", "configMap": {"name": CODE}}],
    }
    lab.create({"apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": name, "namespace": NS,
                             "labels": {"app": name}}, "spec": pod_spec})
    _create(lab, "Service", name, spec={
        "selector": {"app": name},
        "ports": [{"name": "http", "port": 8080, "targetPort": 8080}],
    })
    lab.kubectl("-n", NS, "wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=95s", timeout=105)


def run(lab):
    image = load_runtime(lab)
    _create(lab, "ConfigMap", CODE, immutable=True,
            data={"response_fixture.py": (HERE / "response_fixture.py").read_text()})
    _start_service(lab, image, BASE, "baseline")
    _start_service(lab, image, APP, "shaped")
    # The evaluator and fixed vectors run inside the isolated fixture pod. It
    # calls only the cluster-local Service and emits aggregate observations.
    result = lab.kubectl("-n", NS, "exec", f"pod/{APP}", "--", "python",
                         "/fixture/response_fixture.py", "evaluate",
                         f"http://{BASE}.{NS}.svc:8080", f"http://{APP}.{NS}.svc:8080", timeout=20)
    observations = json.loads(result.stdout)

    lab.check("red", CLAIM_RED, observations["raw_contract_violation"],
              observations["red"])
    lab.check("green", CLAIM_GREEN, observations["shaped_contract_pass"],
              observations["green"])
    lab.check("positive", CLAIM_POSITIVE, observations["utility_pass"],
              observations["positive"])

    # Evidence intentionally contains only deterministic booleans, counts,
    # and aggregate utility; it excludes feature vectors and score values.
    (lab.evidence / "privacy-response-shaping-observations.json").write_text(
        json.dumps({"red": observations["red"],
                    "green": observations["green"],
                    "positive": observations["positive"]},
                   indent=2, sort_keys=True) + "\n")
