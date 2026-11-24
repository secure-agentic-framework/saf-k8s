"""Verify a quality gate in Kubernetes and independently check its storage outputs."""
import hashlib
import importlib.util
import json
from pathlib import Path

from fixtures import container, pod

HERE = Path(__file__).resolve().parent
CODE = "fixture-quality-code"
CLAIM = "fixture-quality-output"
EXPECTED = {
    "changed": "distribution_mean_shift", "outliers": "outlier_rate",
    "out-of-bounds": "input_validation",
}
SCOPE = (
    "A real Kind processor reads an immutable approved snapshot and four small invented candidates. "
    "An unchecked branch publishes all four. The governed branch independently tests data schema, "
    "mean drift and outlier limits. A read-only observer verifies the exact release by its digest. "
    "The thresholds only describe this fixture."
)


def workload(lab, image, name, operation, read_only=False):
    unit = container("quality", image=image, imagePullPolicy="Never",
                     command=["python", "/case/quality_worker.py", operation], volumeMounts=[
                         {"name": "code", "mountPath": "/case", "readOnly": True},
                         {"name": "output", "mountPath": "/volume", "readOnly": read_only},
                     ])
    lab.create(pod(name, [unit], securityContext={"fsGroup": 65534},
                   automountServiceAccountToken=False, volumes=[
                       {"name": "code", "configMap": {"name": CODE}},
                       {"name": "output", "persistentVolumeClaim": {"claimName": CLAIM}},
                   ]))
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{name}",
                "--timeout=85s", timeout=95)
    return json.loads(lab.kubectl("logs", f"pod/{name}").stdout)


def run(lab):
    path = HERE.parent / "SAF-K8S-0908-001" / "case.py"
    spec = importlib.util.spec_from_file_location("saf_quality_runtime", path)
    if spec is None or spec.loader is None:
        lab.block("The pinned fixture runtime could not be imported")
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    image = runtime.load_runtime(lab)
    datasets = {f.name: f.read_text() for f in (HERE / "fixtures").glob("*.json")}
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CODE},
                "immutable": True, "data": {**datasets,
                    "quality_worker.py": (HERE / "quality_worker.py").read_text()}})
    lab.create({"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": CLAIM},
                "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "64Mi"}}}})
    decisions = workload(lab, image, "fixture-quality-producer", "produce")
    reads = workload(lab, image, "fixture-quality-independent-reader", "read", read_only=True)
    expected_digests = {name: hashlib.sha256(json.dumps(
        json.loads(datasets[name + ".json"]), sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest() for name in ("within-limits", *EXPECTED)}
    lab.check("red", "The unchecked baseline persists every candidate to the volume",
              reads["baseline"] == expected_digests, reads["baseline"])
    green = {name: decisions[name]["decision"] == "hold" and decisions[name]["cause"] == reason
             and name not in reads["approved"] for name, reason in EXPECTED.items()}
    green["bounds_verified"] = decisions["out-of-bounds"]["validation_errors"] == ["value_bounds"]
    green["outlier_signal_distinct_from_mean_shift"] = (
        decisions["outliers"]["comparison"]["absolute_mean_shift"] == 0
        and decisions["outliers"]["comparison"]["outlier_rate"] > 0.25
    )
    lab.check("green", "Schema, drift and outlier holds prevent writes to the release branch",
              all(green.values()), green)
    positive = {"writer": decisions["within-limits"], "independent_reader": reads["approved"]}
    lab.check("positive", "The independent reader verifies only the within-limit release",
              positive["writer"]["decision"] == "release"
              and reads["approved"] == {"within-limits": expected_digests["within-limits"]}, positive)
    (lab.evidence / "training-data-quality-observations.json").write_text(json.dumps({
        "policy_decisions": decisions, "persistent_digests": reads, "expected_digests": expected_digests,
    }, sort_keys=True, indent=2) + "\n")
