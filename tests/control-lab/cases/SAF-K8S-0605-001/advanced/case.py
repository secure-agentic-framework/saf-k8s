"""Exercise Pod init accounting and the pinned TrainJob schema at admission."""
from hashlib import sha256
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
NS = "saf-0605-001-local"
CONSTRAINT = "saf-gpu-provenance-admission"
TRAIN_JOB_CRD = "trainjobs.trainer.kubeflow.org"
CRD_URL = ("https://raw.githubusercontent.com/kubeflow/trainer/v2.3.0/"
           "manifests/base/crds/trainer.kubeflow.org_trainjobs.yaml")
CRD_HASH = "a742cafc5b5582640c7e0b7467c024fc237256fbca5ba0a9f0531dfb66d64416"
CAP = "effective Pod GPU limits 3 exceed fixture maximum 2"
TRAIN_CAP = "TrainJob declared GPU limits 4 exceed fixture maximum 2"
GPU = "nvidia.com/gpu"


def submit(lab, name):
    return lab.kubectl("-n", NS, "create", "-f", str(HERE / "fixtures" / (name + ".yaml")),
                       "--dry-run=server", "-o", "json", allow_failure=True)


def denied(result, message):
    return result.returncode != 0 and CONSTRAINT in result.stderr and message in result.stderr


def run(lab, gator):
    offline = lab.command(str(gator), "verify", "--verbose", str(HERE / "gator-suite.yaml"))
    lines = [line for line in offline.stdout.splitlines()
             if line.strip().startswith("--- PASS: ") and "gpu-limits-and-init-accounting" not in line]
    lab.check("positive", "The pinned Gator suite passes seven extended resource comparisons",
              len(lines) == 7, {"passed_gator_checks": len(lines)})
    lab.kubectl("create", "namespace", NS)
    artifact = lab.kubeconfig.with_name("kubeflow-trainjobs-v2.3.0.yaml")
    lab.command("curl", "-fsSL", CRD_URL, "-o", str(artifact), timeout=60)
    if sha256(artifact.read_bytes()).hexdigest() != CRD_HASH:
        lab.block("The TrainJob schema differs from the reviewed upstream release")
    lab.kubectl("apply", "-f", str(artifact))
    lab.kubectl("wait", "--for=condition=Established", f"crd/{TRAIN_JOB_CRD}", "--timeout=40s")
    crd = json.loads(lab.kubectl("get", "crd", TRAIN_JOB_CRD, "-o", "json").stdout)
    versions = [row["name"] for row in crd["spec"]["versions"] if row["served"]]
    lab.check("positive", "Kubernetes serves the pinned Kubeflow TrainJob CRD schema",
              "v1alpha1" in versions and crd["spec"]["names"]["kind"] == "TrainJob",
              {"served_versions": versions, "upstream_schema_sha256": CRD_HASH})

    rejected_cases = {
        "pod-init-phase-over-cap": CAP,
        "pod-restartable-steady-over-cap": CAP,
        "pod-limits-only-wrong-runtime": "GPU Pods require RuntimeClass saf-gpu",
        "trainjob-limits-only-over-cap": TRAIN_CAP,
    }
    evidence = {}
    for name in rejected_cases:
        result = submit(lab, name)
        admitted = result.returncode == 0
        lab.check("red", f"The API accepts {name} before the constraint is installed",
                  admitted, {"accepted_before_constraint": admitted})
        evidence[name] = {"before": json.loads(result.stdout)}

    lab.kubectl("apply", "-f", str(HERE / "constraint-template.yaml"))
    lab.kubectl("wait", "--for=condition=Established",
                "crd/safgpuprovenanceadmission.constraints.gatekeeper.sh", "--timeout=60s", timeout=70)
    lab.kubectl("apply", "-f", str(HERE / "constraint.yaml"))
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if denied(submit(lab, "pod-init-phase-over-cap"), CAP):
            break
        time.sleep(.5)
    else:
        lab.block("The advanced Gatekeeper constraint did not reach native admission")
    for name, message in rejected_cases.items():
        result = submit(lab, name)
        rejected = denied(result, message)
        lab.check("green", f"The exact Gatekeeper policy rejects {name}",
                  rejected, {"named_constraint_denial": rejected, "reason": message})
        evidence[name]["after"] = result.stderr.strip()

    for name in ("pod-limits-only-at-cap", "pod-restartable-init-at-cap", "trainjob-limits-only-at-cap"):
        result = submit(lab, name)
        obj = json.loads(result.stdout) if result.returncode == 0 else {}
        lab.check("positive", f"The at-cap declaration is accepted for {name}",
                  obj.get("metadata", {}).get("name") == name, {"at_cap_admitted": bool(obj)})
        evidence[name] = {"after": obj}
    pod = evidence["pod-limits-only-at-cap"]["after"]
    requests = [c.get("resources", {}).get("requests", {}).get(GPU) for c in pod["spec"]["containers"]]
    limits = [c.get("resources", {}).get("limits", {}).get(GPU) for c in pod["spec"]["containers"]]
    lab.check("positive", "Native Pod defaulting fills GPU requests from the declared limits",
              requests == limits and any(requests), {"requests_equal_limits": requests == limits,
                                                      "gpu_requests": requests})
    (lab.evidence / "advanced-gpu-admission.json").write_text(json.dumps(evidence, indent=2) + "\n")
