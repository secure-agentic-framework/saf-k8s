"""Test namespace-local image pull Secret delivery to a Pod reference."""
import json
from pathlib import Path
import subprocess
import time

from fixtures import container, pod

HERE = Path(__file__).resolve().parent
ACCOUNT = "fixture-pull-account"
SECRET = "fixture-empty-pull-config"
SCOPE = (
    "One disposable namespace, an empty dockerconfigjson Secret and normal ServiceAccount "
    "admission. Reference injection and an ordinary public-image workload are verified. "
    "Actual private-registry authentication, external Secret managers and CI delivery need separate evidence."
)


def classify(surface, form):
    if form == "direct-value" and surface in {"Pod workload", "Dockerfile", "CI environment"}:
        return "prohibited-value"
    if surface == "Pod imagePullSecrets reference" and form == "name-only-reference":
        return "allowed-reference"
    return "unclassified"


def evaluate_examples(lab):
    samples = json.loads((HERE / "embedding-cases.json").read_text())
    observed = {sample["surface"]: classify(sample["surface"], sample["form"])
                for sample in samples}
    expected = {
        "Pod workload": "prohibited-value",
        "Dockerfile": "prohibited-value",
        "CI environment": "prohibited-value",
        "Pod imagePullSecrets reference": "allowed-reference",
    }
    lab.check("red", "The policy example flags embedded-value forms in each named surface",
              observed == expected, observed)


def create_empty_pull_secret(lab):
    resource = {
        "apiVersion": "v1", "kind": "Secret", "metadata": {"name": SECRET},
        "type": "kubernetes.io/dockerconfigjson",
        "stringData": {".dockerconfigjson": json.dumps({"auths": {}})},
    }
    command = [
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "--namespace", "saf-test", "--request-timeout=20s",
        "create", "-f", "-", "-o", "name",
    ]
    result = subprocess.run(command, input=json.dumps(resource), text=True,
                            capture_output=True, env=lab.env, timeout=30)
    lab.check("positive", "The API admits the namespace-local empty pull configuration",
              result.returncode == 0 and result.stdout.strip() == f"secret/{SECRET}",
              {"secret_admitted": result.returncode == 0})


def run(lab):
    evaluate_examples(lab)
    lab.kubectl("create", "serviceaccount", ACCOUNT)
    body = pod("fixture-pull-reference", [container("public-probe", command=["true"])],
               serviceAccountName=ACCOUNT, automountServiceAccountToken=False)
    baseline = lab.create(body, dry_run=True)["spec"]
    lab.check("red", "The Pod has no injected pull reference before linking the ServiceAccount",
              not baseline.get("imagePullSecrets"), {"pull_references": baseline.get("imagePullSecrets", [])})

    create_empty_pull_secret(lab)
    patch = json.dumps({"imagePullSecrets": [{"name": SECRET}]})
    lab.kubectl("patch", "serviceaccount", ACCOUNT, "--type=merge", "-p", patch)
    deadline = time.monotonic() + 20
    expected = [{"name": SECRET}]
    observed = []
    while time.monotonic() < deadline:
        observed = lab.create(body, dry_run=True)["spec"].get("imagePullSecrets", [])
        if observed == expected:
            break
        time.sleep(0.5)
    lab.check("green", "Kubernetes admission injects the exact same-namespace Secret name",
              observed == expected, {"pull_references": observed})

    admitted = lab.create(body)
    lab.kubectl("wait", "pod/fixture-pull-reference", "--for=jsonpath={.status.phase}=Succeeded",
                "--timeout=75s", timeout=85)
    references = admitted["spec"].get("imagePullSecrets", [])
    lab.check("positive", "The live public-image Pod carries only the expected name reference",
              references == expected, {"pull_references": references, "workload_succeeded": True})
