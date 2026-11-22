"""Exercise both stable Kubernetes v1.37 workload certificate projections."""
from pathlib import Path
from runpy import run_path


ROOT = Path(__file__).resolve().parent
TRUST_BUNDLES = run_path(str(ROOT / "case.py"))
NODE_IMAGE = TRUST_BUNDLES["NODE_IMAGE"]
prepare_kind = TRUST_BUNDLES["prepare_kind"]
SCOPE = (
    "Kubernetes v1.37.0 kind with synthetic Pods. Validate selection and live update of public "
    "trust anchors, then authorized Pod certificate issuance, projection, and refresh under an "
    "exactly scoped test signer. Cross-cluster exchange, peer authentication and production "
    "authorization require independent evidence."
)


def run(lab):
    TRUST_BUNDLES["run"](lab)
    run_path(str(ROOT / "pod-certificate" / "probe.py"))["run"](lab)
