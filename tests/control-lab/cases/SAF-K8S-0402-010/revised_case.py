"""Exercise both stable Kubernetes v1.37 workload certificate projections."""
from pathlib import Path
from runpy import run_path


ROOT = Path(__file__).resolve().parent
TRUST_BUNDLES = run_path(str(ROOT / "case.py"))
NODE_IMAGE = TRUST_BUNDLES["NODE_IMAGE"]
prepare_kind = TRUST_BUNDLES["prepare_kind"]
SCOPE = (
    "Two runner-owned Kubernetes v1.37.0 Kind clusters on the same inspected local Kind node "
    "network. Retain the existing trust-anchor selection and PodCertificate issuance/projection/"
    "refresh checks. Add an exact synthetic public-root CTB exchange and an A Pod using its own "
    "projected certificate/key to authenticate to B's private NodePort, with SNI and URI checks, "
    "an untrusted-issuer rejection, and trusted wrong-subject denial. Private workload keys stay "
    "in Pods. This is a local fixture, not cloud federation or production authorization evidence."
)


def run(lab):
    TRUST_BUNDLES["run"](lab)
    run_path(str(ROOT / "pod-certificate" / "probe.py"))["run"](lab)
