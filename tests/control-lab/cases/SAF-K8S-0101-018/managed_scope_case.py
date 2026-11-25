"""Compare total anonymous rejection with a documented health-only configuration."""
import importlib.util
from pathlib import Path

SCOPE = (
    "Disposable v1.36.1 kubeadm. Verify full anonymous rejection with authenticated probes, "
    "and compare the upstream health-only profile for two fixed CA-verified paths. "
    "Provider-specific observations are deployment evidence collected using the adoption guide."
)


def run(lab):
    spec = importlib.util.spec_from_file_location("saf_authenticated_probes",
                                                  Path(__file__).with_name("healthy_case.py"))
    profile = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(profile)
    profile.run(lab, compare_health_only=True)
