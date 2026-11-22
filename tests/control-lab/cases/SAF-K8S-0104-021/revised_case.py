"""Check the expanded version-skew policy and the regular live inventory."""
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("baseline_skew_case", HERE / "case.py")
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)

SCOPE = (
    "Synthetic Kubernetes v1.36 policy cases for mixed API server endpoints and the optional "
    "cloud-controller-manager, plus read-only inventory on one disposable v1.36.1 kind cluster. "
    "Actual managed-provider endpoints and mixed-version upgrades require their own evidence."
)


def check_ha_endpoints(lab):
    policy = json.loads((HERE / "policy.json").read_text())
    api_servers = [{"id": "older-api", "version": "1.35.9"},
                   {"id": "newer-api", "version": "1.36.1"}]
    overlapping_endpoints = ["older-api", "newer-api"]
    cases = (
        ("shared-controller", "1.35.9", overlapping_endpoints, []),
        ("newer-endpoint-only", "1.36.1", ["newer-api"], []),
        ("shared-controller-too-new", "1.36.1", overlapping_endpoints,
         [("newer_than_api_server", "older-api")]),
        ("shared-controller-too-old", "1.34.9", overlapping_endpoints,
         [("too_old_for_api_server", "newer-api")]),
    )
    for name, version, targets, expected in cases:
        inventory = {"api_servers": api_servers, "cloud_controller_managers": [
            {"id": name, "version": version, "api_servers": targets}
        ]}
        failures = baseline.evaluator.evaluate(inventory, policy)
        observed = [(failure["code"], failure["related"]) for failure in failures]
        lab.check("red" if expected else "green", f"Cloud controller skew decision for {name}",
                  observed == expected and all(failure["component"] == "cloud-controller-manager"
                                               for failure in failures), {"decisions": observed})


def run(lab):
    baseline._synthetic_checks(lab)
    check_ha_endpoints(lab)
    baseline._live_single_version_inventory(lab)
