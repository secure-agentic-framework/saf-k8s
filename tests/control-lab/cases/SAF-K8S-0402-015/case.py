"""Verify prevention of new legacy token Secret objects with dry-run requests."""
from datetime import datetime
from pathlib import Path
import time


HERE = Path(__file__).parent
REJECTION = "Secret type kubernetes.io/service-account-token is not permitted for new Secrets"
SCOPE = (
    "Kubernetes v1.36.1 server-side dry runs of an empty synthetic legacy Secret and "
    "an inert Opaque Secret, with a namespace-scoped admission policy. The case also "
    "verifies the native tracking ConfigMap and a type-based inventory query. Credential "
    "issuance, actual token use and removal, migration and production scope remain separate."
)


def dry_run(lab, fixture):
    return lab.kubectl("create", "--dry-run=server", "-o", "name", "-f", str(HERE / "fixtures" / fixture),
                       allow_failure=True)


def run(lab):
    legacy = "legacy-token-secret-empty.yaml"
    ordinary = "ordinary-secret-inert.yaml"
    baseline = dry_run(lab, legacy)
    admitted = baseline.returncode == 0 and baseline.stdout.strip() == "secret/saf-k8s-0402-015-legacy-empty-probe"
    lab.check("red", "The API accepts the empty legacy shape in a dry run before policy",
              admitted, {"dry_run_admitted": admitted})
    lab.apply(HERE / "admission-policy.yaml")
    deadline = time.monotonic() + 15
    while True:
        tested = dry_run(lab, legacy)
        denied = tested.returncode != 0 and REJECTION in tested.stderr
        if denied or time.monotonic() >= deadline:
            break
        time.sleep(0.25)
    lab.check("green", "Admission rejects the same legacy Secret request on its type",
              denied, {"matched_legacy_type_denial": denied})
    other = dry_run(lab, ordinary)
    preserved = other.returncode == 0 and other.stdout.strip() == "secret/saf-k8s-0402-015-ordinary-inert-probe"
    lab.check("positive", "Admission allows an inert Opaque Secret in a dry run",
              preserved, {"ordinary_dry_run_admitted": preserved})
    legacy_names = lab.kubectl("get", "secrets", "--field-selector", "type=kubernetes.io/service-account-token",
                              "-o", "name").stdout.splitlines()
    all_names = lab.kubectl("get", "secrets", "-o", "name").stdout.splitlines()
    lab.check("positive", "The type query succeeds and neither dry run persists a Secret",
              not legacy_names and not all_names, {"legacy_objects": len(legacy_names), "all_objects": len(all_names)})
    started = lab.kubectl("-n", "kube-system", "get", "configmap",
                          "kube-apiserver-legacy-service-account-token-tracking", "-o", "jsonpath={.data.since}").stdout
    timestamp = datetime.fromisoformat(started.strip().replace("Z", "+00:00"))
    lab.check("positive", "The built-in tracking ConfigMap records a monitoring start date",
              timestamp.year >= 2023, {"tracking_start_present": True})
