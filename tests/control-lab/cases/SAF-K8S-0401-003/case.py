"""Validate signed-off metadata on one synthetic aggregated ClusterRole input."""
import json
import time
from pathlib import Path


HERE = Path(__file__).parent
NAMESPACE = "saf-0401-003"
SUBJECT = "system:serviceaccount:saf-0401-003:saf-0401-003-subject"
CONSUMER = "system:serviceaccount:saf-0401-003:saf-0401-003-consumer"
SOURCE = "saf-0401-003-synthetic-source"
AGGREGATE = "saf-0401-003-synthetic-aggregate"
UNMARKED = "saf-0401-003-unmarked-role"
CONFIGMAP = "saf-0401-003-owned-fixture"
DENIAL = (
    "synthetic aggregate input requires the exact SAF-K8S-0401-003 owner, "
    "signed-off metadata, and subject"
)
SCOPE = (
    "Kubernetes v1.36.1 validating admission for fixture ClusterRole updates and matching "
    "contributors, followed by live ClusterRole "
    "aggregation into a case-owned aggregate role. Only get on a case-owned "
    "ConfigMap is exercised by an independent consumer through a namespace RoleBinding. "
    "A labeled CRD alone does not contribute rules. Built-in roles, "
    "other aggregate selectors, deployments, and production policy are not tested."
)


def patch(lab, name, changes, *, dry_run=True):
    args = [
        "--as", SUBJECT,
        "patch", "clusterrole", name,
        "--type=merge", "-p", json.dumps(changes, separators=(",", ":")),
    ]
    if dry_run:
        args.append("--dry-run=server")
    args.extend(["-o", "json"])
    return lab.kubectl(*args, allow_failure=True)


def denied(result):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and DENIAL in result.stderr)


def role(lab, name):
    return json.loads(lab.kubectl("get", "clusterrole", name, "-o", "json").stdout)


def has_case_rule(obj):
    for rule in obj.get("rules", []):
        if (rule.get("apiGroups") == [""]
                and rule.get("resources") == ["configmaps"]
                and rule.get("resourceNames") == [CONFIGMAP]
                and rule.get("verbs") == ["get"]):
            return True
    return False


def wait_for_aggregation(lab, timeout=20):
    deadline = time.monotonic() + timeout
    observed = {}
    while time.monotonic() < deadline:
        observed = role(lab, AGGREGATE)
        if has_case_rule(observed):
            return observed
        time.sleep(0.5)
    return observed


def consumer_get(lab, name):
    return lab.kubectl("--as", CONSUMER, "-n", NAMESPACE, "get", "configmap", name,
                       "-o", "jsonpath={.data.marker}", allow_failure=True)


def expect_policy(lab, metadata):
    deadline = time.monotonic() + 20
    while True:
        probe = patch(lab, SOURCE, metadata)
        if denied(probe) or probe.returncode or time.monotonic() >= deadline:
            return probe
        time.sleep(0.5)


def run(lab):
    # Every RBAC object and the one permitted ConfigMap belongs to this case.
    lab.kubectl("-n", NAMESPACE, "apply", "-f", str(HERE / "resources.yaml"))

    lab.kubectl("wait", "--for=condition=Established", "crd/markers.saf-0401-003.example",
                "--timeout=20s", timeout=30)
    before = consumer_get(lab, CONFIGMAP)
    aggregate_empty = not role(lab, AGGREGATE).get("rules", [])
    lab.check("red", "A labeled custom resource definition contributes no RBAC rule",
              aggregate_empty and before.returncode != 0 and "(Forbidden)" in before.stderr,
              {"aggregate_empty": aggregate_empty, "consumer_denied_before_approved_role": before.returncode != 0})

    unapproved = {
        "metadata": {
            "labels": {"saf-k8s.example/aggregate-to-case": "unapproved"},
            "annotations": {"saf-k8s.example/approval": "not-reviewed"},
        }
    }
    red = patch(lab, SOURCE, unapproved)
    lab.check(
        "red",
        "Before admission policy, the exact synthetic subject can submit unapproved aggregation metadata",
        red.returncode == 0,
        red.stderr.strip() or "server dry-run accepted the unapproved metadata change",
    )

    lab.apply(HERE / "admission-policy.yaml")
    rejected_metadata = expect_policy(lab, unapproved)
    lab.check("green", "Policy denies the same subject's unapproved metadata update",
              denied(rejected_metadata), {"exact_policy_denial": denied(rejected_metadata)})

    approved = {
        "metadata": {
            "labels": {"saf-k8s.example/aggregate-to-case": "approved"},
            "annotations": {"saf-k8s.example/approval": "reviewed-2026-11-21"},
        }
    }
    signed_off = patch(lab, SOURCE, approved, dry_run=False)
    if signed_off.returncode == 0:
        accepted = json.loads(signed_off.stdout)
        metadata = accepted.get("metadata", {})
        exact_metadata = (
            metadata.get("labels", {}).get("saf-k8s.example/control-case") == "SAF-K8S-0401-003"
            and metadata.get("labels", {}).get("saf-k8s.example/aggregate-to-case") == "approved"
            and metadata.get("annotations", {}).get("saf-k8s.example/owner") == "SAF-K8S-0401-003"
            and metadata.get("annotations", {}).get("saf-k8s.example/approval") == "reviewed-2026-11-21"
        )
    else:
        exact_metadata = False
    lab.check(
        "positive",
        "Policy accepts the exact signed-off metadata from the exact synthetic subject and owner",
        signed_off.returncode == 0 and exact_metadata,
        signed_off.stderr.strip() or "approved metadata persisted with exact case owner and approval",
    )

    aggregated = wait_for_aggregation(lab)
    lab.check(
        "green",
        "Live aggregation controller matches the approved synthetic source role",
        has_case_rule(aggregated),
        {"aggregate_role": AGGREGATE, "rules": aggregated.get("rules", [])},
    )

    read = consumer_get(lab, CONFIGMAP)
    other = consumer_get(lab, "saf-0401-003-other-fixture")
    restricted = other.returncode != 0 and "(Forbidden)" in other.stderr
    lab.check(
        "positive",
        "The separate consumer reads the exact named fixture through its aggregate binding",
        read.returncode == 0 and read.stdout == "saf-0401-003-owned-fixture" and restricted,
        {"exact_fixture_read": read.returncode == 0, "other_fixture_denied": restricted},
    )

    wrong_owner = patch(lab, SOURCE, {
        "metadata": {"annotations": {"saf-k8s.example/owner": "SAF-K8S-OTHER"}}
    })
    lab.check(
        "green",
        "Policy denies a metadata change that substitutes another synthetic owner",
        denied(wrong_owner),
        wrong_owner.stderr.strip(),
    )

    outside_scope = patch(lab, UNMARKED, {
        "metadata": {"annotations": {"saf-k8s.example/review-note": "synthetic-positive"}}
    })
    lab.check(
        "positive",
        "The same subject can update an unmarked case-owned ClusterRole outside policy scope",
        outside_scope.returncode == 0,
        outside_scope.stderr.strip() or "unmarked ClusterRole update accepted",
    )
