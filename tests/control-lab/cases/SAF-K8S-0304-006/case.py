"""Dry-run Pod admission checks for a hostPath denial control."""
import json
from pathlib import Path

HERE = Path(__file__).parent
FIXTURES = json.loads((HERE / "fixtures.json").read_text())
NAMESPACE = "saf-0304-hostpath-policy"
POLICY_VERSION = "v1.36"
DENIAL_MARKER = "violates PodSecurity"
SCOPE = (
    "Server-side dry-run admission of one synthetic hostPath Pod under an "
    "unlabeled namespace and the same namespace enforcing Kubernetes v1.36 "
    "Pod Security Admission Baseline, plus a permitted emptyDir Pod dry-run. "
    "No Pod is persisted or run. No host path is created, mounted, or read. "
    "Does not test production-wide namespace coverage, admission configuration, "
    "policy-engine exceptions, exception-register governance, or audit delivery."
)


def server_dry_run(lab, pod):
    """Submit only a server-side dry-run CREATE request for a fixture Pod."""
    return lab.kubectl(
        "-n", NAMESPACE,
        "create", "-f", "-", "--dry-run=server", "-o", "json",
        payload=json.dumps(pod), allow_failure=True,
    )


def denied_for_hostpath(result):
    message = result.stderr
    return (
        result.returncode != 0
        and "(Forbidden)" in message
        and DENIAL_MARKER in message
        and f"baseline:{POLICY_VERSION}" in message
        and "hostPath volumes" in message
    )


def admitted_pod(result, expected_name):
    if result.returncode != 0:
        return False, result.stderr.strip()
    try:
        admitted = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        return False, f"server dry-run returned invalid JSON: {error}"
    return (
        admitted.get("kind") == "Pod"
        and admitted.get("metadata", {}).get("name") == expected_name,
        {"kind": admitted.get("kind"), "name": admitted.get("metadata", {}).get("name")},
    )


def run(lab):
    hostpath = FIXTURES["hostpath_candidate"]
    permitted = FIXTURES["permitted_emptydir_candidate"]

    # Both probes are dry-run CREATE requests. The initial namespace is created
    # without Pod Security labels to establish that the API accepts the same
    # harmless hostPath-shaped Pod before the intended admission policy applies.
    lab.kubectl("create", "namespace", NAMESPACE)
    red = server_dry_run(lab, hostpath)
    red_ok, red_observed = admitted_pod(red, hostpath["metadata"]["name"])
    lab.check(
        "red",
        "Unlabeled fixture namespace admits the hostPath-shaped server dry-run",
        red_ok,
        red_observed,
    )

    lab.kubectl(
        "label", "namespace", NAMESPACE,
        "pod-security.kubernetes.io/enforce=baseline",
        f"pod-security.kubernetes.io/enforce-version={POLICY_VERSION}",
        "pod-security.kubernetes.io/audit=baseline",
        f"pod-security.kubernetes.io/audit-version={POLICY_VERSION}",
        "pod-security.kubernetes.io/warn=baseline",
        f"pod-security.kubernetes.io/warn-version={POLICY_VERSION}",
    )
    green = server_dry_run(lab, hostpath)
    lab.check(
        "green",
        "Pinned Baseline denies the same hostPath dry-run for the hostPath reason",
        denied_for_hostpath(green),
        green.stderr.strip(),
    )

    positive = server_dry_run(lab, permitted)
    positive_ok, positive_observed = admitted_pod(
        positive, permitted["metadata"]["name"]
    )
    lab.check(
        "positive",
        "Pinned Baseline admits a harmless non-hostPath emptyDir dry-run",
        positive_ok,
        positive_observed,
    )
    persisted = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pods", "-o", "json").stdout)["items"]
    lab.check("positive", "The admission probes leave no Pods in the fixture namespace",
              not persisted, {"persisted_pods": len(persisted)})
