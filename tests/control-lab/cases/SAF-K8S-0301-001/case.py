"""Check explicit PSA namespace levels with harmless admission probes.

The Restricted-specific probe is submitted only with --dry-run=server. The sole
created workload is the compliant Pod in the Restricted namespace.
"""
import json
from pathlib import Path
import time

from fixtures import BUSYBOX_IMAGE

RESTRICTED = "saf-0301-restricted"
BASELINE = "saf-0301-baseline"
SYSTEM = "saf-0301-system"
PSA_VERSION = "v1.36"
BASELINE_REASON = (
    "Synthetic compatibility namespace demonstrates the separately classified "
    "Baseline profile; it is not a production or system namespace."
)
SCOPE = (
    "Namespace classification and exception governance for fixture namespaces, "
    "with pinned Restricted, documented Baseline and Privileged cases, and live PSA."
)


def namespace(name, level, **annotations):
    metadata = {
        "name": name,
        "labels": {
            "pod-security.kubernetes.io/enforce": level,
            "pod-security.kubernetes.io/enforce-version": PSA_VERSION,
            "pod-security.kubernetes.io/audit": level,
            "pod-security.kubernetes.io/audit-version": PSA_VERSION,
            "pod-security.kubernetes.io/warn": level,
            "pod-security.kubernetes.io/warn-version": PSA_VERSION,
        },
    }
    if annotations:
        metadata["annotations"] = annotations
    return {"apiVersion": "v1", "kind": "Namespace", "metadata": metadata}


def probe(name, *, restricted_context):
    security_context = {
        "runAsNonRoot": True,
        "runAsUser": 65534,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    if restricted_context:
        security_context.update({
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
        })
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name},
        "spec": {
            "restartPolicy": "Never",
            "containers": [{
                "name": "probe",
                "image": BUSYBOX_IMAGE,
                "command": ["sh", "-c", "sleep 3600"],
                "securityContext": security_context,
            }],
        },
    }


def server_dry_run(lab, namespace_name, resource, *, allow_failure=False):
    return lab.kubectl(
        "-n", namespace_name, "create", "-f", "-", "--dry-run=server", "-o", "json",
        payload=json.dumps(resource), allow_failure=allow_failure,
    )


def restricted_denial(result):
    text = result.stderr.lower()
    return (
        result.returncode != 0
        and "(forbidden)" in text
        and "podsecurity" in text
        and "allowprivilegeescalation" in text
    )


def namespace_denied(result):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and "use Restricted or record an approved namespace security exception" in result.stderr)


def run(lab):
    baseline = namespace(
        BASELINE,
        "baseline",
        **{"saf-lab.example/exception": BASELINE_REASON},
    )
    lab.kubectl("apply", "-f", "-", payload=json.dumps(baseline))
    initial = namespace(RESTRICTED, "baseline")
    lab.kubectl("apply", "-f", "-", payload=json.dumps(initial))

    for name in (RESTRICTED, BASELINE):
        lab.kubectl("-n", name, "wait", "--for=create", "serviceaccount/default", "--timeout=20s")
    probe_before = probe("restricted-context-probe", restricted_context=False)
    baseline_before = server_dry_run(lab, RESTRICTED, probe_before)
    lab.check(
        "red",
        "Before Restricted assignment, the harmless Restricted-specific probe is admitted",
        baseline_before.returncode == 0,
        "server dry-run accepted in explicitly Baseline-classified namespace",
    )

    unclassified = {"apiVersion": "v1", "kind": "Namespace",
                    "metadata": {"name": "saf-0301-unclassified"}}
    before = lab.create(unclassified, dry_run=True, allow_failure=True)
    lab.check("red", "The API admits an unclassified fixture namespace before policy",
              before.returncode == 0, before.stderr.strip() or "admitted")
    lab.apply(Path(__file__).with_name("namespace-policy.yaml"))
    deadline = time.monotonic() + 15
    while True:
        result = lab.create(unclassified, dry_run=True, allow_failure=True)
        if namespace_denied(result) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check("green", "Governance rejects an unclassified fixture namespace",
              namespace_denied(result), result.stderr.strip())
    for level in ("baseline", "privileged"):
        unapproved = namespace("saf-0301-unapproved-" + level, level)
        denied = lab.create(unapproved, dry_run=True, allow_failure=True)
        lab.check("green", f"Governance rejects {level} without a documented exception",
                  namespace_denied(denied), denied.stderr.strip())

    restricted = namespace(RESTRICTED, "restricted")
    lab.kubectl("apply", "-f", "-", payload=json.dumps(restricted))
    system = namespace(SYSTEM, "privileged", **{
        "saf-lab.example/exception": "Approved synthetic platform exception for the isolation layer."
    })
    lab.kubectl("apply", "-f", "-", payload=json.dumps(system))
    lab.kubectl("-n", SYSTEM, "wait", "--for=create", "serviceaccount/default", "--timeout=20s")
    system_admitted = server_dry_run(lab, SYSTEM, probe_before)
    lab.check("positive", "A documented Privileged namespace admits the harmless dry-run",
              system_admitted.returncode == 0, "server dry-run accepted")
    inventory = json.loads(lab.kubectl("get", "namespaces", "-o", "json").stdout)
    classified = {}
    for item in inventory["items"]:
        labels = item["metadata"].get("labels", {})
        if item["metadata"]["name"] in (RESTRICTED, BASELINE, SYSTEM):
            classified[item["metadata"]["name"]] = {
                "enforce": labels.get("pod-security.kubernetes.io/enforce"),
                "version": labels.get("pod-security.kubernetes.io/enforce-version"),
            }
    expected = {
        RESTRICTED: {"enforce": "restricted", "version": PSA_VERSION},
        BASELINE: {"enforce": "baseline", "version": PSA_VERSION},
        SYSTEM: {"enforce": "privileged", "version": PSA_VERSION},
    }
    lab.check("green", "Synthetic namespace inventory shows explicit pinned PSA levels",
              classified == expected, classified)

    denied = server_dry_run(lab, RESTRICTED, probe_before, allow_failure=True)
    lab.check("green", "Restricted dry-run denies the same probe with a PSA reason",
              restricted_denial(denied), denied.stderr.strip())

    baseline_after = server_dry_run(lab, BASELINE, probe_before)
    reason = json.loads(lab.kubectl("get", "namespace", BASELINE, "-o", "json").stdout)[
        "metadata"]["annotations"]["saf-lab.example/exception"]
    lab.check("positive", "Documented Baseline comparison admits the dry-run probe",
              baseline_after.returncode == 0 and reason == BASELINE_REASON,
              {"admitted": True, "exception": reason})

    compliant = probe("restricted-compliant-ready", restricted_context=True)
    admitted = server_dry_run(lab, RESTRICTED, compliant)
    admitted_pod = json.loads(admitted.stdout)
    observed_context = admitted_pod["spec"]["containers"][0]["securityContext"]
    lab.check("positive", "Compliant Restricted manifest is admitted by server dry-run",
              observed_context == compliant["spec"]["containers"][0]["securityContext"],
              observed_context)
    lab.kubectl("-n", RESTRICTED, "create", "-f", "-", payload=json.dumps(compliant))
    lab.kubectl("-n", RESTRICTED, "wait", "--for=condition=Ready",
                "pod/restricted-compliant-ready", "--timeout=95s", timeout=105)
    lab.check("positive", "Compliant Pod reaches Ready in the Restricted namespace", True, "Ready")
