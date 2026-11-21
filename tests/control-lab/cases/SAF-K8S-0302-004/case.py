"""Host namespace admission probes with an inert, tightly scoped exception."""
import json
from pathlib import Path
import time

from fixtures import container, pod

HERE = Path(__file__).parent
PIN = "v1.36"
BASELINE = "saf-0302-baseline"
RESTRICTED = "saf-0302-restricted"
EXCEPTION = "saf-0302-hostnetwork-exception"
APPROVED_NAME = "saf-0302-approved-hostnetwork-probe"
APPROVED_IDENTITY = "saf-0302-approved"
APPROVED_SUBMITTER = "saf-0302-operator"
APPROVED_CONFIG = "synthetic-hostnetwork-probe-v1"
EXCEPTION_POLICY_MESSAGE = "host namespace use is limited to the exact synthetic hostNetwork probe"
DENIAL = "violates PodSecurity"
SCOPE = (
    "Server-side dry-run admission of hostPID, hostIPC, and hostNetwork independently "
    "under namespace-enforced, Kubernetes-v1.36-pinned Pod Security Admission Baseline "
    "and Restricted. A separate ValidatingAdmissionPolicy demonstrates one exact, "
    "non-persisted hostNetwork-only synthetic exception. One ordinary isolated Pod is "
    "run to Ready. No host-namespace Pod is created or run; host state and sensitive "
    "endpoints are never queried."
)


def candidate(namespace, name, field=None):
    obj = pod(name, [container("probe")])
    obj["metadata"]["namespace"] = namespace
    if field is not None:
        obj["spec"][field] = True
    return obj


def approved_exception(*, namespace=EXCEPTION, identity=APPROVED_IDENTITY,
                       name=APPROVED_NAME, config=APPROVED_CONFIG, field="hostNetwork"):
    obj = candidate(namespace, name, field)
    obj["spec"]["serviceAccountName"] = identity
    obj["spec"]["automountServiceAccountToken"] = False
    obj["spec"]["containers"][0]["securityContext"]["readOnlyRootFilesystem"] = True
    obj["metadata"]["annotations"] = {"saf-k8s.example/hostns-exception": config}
    return obj


def server_dry_run(lab, obj, submitter=None):
    # All Pods carrying host namespace flags, including red and exception arms,
    # are API-server dry-runs. This helper is the only Pod submission path here.
    actor = ["--as", submitter] if submitter else []
    return lab.kubectl(*actor, "-n", obj["metadata"]["namespace"], "create", "-f", "-", "--dry-run=server", "-o", "json",
                       payload=json.dumps(obj), allow_failure=True)


def psa_denied(result, level, field):
    expected = f'{field}=true'
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and DENIAL in result.stderr and f'{level}:{PIN}' in result.stderr
            and expected in result.stderr)


def policy_denied(result):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and EXCEPTION_POLICY_MESSAGE in result.stderr)


def label_psa(lab, namespace, level):
    lab.kubectl("label", "namespace", namespace,
                f"pod-security.kubernetes.io/enforce={level}",
                f"pod-security.kubernetes.io/enforce-version={PIN}",
                f"pod-security.kubernetes.io/audit={level}",
                f"pod-security.kubernetes.io/audit-version={PIN}",
                f"pod-security.kubernetes.io/warn={level}",
                f"pod-security.kubernetes.io/warn-version={PIN}", "--overwrite")


def run(lab):
    # Create only namespaced fixtures owned by this case. The runner's saf-test
    # namespace is used for the pre-enforcement, inert reachability challenge.
    for namespace in (BASELINE, RESTRICTED, EXCEPTION, "saf-0302-other"):
        lab.kubectl("create", "namespace", namespace)
    for namespace in (BASELINE, EXCEPTION):
        lab.kubectl("-n", namespace, "create", "serviceaccount", APPROVED_IDENTITY)
    lab.kubectl("-n", EXCEPTION, "create", "role", "synthetic-probe-creator",
                "--verb=create", "--resource=pods")
    lab.kubectl("-n", EXCEPTION, "create", "rolebinding", "synthetic-probe-creator",
                "--role=synthetic-probe-creator", f"--user={APPROVED_SUBMITTER}")

    # Red phase: prove each distinct forbidden shape reaches Pod admission while
    # the synthetic namespace has no enforce label. These requests cannot persist.
    for field in ("hostPID", "hostIPC", "hostNetwork"):
        result = server_dry_run(lab, candidate("saf-test", f"red-{field.lower()}", field))
        lab.check("red", f"Unenforced API accepts inert {field} dry-run",
                  result.returncode == 0, result.stderr.strip() or "server dry-run admitted")

    label_psa(lab, BASELINE, "baseline")
    label_psa(lab, RESTRICTED, "restricted")
    for level, namespace in (("baseline", BASELINE), ("restricted", RESTRICTED)):
        for field in ("hostPID", "hostIPC", "hostNetwork"):
            result = server_dry_run(lab, candidate(namespace, f"deny-{field.lower()}", field))
            lab.check("green", f"Pinned PSA {level} denies {field} independently",
                      psa_denied(result, level, field), result.stderr.strip())

    # The exception namespace is explicit and uses privileged PSA only so a
    # separate admission rule can evaluate the narrow policy exception.
    lab.kubectl("label", "namespace", EXCEPTION,
                "saf-k8s.example/hostns-exception=approved-synthetic",
                "pod-security.kubernetes.io/enforce=privileged",
                f"pod-security.kubernetes.io/enforce-version={PIN}",
                "pod-security.kubernetes.io/audit=privileged",
                f"pod-security.kubernetes.io/audit-version={PIN}",
                "pod-security.kubernetes.io/warn=privileged",
                f"pod-security.kubernetes.io/warn-version={PIN}", "--overwrite")
    lab.apply(HERE / "admission-policy.yaml")

    # Wait for the exact policy denial before evaluating the positive exception;
    # a pre-activation API acceptance cannot count as policy evidence.
    wrong_identity = server_dry_run(lab, approved_exception(identity="default"), APPROVED_SUBMITTER)
    deadline = time.monotonic() + 15
    while not policy_denied(wrong_identity) and time.monotonic() < deadline:
        time.sleep(0.5)
        wrong_identity = server_dry_run(lab, approved_exception(identity="default"), APPROVED_SUBMITTER)
    lab.check("green", "Exception policy denies the exact shape under wrong identity",
              policy_denied(wrong_identity), wrong_identity.stderr.strip())

    host_pid = server_dry_run(lab, approved_exception(field="hostPID"), APPROVED_SUBMITTER)
    lab.check("green", "Exception rule never permits hostPID",
              policy_denied(host_pid), host_pid.stderr.strip())
    host_ipc = server_dry_run(lab, approved_exception(field="hostIPC"), APPROVED_SUBMITTER)
    lab.check("green", "Exception rule never permits hostIPC",
              policy_denied(host_ipc), host_ipc.stderr.strip())

    wrong_name = server_dry_run(lab, approved_exception(name="near-match-hostnetwork"), APPROVED_SUBMITTER)
    lab.check("green", "Exception rule denies a different named synthetic workload",
              policy_denied(wrong_name), wrong_name.stderr.strip())
    wrong_config = server_dry_run(lab, approved_exception(config="unapproved-config"), APPROVED_SUBMITTER)
    lab.check("green", "Exception rule denies an unapproved synthetic configuration",
              policy_denied(wrong_config), wrong_config.stderr.strip())

    # Namespace negative: same approved identity/name/config submitted in a
    # distinct pinned Baseline namespace is rejected by PSA before policy scope.
    wrong_namespace = server_dry_run(lab, approved_exception(namespace=BASELINE))
    lab.check("green", "Exception-shaped hostNetwork request is denied outside exception namespace",
              psa_denied(wrong_namespace, "baseline", "hostNetwork"),
              wrong_namespace.stderr.strip())

    wrong_actor = server_dry_run(lab, approved_exception())
    lab.check("green", "Exception-shaped request is denied for a different authenticated submitter",
              policy_denied(wrong_actor), wrong_actor.stderr.strip())
    allowed = server_dry_run(lab, approved_exception(), APPROVED_SUBMITTER)
    lab.check("positive", "Only exact synthetic hostNetwork exception passes server dry-run",
              allowed.returncode == 0, allowed.stderr.strip() or "server dry-run admitted")

    # A normal isolated workload is the only Pod persisted by this case.
    normal = pod("saf-0302-isolated-ready", [container("probe")])
    normal["metadata"]["namespace"] = BASELINE
    lab.kubectl("-n", BASELINE, "create", "-f", "-", payload=json.dumps(normal))
    lab.kubectl("wait", "--for=condition=Ready",
                f"pod/{normal['metadata']['name']}", "--namespace", BASELINE,
                "--timeout=95s", timeout=105)
    lab.check("positive", "Normal isolated workload reaches Ready",
              True, "Ready condition observed")
