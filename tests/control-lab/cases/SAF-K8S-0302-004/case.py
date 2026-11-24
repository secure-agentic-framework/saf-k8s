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
    "non-persisted hostNetwork-only synthetic exception behind a test-specific, "
    "revocable namespace RBAC grant. The case verifies withdrawal and ordinary "
    "Restricted admission afterward. One ordinary isolated Pod is run to Ready. "
    "No host-namespace Pod is created or run; host state and sensitive endpoints "
    "are never queried."
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


def observe(lab, name, result):
    """Keep raw, non-secret API observations separate from portable verdicts."""
    record = {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    (lab.evidence / f"{name}.raw.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def check_observed(lab, phase, title, name, result, passed, detail):
    observe(lab, name, result)
    # Keep check text deterministic; cluster-specific API messages live in evidence.
    lab.check(phase, title, passed, detail)


def psa_denied(result, level, field):
    expected = f'{field}=true'
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and DENIAL in result.stderr and f'{level}:{PIN}' in result.stderr
            and expected in result.stderr)


def policy_denied(result):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and EXCEPTION_POLICY_MESSAGE in result.stderr)


def authorization_denied(result):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and 'cannot create resource "pods"' in result.stderr)


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
    before_grant = lab.kubectl("auth", "can-i", "create", "pods", "-n", EXCEPTION,
                               f"--as={APPROVED_SUBMITTER}", allow_failure=True)
    check_observed(lab, "red", "The proposed exception submitter starts without Pod-create authorization",
                   "before-approval-rbac", before_grant, before_grant.stdout.strip() == "no",
                   "expected absent test-specific grant")
    lab.kubectl("-n", EXCEPTION, "create", "rolebinding", "synthetic-probe-creator",
                "--role=synthetic-probe-creator", f"--user={APPROVED_SUBMITTER}")

    # Approval is an explicit, owner-created namespaced grant. The VAP still
    # constrains the exact Pod shape; RBAC supplies an independently revocable
    # create boundary. No clock or simulated expiry is used.
    grant = lab.kubectl("auth", "can-i", "create", "pods", "-n", EXCEPTION,
                        f"--as={APPROVED_SUBMITTER}", allow_failure=True)
    check_observed(lab, "green", "Owner approval grants only the test submitter Pod-create authorization",
                   "approval-rbac", grant, grant.stdout.strip() == "yes",
                   "expected test-specific create grant observed")

    # Red phase: prove each distinct forbidden shape reaches Pod admission while
    # the synthetic namespace has no enforce label. These requests cannot persist.
    for field in ("hostPID", "hostIPC", "hostNetwork"):
        result = server_dry_run(lab, candidate("saf-test", f"red-{field.lower()}", field))
        check_observed(lab, "red", f"Unenforced API accepts inert {field} dry-run",
                       f"red-{field.lower()}", result, result.returncode == 0,
                       "expected server-side dry-run admission outcome observed")

    label_psa(lab, BASELINE, "baseline")
    label_psa(lab, RESTRICTED, "restricted")
    for level, namespace in (("baseline", BASELINE), ("restricted", RESTRICTED)):
        for field in ("hostPID", "hostIPC", "hostNetwork"):
            result = server_dry_run(lab, candidate(namespace, f"deny-{field.lower()}", field))
            check_observed(lab, "green", f"Pinned PSA {level} denies {field} independently",
                           f"{level}-{field.lower()}", result, psa_denied(result, level, field),
                           "expected pinned Pod Security Admission outcome observed")

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
    check_observed(lab, "green", "Exception policy denies the exact shape under wrong identity",
                   "exception-wrong-identity", wrong_identity, policy_denied(wrong_identity),
                   "expected exception policy denial observed")

    host_pid = server_dry_run(lab, approved_exception(field="hostPID"), APPROVED_SUBMITTER)
    check_observed(lab, "green", "Exception rule never permits hostPID", "exception-hostpid",
                   host_pid, policy_denied(host_pid), "expected exception policy denial observed")
    host_ipc = server_dry_run(lab, approved_exception(field="hostIPC"), APPROVED_SUBMITTER)
    check_observed(lab, "green", "Exception rule never permits hostIPC", "exception-hostipc",
                   host_ipc, policy_denied(host_ipc), "expected exception policy denial observed")

    wrong_name = server_dry_run(lab, approved_exception(name="near-match-hostnetwork"), APPROVED_SUBMITTER)
    check_observed(lab, "green", "Exception rule denies a different named synthetic workload",
                   "exception-wrong-name", wrong_name, policy_denied(wrong_name),
                   "expected exception policy denial observed")
    wrong_config = server_dry_run(lab, approved_exception(config="unapproved-config"), APPROVED_SUBMITTER)
    check_observed(lab, "green", "Exception rule denies an unapproved synthetic configuration",
                   "exception-wrong-config", wrong_config, policy_denied(wrong_config),
                   "expected exception policy denial observed")

    # Namespace negative: same approved identity/name/config submitted in a
    # distinct pinned Baseline namespace is rejected by PSA before policy scope.
    wrong_namespace = server_dry_run(lab, approved_exception(namespace=BASELINE))
    check_observed(lab, "green", "Exception-shaped hostNetwork request is denied outside exception namespace",
                   "exception-wrong-namespace", wrong_namespace,
                   psa_denied(wrong_namespace, "baseline", "hostNetwork"),
                   "expected pinned Pod Security Admission outcome observed")

    wrong_actor = server_dry_run(lab, approved_exception())
    check_observed(lab, "green", "Exception-shaped request is denied for a different authenticated submitter",
                   "exception-wrong-actor", wrong_actor, policy_denied(wrong_actor),
                   "expected exception policy denial observed")
    allowed = server_dry_run(lab, approved_exception(), APPROVED_SUBMITTER)
    check_observed(lab, "positive", "Only exact synthetic hostNetwork exception passes server dry-run",
                   "exception-approved", allowed, allowed.returncode == 0,
                   "expected server-side dry-run admission outcome observed")

    # Withdraw the owner-created grant. Both the RBAC authorization check and
    # the same exceptional dry-run must fail, while ordinary Restricted work
    # remains admissible. The hostNetwork request is still dry-run only.
    lab.kubectl("-n", EXCEPTION, "delete", "rolebinding", "synthetic-probe-creator")
    revoked = lab.kubectl("auth", "can-i", "create", "pods", "-n", EXCEPTION,
                          f"--as={APPROVED_SUBMITTER}", allow_failure=True)
    check_observed(lab, "green", "Withdrawing the owner grant removes test submitter Pod-create authorization",
                   "revocation-rbac", revoked, revoked.stdout.strip() == "no",
                   "expected revoked test-specific authorization observed")
    after_withdrawal = server_dry_run(lab, approved_exception(), APPROVED_SUBMITTER)
    observe(lab, "exception-after-withdrawal", after_withdrawal)
    lab.check("green", "Same hostNetwork exception is denied after owner approval withdrawal",
              authorization_denied(after_withdrawal),
              "expected RBAC denial after approval withdrawal observed")
    ordinary_dry_run = server_dry_run(lab, candidate(RESTRICTED, "ordinary-after-withdrawal"))
    check_observed(lab, "positive", "Ordinary isolated fixture remains admissible after exception withdrawal",
                   "ordinary-after-withdrawal", ordinary_dry_run,
                   ordinary_dry_run.returncode == 0,
                   "expected ordinary Restricted admission outcome observed")

    # A normal isolated workload is the only Pod persisted by this case.
    normal = pod("saf-0302-isolated-ready", [container("probe")])
    normal["metadata"]["namespace"] = BASELINE
    lab.kubectl("-n", BASELINE, "create", "-f", "-", payload=json.dumps(normal))
    lab.kubectl("wait", "--for=condition=Ready",
                f"pod/{normal['metadata']['name']}", "--namespace", BASELINE,
                "--timeout=95s", timeout=105)
    lab.check("positive", "Normal isolated workload reaches Ready",
              True, "Ready condition observed")

    observations = {f.name.removesuffix(".raw.json"): json.loads(f.read_text())
                    for f in sorted(lab.evidence.glob("*.raw.json"))}
    (lab.evidence / "host-namespace-observations.json").write_text(
        json.dumps(observations, indent=2, sort_keys=True) + "\n")
