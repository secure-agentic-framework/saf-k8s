"""Exercise isolated recovery when an ordinary bound identity becomes unavailable."""
import json
import subprocess
import time

NS = "saf-test"
RBAC = "rbac.authorization.k8s.io/v1"
NORMAL = "fixture-routine-reader"
RECOVERY = "fixture-recovery-reader"
REFERENCE = "fixture-routine-credential-anchor"
READ = "fixture-approved-exercise-record"
OTHER = "fixture-unrelated-record"
MARKER = "owned-recovery-exercise"
SCOPE = (
    "The actual Kubernetes API verifies a narrowly scoped routine credential before and "
    "after its own bound input is removed. An independently provisioned fixture credential "
    "can perform only the approved read. Reissuing the routine path restores normal "
    "operation. This tests a defined local credential-unavailability scenario and selected "
    "authorization; external provider dependencies, production privileges and emergency "
    "governance require independent real-site evidence."
)


def put(lab, kind, name, api="v1", **fields):
    return lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})


def approved(lab, account):
    put(lab, "RoleBinding", account, RBAC,
        roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": READ},
        subjects=[{"kind": "ServiceAccount", "name": account, "namespace": NS}])


def identity(lab, account, label, reference=False):
    baseline = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                "--namespace", NS, "create", "token", account, "--duration=10m"]
    if reference:
        baseline += ["--bound-object-kind=Secret", "--bound-object-name", REFERENCE]
    token = subprocess.run(baseline, capture_output=True, text=True, timeout=20, env=lab.env)
    if token.returncode or len(token.stdout.strip().split(".")) != 3:
        lab.block("Could not issue the temporary exercise context")
    root = lab.kubeconfig.parent
    token_file = root / f"{label}.token"
    token_file.touch(mode=0o600, exist_ok=False)
    token_file.write_text(token.stdout.strip())
    config = root / f"{label}.json"
    config.touch(mode=0o600, exist_ok=False)
    cluster = {
        field: lab.kubectl("config", "view", "--minify", "--raw", "-o",
                           "jsonpath={.clusters[0].cluster." + field + "}").stdout.strip()
        for field in ("server", "certificate-authority-data")
    }
    config.write_text(json.dumps({
        "apiVersion": "v1", "kind": "Config", "current-context": "fixture",
        "clusters": [{"name": "fixture", "cluster": cluster}],
        "users": [{"name": "fixture", "user": {"tokenFile": str(token_file)}}],
        "contexts": [{"name": "fixture", "context": {"cluster": "fixture", "user": "fixture"}}],
    }))
    return config


def read(lab, config, name=READ):
    result = lab.command("kubectl", "--kubeconfig", str(config), "--context", "fixture",
                         "--request-timeout=6s", "get",
                         f"--raw=/api/v1/namespaces/{NS}/configmaps/{name}",
                         allow_failure=True, timeout=12)
    if result.returncode == 0 and json.loads(result.stdout)["data"]["marker"] == MARKER:
        return "allowed"
    if "Unauthorized" in result.stderr or "logged in" in result.stderr:
        return "unauthenticated"
    if "(Forbidden)" in result.stderr:
        return "forbidden"
    lab.block("The named fixture read returned an unrelated result")


def await_read(lab, config, expected):
    grace = 75 if expected == "unauthenticated" else 8
    deadline = time.monotonic() + grace
    while True:
        observed = read(lab, config)
        if observed == expected or time.monotonic() >= deadline:
            return observed
        time.sleep(2)


def run(lab):
    for account in (NORMAL, RECOVERY):
        put(lab, "ServiceAccount", account, automountServiceAccountToken=False)
    for item in (READ, OTHER):
        put(lab, "ConfigMap", item, data={"marker": MARKER})
    put(lab, "Role", READ, RBAC, rules=[{
        "apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"], "resourceNames": [READ],
    }])
    anchor = put(lab, "Secret", REFERENCE)
    approved(lab, NORMAL)
    original = identity(lab, NORMAL, "original", reference=True)
    fallback = identity(lab, RECOVERY, "fallback")
    baseline = {"routine_context_works": await_read(lab, original, "allowed") == "allowed",
                "separate_unapproved_context_denied": read(lab, fallback) == "forbidden"}
    lab.check("red", "Normal access and independent recovery authorization have different prerequisites",
              all(baseline.values()), baseline)

    approved(lab, RECOVERY)
    if await_read(lab, fallback, "allowed") != "allowed":
        lab.block("The approved recovery binding did not become effective")
    lab.kubectl("delete", "secret", REFERENCE, "--wait=true")
    recovery = {"routine_context_unavailable": await_read(lab, original, "unauthenticated") == "unauthenticated",
                "already_approved_recovery_context_reads": read(lab, fallback) == "allowed",
                "recovery_context_cannot_read_other_scope": read(lab, fallback, OTHER) == "forbidden"}
    lab.check("green", "Actual routine authentication becomes unavailable and the approved recovery read still works",
              all(recovery.values()), recovery)

    replacement = put(lab, "Secret", REFERENCE)
    restored = identity(lab, NORMAL, "new-routine", reference=True)
    lab.kubectl("delete", "rolebinding", RECOVERY, "--wait=true")
    final = {"replacement_authority_object_has_new_uid": replacement["metadata"]["uid"] != anchor["metadata"]["uid"],
             "new_routine_context_restores_operation": read(lab, restored) == "allowed",
             "old_routine_context_stays_invalid": read(lab, original) == "unauthenticated",
             "withdrawal_removes_temporary_recovery_access": await_read(lab, fallback, "forbidden") == "forbidden"}
    lab.check("positive", "Routine operation is restored and the temporary access is removed",
              all(final.values()), final)
    (lab.evidence / "recovery-exercise-observations.json").write_text(json.dumps({
        "scenario": "owned bound credential becomes unavailable",
        "before": baseline, "during": recovery, "after": final,
    }, indent=2) + "\n")
