"""Test a governed suspension and readmission against a real member API."""
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import time
from urllib.parse import urlsplit

from fixtures import BUSYBOX_IMAGE

HERE = Path(__file__).resolve().parent
NS = "saf-test"
RBAC = "rbac.authorization.k8s.io/v1"
ROLE = "fixture-placement"
MEMBER = "fixture-federation-member"
INITIAL = "fixture-workload-original"
SUSPENDED = "fixture-workload-suspended"
RESTORED = "fixture-workload-restored"
OPERATOR = "fixture-platform-operator"
APPROVER = "fixture-security-reviewer"
SIGNAL_SOURCE = "fixture-isolation-signal-source"
SIGNAL_OTHER = "fixture-unapproved-signal-source"
SIGNAL_AUDIENCE = "fixture-federation-isolation-signal"
HOLD = "fixture-federation-hold"
APPROVAL = "fixture-readmission-approval"
SCOPE = (
    "An isolated Kind hub and actual second member cluster. Kubernetes TokenReview attributes a "
    "fixed synthetic isolation signal to an exact fixture service account; a benign comparator "
    "remains placeable. A harmless operator suspension revokes "
    "new placement authorization on the member and drains the specific fixture workload. A distinct, "
    "scoped reviewer approves the exact member UID and suspension marker. The member stays denied "
    "until the approval is accepted, after which a new prepared fixture workload becomes ready."
)


def helper():
    spec = importlib.util.spec_from_file_location(
        "saf_federation_member", HERE.parent / "SAF-K8S-0910-029" / "case.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("The published owned-member helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def row(kind, name, api="v1", **fields):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields}


def identity(name):
    return f"system:serviceaccount:{NS}:{name}"


def grant(lab, actor, record):
    lab.create(row("ServiceAccount", actor, automountServiceAccountToken=False))
    lab.create(row("Role", actor, RBAC, rules=[{
        "apiGroups": [""], "resources": ["configmaps"], "resourceNames": [record],
        "verbs": ["get", "patch"],
    }]))
    lab.create(row("RoleBinding", actor, RBAC, roleRef={
        "apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": actor,
    }, subjects=[{"kind": "ServiceAccount", "name": actor, "namespace": NS}]))


def disposition(lab, record, actor, value):
    return lab.kubectl("patch", "configmap", record, "--type=merge", "-p",
                        json.dumps({"data": {"claim.json": json.dumps(value)}}),
                        f"--as={identity(actor)}", allow_failure=True)



def private_kubectl(lab, *args, payload=None):
    """Run credential-bearing calls without retaining stdout/stderr in the lab transcript."""
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
               "--namespace", NS, "--request-timeout=12s", *args]
    try:
        result = subprocess.run(command, input=payload, text=True, capture_output=True,
                                env=lab.env, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("A private signal-identity API request did not complete")
    if result.returncode:
        lab.block("A private signal-identity API request failed")
    return result.stdout


def signal_token(lab, account):
    body = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest",
            "spec": {"audiences": [SIGNAL_AUDIENCE], "expirationSeconds": 600}}
    raw = private_kubectl(lab, "create", f"--raw=/api/v1/namespaces/{NS}/serviceaccounts/{account}/token",
                          "-f", "-", payload=json.dumps(body))
    return json.loads(raw)["status"]["token"]


def review_signal_token(lab, token):
    body = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
            "spec": {"token": token, "audiences": [SIGNAL_AUDIENCE]}}
    status = json.loads(private_kubectl(lab, "create", "--raw=/apis/authentication.k8s.io/v1/tokenreviews",
                                        "-f", "-", payload=json.dumps(body))).get("status", {})
    return (status.get("authenticated") is True,
            status.get("user", {}).get("username"),
            SIGNAL_AUDIENCE in status.get("audiences", []))


def accept_signal(lab, token, signal, member_uid):
    auth = review_signal_token(lab, token)
    source = f"system:serviceaccount:{NS}:{SIGNAL_SOURCE}"
    exact_shape = (set(signal) == {"signal_id", "member_uid", "decision", "ticket"}
                   and signal.get("signal_id") == "fixture-signal-001"
                   and signal.get("member_uid") == member_uid
                   and signal.get("decision") in {"clear", "isolate"}
                   and signal.get("ticket") == "fixture-event-001")
    return auth[0] and auth[1] == source and auth[2] and exact_shape


def query(lab, record):
    raw = lab.kubectl("get", "configmap", record, "-o", "json").stdout
    return json.loads(json.loads(raw)["data"]["claim.json"])


def deployment(name):
    labels = {"app": name, "saf-fixture": "federation-placement"}
    return row("Deployment", name, "apps/v1", spec={
        "replicas": 1, "selector": {"matchLabels": labels},
        "template": {"metadata": {"labels": labels},
                     "spec": {"automountServiceAccountToken": False, "terminationGracePeriodSeconds": 3,
                              "containers": [{"name": "fixture", "image": BUSYBOX_IMAGE,
                                              "command": ["sleep", "3600"]}]}},
    })


def place(target, name):
    result = target.kubectl("create", "-f", "-", "-o", "name", actor=MEMBER,
                            payload=json.dumps(deployment(name)), allow_failure=True)
    if result.returncode == 0:
        return "placed"
    return "forbidden" if "Forbidden" in result.stderr else "unexpected-error"


def ready(lab, target, name):
    lab.command(*target.args("rollout", "status", "deployment/" + name,
                             "--timeout=75s", "--request-timeout=80s"), timeout=85)


def suspension(lab, target):
    target.kubectl("delete", "rolebinding", ROLE)
    target.kubectl("scale", "deployment", INITIAL, "--replicas=0")
    deadline = time.monotonic() + 30
    while True:
        owned = json.loads(target.kubectl("get", "pods", "-l", f"app={INITIAL}", "-o", "json").stdout)["items"]
        if not owned:
            return True
        if time.monotonic() >= deadline:
            lab.block("An isolated fixture Pod remained after the governed drain")
        time.sleep(0.25)


def run(lab):
    common = helper()
    with common.second_cluster(lab) as target:
        endpoint = json.loads(target.kubectl("config", "view", "--minify", "-o", "json").stdout
                              )["clusters"][0]["cluster"]["server"]
        member_address = lab.command("docker", "port", target.name + "-control-plane", "6443/tcp").stdout.strip()
        if not re.fullmatch(r"127\.0\.0\.1:\d+", member_address) or urlsplit(endpoint).netloc != member_address:
            lab.block("The member context did not match the separately owned loopback endpoint")
        uid = target.kubectl("get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}").stdout.strip()
        hub_uid = lab.kubectl("get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}").stdout.strip()
        if not uid or uid == hub_uid:
            lab.block("Hub and member must be distinct Kubernetes clusters")
        target.create("ServiceAccount", MEMBER, automountServiceAccountToken=False)
        target.create("Role", ROLE, RBAC, rules=[{
            "apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["create"],
        }])
        common.binding(target, ROLE, ROLE, MEMBER)
        grant(lab, OPERATOR, HOLD)
        grant(lab, APPROVER, APPROVAL)
        for source in (SIGNAL_SOURCE, SIGNAL_OTHER):
            lab.create(row("ServiceAccount", source, automountServiceAccountToken=False))
        for record in (HOLD, APPROVAL):
            lab.create(row("ConfigMap", record, data={"claim.json": "{}"}))

        # Signals are fixed harmless fixture metadata. The bearer stays in memory and is never
        # passed through lab.command, printed, or included in an evidence file.
        trusted_signal_token = signal_token(lab, SIGNAL_SOURCE)
        other_signal_token = signal_token(lab, SIGNAL_OTHER)
        clear = {"signal_id": "fixture-signal-001", "member_uid": uid,
                 "decision": "clear", "ticket": "fixture-event-001"}
        exact_clear = accept_signal(lab, trusted_signal_token, clear, uid)
        clear_noop = exact_clear and query(lab, HOLD) == {} and place(target, "fixture-workload-clear") == "placed"
        if clear_noop:
            ready(lab, target, "fixture-workload-clear")
            target.kubectl("delete", "deployment", "fixture-workload-clear", "--wait=true")
        rejected_untrusted = not accept_signal(lab, other_signal_token,
            {**clear, "decision": "isolate"}, uid)
        wrong_member = not accept_signal(lab, trusted_signal_token,
            {**clear, "member_uid": "fixture-other-member-uid", "decision": "isolate"}, uid)
        unchanged = query(lab, HOLD) == {} and query(lab, APPROVAL) == {}
        signal_observation = {"trusted_source_clear_accepted": exact_clear,
                              "clear_left_hold_empty_and_comparator_ready": clear_noop,
                              "other_source_isolate_refused": rejected_untrusted,
                              "wrong_member_isolate_refused": wrong_member,
                              "hold_and_approval_unchanged_after_refusals": unchanged,
                              "token_material_recorded": False}
        lab.check("signal", "Authenticated clear signal is a no-op; unapproved or wrong-member signals cannot change placement state",
                  exact_clear and clear_noop and rejected_untrusted and wrong_member and unchanged,
                  signal_observation)
        # Later records remain in local scope only; do not retain token objects.
        del trusted_signal_token, other_signal_token

        baseline = place(target, INITIAL)
        if baseline == "placed":
            ready(lab, target, INITIAL)
        original = target.kubectl("get", "deployment", INITIAL, "-o", "jsonpath={.status.readyReplicas}").stdout
        red = {"member_placement_succeeds_before_isolation": baseline == "placed",
               "initial_workload_is_running": original.strip() == "1"}
        lab.check("red", "An active member receives and runs the owned fixture workload", all(red.values()), red)

        hold = {"member_uid": uid, "decision": "suspended", "ticket": "fixture-event-001"}
        isolation_signal = {"signal_id": "fixture-signal-001", "member_uid": uid,
                            "decision": "isolate", "ticket": "fixture-event-001"}
        signal_credential = signal_token(lab, SIGNAL_SOURCE)
        signal_authorized = accept_signal(lab, signal_credential, isolation_signal, uid)
        del signal_credential
        if not signal_authorized:
            lab.block("The exact fixture isolation signal lacked an authenticated approved source")
        requested = disposition(lab, HOLD, OPERATOR, hold)
        if requested.returncode or query(lab, HOLD) != hold:
            lab.block("The scoped operator could not persist the exact suspension")
        drained = suspension(lab, target)
        blocked = place(target, SUSPENDED)
        valid = {"member_uid": uid, "decision": "approved", "ticket": hold["ticket"],
                 "reviewer": APPROVER}
        unapproved = disposition(lab, APPROVAL, OPERATOR, valid)
        remains_held = query(lab, APPROVAL) == {} and place(target, SUSPENDED) == "forbidden"
        green = {
            "new_placement_is_denied": blocked == "forbidden",
            "existing_fixture_is_drained": drained,
            "operator_cannot_write_the_independent_approval": unapproved.returncode != 0
            and "Forbidden" in unapproved.stderr,
            "without_approval_placement_stays_suspended": remains_held,
        }
        lab.check("green", "Isolation revokes placement, drains the workload and requires separate approval",
                  all(green.values()), green)
        reviewed = disposition(lab, APPROVAL, APPROVER, valid)
        current = query(lab, APPROVAL)
        if reviewed.returncode or current != valid or current["reviewer"] == OPERATOR:
            lab.block("Readmission requires the exact member and suspension approval")
        common.binding(target, ROLE, ROLE, MEMBER)
        reentry = place(target, RESTORED)
        if reentry == "placed":
            ready(lab, target, RESTORED)
        ready_now = target.kubectl("get", "deployment", RESTORED, "-o", "jsonpath={.status.readyReplicas}").stdout
        positive = {"different_reviewer_admitted_the_exact_member": current == valid,
                    "new_approved_placement_reaches_ready": reentry == "placed" and ready_now.strip() == "1"}
        lab.check("positive", "Separately approved readmission restores actual scoped placement",
                  all(positive.values()), positive)
    (lab.evidence / "federation-membership.json").write_text(json.dumps({
        "signal": signal_observation, "baseline": red, "suspension": green, "readmission": positive,
    }, sort_keys=True, indent=2) + "\n")
