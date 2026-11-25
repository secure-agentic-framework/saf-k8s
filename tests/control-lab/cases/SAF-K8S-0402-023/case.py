"""Track long-lived service-account token classes and their governed retirement."""

from datetime import datetime, timedelta, timezone
import base64
import json
import subprocess
import time

from fixtures import container, pod

NS = "saf-test"
ACCOUNT = "fixture-inventory-account"
TOKEN_TYPE = "kubernetes.io/service-account-token"
LEGACY = "fixture-legacy-linked"
MANUAL = "fixture-manual-unlinked"
OWNED = {LEGACY, MANUAL}
LABEL = "saf.example.org/token-review"
SCOPE = (
    "Use metadata from two owned Kubernetes Secret-backed token fixtures plus one isolated "
    "projected-token Pod. Check exception classification and retirement, then observe the "
    "actual issuer-issued JWT lifetime and TokenReview acceptance through expiration. Token "
    "bytes stay in process memory and are excluded from logs and evidence."
)


def create_token_fixture(lab, name):
    spec = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name, "annotations": {
                "kubernetes.io/service-account.name": ACCOUNT}}, "type": TOKEN_TYPE}
    # Name output remains safe even if the controller fills the Secret concurrently.
    lab.kubectl("create", "-f", "-", "-o", "name", payload=json.dumps(spec))


def inventory(lab):
    fields = (r'{range .items[*]}{.metadata.name}{"\t"}'
              r'{.metadata.annotations.kubernetes\.io/service-account\.name}{"\n"}{end}')
    raw = lab.kubectl("get", "secrets", "--field-selector", f"type={TOKEN_TYPE}",
                      "-o", "jsonpath=" + fields).stdout
    memberships = set(lab.kubectl("get", "serviceaccount/" + ACCOUNT,
                                 "-o", "jsonpath={.secrets[*].name}").stdout.split())
    records = {}
    for line in raw.splitlines():
        name, subject = line.split("\t")
        if name not in OWNED or subject != ACCOUNT:
            lab.block("Unexpected object in the owned metadata fixture inventory")
        records[name] = "legacy-linked" if name in memberships else "manual-unlinked"
    return records


def exception(lab, name, classification, deadline):
    data = {"namespace": NS, "account": ACCOUNT, "secret": name,
            "class": classification, "owner": "fixture-owner", "approval": "fixture-approval",
            "reason": "synthetic migration compatibility", "reviewBy": deadline.isoformat(),
            "retireBy": (deadline + timedelta(days=10)).isoformat()}
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name,
                "labels": {LABEL: "true"}}, "immutable": True, "data": data})


def classify(lab, records, now):
    listed = json.loads(lab.kubectl("get", "configmaps", "-l", LABEL + "=true", "-o", "json").stdout)
    approvals = {item["metadata"]["name"]: item["data"] for item in listed["items"]}
    decisions = {}
    for name, category in records.items():
        record = approvals.get(name, {})
        if (not all(record.get(field) for field in ("owner", "approval", "reason", "reviewBy", "retireBy"))
                or (record.get("namespace"), record.get("account"), record.get("secret"), record.get("class"))
                != (NS, ACCOUNT, name, category)):
            decisions[name] = "missing-or-mismatched"
            continue
        review_by = datetime.fromisoformat(record["reviewBy"])
        retire_by = datetime.fromisoformat(record["retireBy"])
        decisions[name] = "action-due" if min(review_by, retire_by) <= now else "current-exception"
    return decisions



AUDIENCE = "https://kubernetes.default.svc"
REQUESTED_TTL = 600


def quiet_kubectl(lab, *args, payload=None, timeout=30):
    """Keep synthetic credential bytes out of command logs and transcripts."""
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
               "--namespace", NS, f"--request-timeout={max(1, timeout - 5)}s", *args]
    try:
        result = subprocess.run(command, input=payload, capture_output=True, text=True,
                                env=lab.env, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        lab.block(f"Credential-safe kubectl failed: {type(error).__name__}")
    if result.returncode:
        lab.block(f"Credential-safe kubectl failed with exit {result.returncode}")
    return result


def projected_claims(token):
    try:
        encoded = token.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        issued, expires = int(payload["iat"]), int(payload["exp"])
        audiences = payload.get("aud", [])
        if isinstance(audiences, str):
            audiences = [audiences]
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("Projected token claims unavailable") from error
    if AUDIENCE not in audiences:
        raise RuntimeError("Projected token audience did not match request")
    return issued, expires, expires - issued


def token_review(lab, token):
    request = json.dumps({"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
                          "spec": {"audiences": [AUDIENCE], "token": token}})
    response = quiet_kubectl(lab, "create", "-f", "-", "-o", "json", payload=request)
    status = json.loads(response.stdout).get("status", {})
    valid = status.get("authenticated") is True
    if valid:
        user = status.get("user", {})
        if user.get("username") != f"system:serviceaccount:{NS}:{ACCOUNT}" or status.get("audiences") != [AUDIENCE]:
            lab.block("TokenReview identified a different subject or audience")
    return valid


def start_projected_pod(lab, name):
    spec = pod(name, [container("wait", volumeMounts=[{"name": "projected",
                                                   "mountPath": "/var/run/saf-token",
                                                   "readOnly": True}])], serviceAccountName=ACCOUNT,
               automountServiceAccountToken=False,
               volumes=[{"name": "projected", "projected": {"sources": [{"serviceAccountToken": {
                   "path": "token", "audience": AUDIENCE, "expirationSeconds": REQUESTED_TTL
               }}]}}])
    lab.create(spec)
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=95s", timeout=105)
    return lab.kubectl("get", f"pod/{name}", "-o", "jsonpath={.metadata.uid}").stdout.strip()


def observe_projected_lifetime(lab):
    name = "fixture-issued-ttl"
    pod_uid = start_projected_pod(lab, name)
    requested = lab.kubectl("get", f"pod/{name}", "-o",
        "jsonpath={.spec.volumes[0].projected.sources[0].serviceAccountToken.expirationSeconds}").stdout.strip()
    raw = quiet_kubectl(lab, "exec", name, "--", "cat", "/var/run/saf-token/token")
    token = raw.stdout.strip()
    if not token or token.count(".") != 2:
        lab.block("Projected token was absent or malformed")
    issued, expires, actual_ttl = projected_claims(token)
    initial_auth = token_review(lab, token)
    lab.check("green", "A live projected credential carries the exact requested audience and issuer-issued TTL",
              requested == str(REQUESTED_TTL) and actual_ttl == REQUESTED_TTL
              and expires > time.time() and initial_auth,
              {"requested_seconds": int(requested), "issued_seconds": actual_ttl,
               "audience_matches": True, "token_review_authenticated": initial_auth})

    # v1.36 API authentication permits clock skew; wait until exp plus a bounded margin.
    cutoff = expires + 65
    budget = time.monotonic() + REQUESTED_TTL + 75
    while time.time() < cutoff and time.monotonic() < budget:
        time.sleep(min(5, max(0.1, cutoff - time.time())))
    if time.time() < cutoff:
        lab.block("Clock moved backwards before the bounded expiration check")
    after_auth = token_review(lab, token)
    current_uid = lab.kubectl("get", f"pod/{name}", "-o", "jsonpath={.metadata.uid}").stdout.strip()
    lab.check("green", "The original issuer-issued token is rejected after exp while its same Pod remains",
              not after_auth and current_uid == pod_uid,
              {"token_review_authenticated": after_auth, "same_pod_uid": current_uid == pod_uid,
               "expiration_reached": time.time() >= expires})
    fresh_name = "fixture-issued-ttl-control"
    fresh_uid = start_projected_pod(lab, fresh_name)
    fresh = quiet_kubectl(lab, "exec", fresh_name, "--", "cat", "/var/run/saf-token/token").stdout.strip()
    _, fresh_expiry, fresh_ttl = projected_claims(fresh)
    fresh_auth = token_review(lab, fresh)
    lab.check("positive", "A fresh same-scope projected token still authenticates after the original expires",
              bool(fresh_uid) and bool(pod_uid) and fresh_uid != pod_uid and fresh != token
              and fresh_expiry > cutoff and fresh_ttl == REQUESTED_TTL and fresh_auth,
              {"distinct_pod": bool(fresh_uid) and fresh_uid != pod_uid,
               "issued_seconds": fresh_ttl, "fresh_authenticated": fresh_auth})
    (lab.evidence / "issued-ttl-observation.json").write_text(json.dumps({
        "requested_seconds": REQUESTED_TTL, "issued_seconds": actual_ttl,
        "issued_at": datetime.fromtimestamp(issued, timezone.utc).isoformat(),
        "expires_at": datetime.fromtimestamp(expires, timezone.utc).isoformat(),
        "accepted_before_exp": initial_auth, "rejected_after_exp": not after_auth,
        "same_pod_uid_after_exp": current_uid == pod_uid,
        "fresh_same_scope_accepted": fresh_auth,
        "credential_material_recorded": False
    }, indent=2) + "\n")
    token = raw = fresh = None
    lab.kubectl("delete", f"pod/{name}", f"pod/{fresh_name}", "--wait=true")

def run(lab):
    now = datetime.now(timezone.utc)
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": ACCOUNT},
                "automountServiceAccountToken": False})
    for name in (LEGACY, MANUAL):
        create_token_fixture(lab, name)
    # An explicit backlink creates the same classifier input used to
    # identify historical automatically generated objects on modern Kind.
    lab.kubectl("patch", "serviceaccount/" + ACCOUNT, "--type=merge", "-p",
                json.dumps({"secrets": [{"name": LEGACY}]}), "-o", "name")
    projected = pod("fixture-projected-declaration", [container("marker")],
                    schedulingGates=[{"name": "saf.example.org/hold-inventory-probe"}],
                    serviceAccountName=ACCOUNT, automountServiceAccountToken=False,
                    volumes=[{"name": "fixture-assertion", "projected": {"sources": [{"serviceAccountToken": {
                        "path": "assertion", "audience": "https://identity.fixture.invalid", "expirationSeconds": 600
                    }}]}}])
    lab.create(projected)
    path = "{.spec.volumes[0].projected.sources[0].serviceAccountToken.expirationSeconds}"
    requested = lab.kubectl("get", "pod/fixture-projected-declaration", "-o", "jsonpath=" + path).stdout.strip()
    initial = inventory(lab)
    expected = {LEGACY: "legacy-linked", MANUAL: "manual-unlinked"}
    before = classify(lab, initial, now)
    lab.check("red", "Metadata distinguishes the two Secret classes, neither had an exception, and projected intent stays separate",
              initial == expected and len(before) == 2 and set(before.values()) == {"missing-or-mismatched"}
              and requested == "600", {"secret_classes": initial, "initial_decisions": before, "projected_requested_seconds": requested})

    exception(lab, LEGACY, expected[LEGACY], now - timedelta(days=1))
    exception(lab, MANUAL, expected[MANUAL], now + timedelta(days=1))
    reviewed = classify(lab, inventory(lab), now)
    lab.check("green", "The review identifies the overdue exception and preserves the current, exact exception",
              reviewed == {LEGACY: "action-due", MANUAL: "current-exception"}, reviewed)
    lab.kubectl("delete", "secret/" + LEGACY, "--wait=true")
    after = inventory(lab)
    remaining = classify(lab, after, now)
    lab.check("positive", "Retirement removes the exact Secret from the inventory and leaves the separate current exception",
              after == {MANUAL: "manual-unlinked"} and remaining == {MANUAL: "current-exception"},
              {"remaining_classes": after, "remaining_decisions": remaining})
    (lab.evidence / "token-governance-observations.json").write_text(json.dumps({
        "inventory_before": initial, "before_exceptions": before, "reviewed_exceptions": reviewed,
        "inventory_after": after, "remaining_exceptions": remaining,
        "metadata_probe_requested_seconds": int(requested),
    }, indent=2) + "\n")

    observe_projected_lifetime(lab)
