"""Verify least-privilege access and revocation for a disposable recovery identity."""
import json
import subprocess
import time

NS = "saf-1005-017-recovery"
ACCOUNT = "receipt-reader"
RECEIPT = "recovery-receipt"
AUDIENCE = "urn:example:saf:recovery-audit"
USERNAME = f"system:serviceaccount:{NS}:{ACCOUNT}"
RBAC = "rbac.authorization.k8s.io/v1"


def resource(api, kind, name, **fields):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name, "namespace": NS}, **fields}


def create(lab, obj):
    return json.loads(lab.kubectl("-n", NS, "create", "-f", "-", "-o", "json",
                                  payload=json.dumps(obj)).stdout)


def read(lab, name):
    return lab.kubectl("-n", NS, "get", "configmap", name, "-o", "json",
                       "--as", USERNAME, allow_failure=True)


def private_call(lab, *args, payload=None):
    # Keep this deliberately temporary bound credential and review body out of evidence.
    cmd = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
           "--namespace", NS, "--request-timeout=8s", *args]
    response = subprocess.run(cmd, input=payload, text=True, capture_output=True, env=lab.env, timeout=12)
    if response.returncode:
        operation = "TokenReview" if payload else "TokenRequest"
        known = {"expirationSeconds": "duration rejected", "not found": "binding or identity unavailable",
                 "Forbidden": "fixture permission denied", "unknown flag": "unsupported client flag"}
        reason = next((value for marker, value in known.items() if marker in response.stderr),
                      "unclassified API response")
        lab.block(f"The private fixture {operation} failed ({reason})")
    return response.stdout.strip()


def bound_credential(lab, name):
    marker = create(lab, resource("v1", "Secret", name, type="Opaque"))
    return private_call(lab, "create", "token", ACCOUNT, "--duration=10m", "--audience", AUDIENCE,
                        "--bound-object-kind", "Secret", "--bound-object-name", name,
                        "--bound-object-uid", marker["metadata"]["uid"])


def review(lab, token):
    obj = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
           "spec": {"token": token, "audiences": [AUDIENCE]}}
    result = json.loads(private_call(lab, "create", "-f", "-", "-o", "json", payload=json.dumps(obj)))
    status = result["status"]
    accepted = status.get("authenticated", False)
    if accepted:
        if status["user"]["username"] != USERNAME or status["audiences"] != [AUDIENCE]:
            lab.block("The fixture token authenticated as an unexpected identity or audience")
    return bool(accepted)


def run(lab):
    create(lab, resource("v1", "ServiceAccount", ACCOUNT, automountServiceAccountToken=False))
    create(lab, resource("v1", "ConfigMap", RECEIPT, data={"status": "synthetic-ok"}))
    create(lab, resource("v1", "ConfigMap", "unrelated-receipt", data={"status": "synthetic-outside-scope"}))
    initial = read(lab, RECEIPT)
    lab.check("red", "A recovery identity without the approved binding cannot read the case receipt",
              initial.returncode != 0 and "(Forbidden)" in initial.stderr,
              {"named_read_denied_without_binding": initial.returncode != 0})

    create(lab, resource(RBAC, "Role", ACCOUNT, rules=[
        {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"], "resourceNames": [RECEIPT]},
    ]))
    create(lab, resource(RBAC, "RoleBinding", ACCOUNT,
                         subjects=[{"kind": "ServiceAccount", "name": ACCOUNT, "namespace": NS}],
                         roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": ACCOUNT}))
    allowed = read(lab, RECEIPT)
    denied = read(lab, "unrelated-receipt")
    exact = allowed.returncode == 0 and json.loads(allowed.stdout)["data"] == {"status": "synthetic-ok"}
    outside = denied.returncode != 0 and "(Forbidden)" in denied.stderr
    lab.check("green", "The scoped binding allows the exact receipt and denies an unrelated same-namespace read",
              exact and outside, {"approved_read": exact, "unrelated_read_denied": outside})

    old = bound_credential(lab, "first-recovery-credential-marker")
    new = bound_credential(lab, "replacement-recovery-credential-marker")
    old_before = review(lab, old)
    new_before = review(lab, new)
    lab.check("red", "Issuing a replacement alone leaves both fixture credentials valid",
              old != new and old_before and new_before, {"old_valid": old_before, "replacement_valid": new_before})
    lab.kubectl("-n", NS, "delete", "secret", "first-recovery-credential-marker", "--wait=true")
    deadline = time.monotonic() + 70
    while review(lab, old):
        if time.monotonic() >= deadline:
            lab.block("TokenReview kept accepting the retired bound fixture credential")
        time.sleep(1)
    new_after = review(lab, new)
    lab.check("positive", "Retiring the old binding object invalidates only its credential",
              new_after, {"old_valid_after_retirement": False, "replacement_valid": new_after,
                          "audience": AUDIENCE, "subject": USERNAME})
    lab.kubectl("-n", NS, "delete", "secret", "replacement-recovery-credential-marker", "--wait=true")
