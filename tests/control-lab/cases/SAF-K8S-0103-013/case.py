"""Verify short-lived audience-scoped credentials for an owned controller fixture."""

import base64
import json
import subprocess
import time

SCOPE = "Kubernetes-issued credentials bound to a disposable fixture Pod and audience. No external identity provider is accessed."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
NS = "saf-test"
ACCOUNT = "fixture-controller-identity"
AUDIENCE = "fixture-cloud-controller"
OTHER_AUDIENCE = "fixture-other-consumer"
SUBJECT = f"system:serviceaccount:{NS}:{ACCOUNT}"


def protected_request(lab, route, body):
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
               "--request-timeout=8s", "create", f"--raw={route}", "-f", "-"]
    try:
        process = subprocess.run(command, input=json.dumps(body), env=lab.env, text=True,
                                 capture_output=True, timeout=15)
        if process.returncode != 0:
            lab.block("A credential-bearing fixture request failed without retaining its output")
        return json.loads(process.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        lab.block("A credential-bearing fixture response could not be safely processed")


def marker_pod(lab, name):
    item = lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": {
        "serviceAccountName": ACCOUNT, "automountServiceAccountToken": False, "restartPolicy": "Never",
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "unit", "image": IMAGE, "command": ["python", "-c", "import time; time.sleep(170)"],
                        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]}},
                        "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                                      "limits": {"cpu": "100m", "memory": "48Mi"}}}],
    }})
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + name, "--timeout=50s", timeout=60)
    return {"name": name, "uid": item["metadata"]["uid"]}


def token(lab, pod, audiences):
    body = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest",
            "spec": {"audiences": audiences, "expirationSeconds": 600, "boundObjectRef": {
                "apiVersion": "v1", "kind": "Pod", **pod,
            }}}
    response = protected_request(lab, f"/api/v1/namespaces/{NS}/serviceaccounts/{ACCOUNT}/token", body)
    return response["status"]["token"]


def review(lab, value, audience):
    body = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
            "spec": {"token": value, "audiences": [audience]}}
    return protected_request(lab, "/apis/authentication.k8s.io/v1/tokenreviews", body)["status"]


def accepted(status, pod, audience):
    user = status.get("user", {})
    return (status.get("authenticated") is True and user.get("username") == SUBJECT
            and audience in status.get("audiences", [])
            and user.get("extra", {}).get("authentication.kubernetes.io/pod-uid") == [pod["uid"]])


def bounded(value):
    payload = value.split(".")[1]
    body = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    return 0 < body["exp"] - body["iat"] <= 600 and body.get("aud") == [AUDIENCE]


def run(lab):
    lab.kubectl("label", "namespace", NS, "pod-security.kubernetes.io/enforce=restricted")
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": ACCOUNT},
                "automountServiceAccountToken": False})
    first = marker_pod(lab, "fixture-old-controller")
    broad = token(lab, first, [AUDIENCE, OTHER_AUDIENCE])
    wrong_before = accepted(review(lab, broad, OTHER_AUDIENCE), first, OTHER_AUDIENCE)
    del broad
    lab.check("red", "A broad audience credential is accepted by an unrelated intended verifier",
              wrong_before, {"additional_audience_initially_accepted": wrong_before})

    old = token(lab, first, [AUDIENCE])
    other_denied = review(lab, old, OTHER_AUDIENCE).get("authenticated") is not True
    narrow = accepted(review(lab, old, AUDIENCE), first, AUDIENCE)
    short = bounded(old)
    lab.check("green", "A short-lived audience-scoped credential works only for its intended verifier and Pod",
              narrow and other_denied and short,
              {"intended_pod_accepted": narrow, "other_audience_denied": other_denied, "duration_at_most_600_seconds": short})

    next_pod = marker_pod(lab, "fixture-replacement-controller")
    current = token(lab, next_pod, [AUDIENCE])
    reissued = current != old and next_pod["uid"] != first["uid"]
    lab.kubectl("delete", "pod", first["name"], "--grace-period=0", "--force", "--wait=true")
    deadline = time.monotonic() + 80
    expired = False
    while time.monotonic() < deadline:
        expired = review(lab, old, AUDIENCE).get("authenticated") is not True
        if expired:
            break
        time.sleep(2)
    refreshed = accepted(review(lab, current, AUDIENCE), next_pod, AUDIENCE) and bounded(current)
    lab.check("positive", "Credential reissue binds to the replacement Pod and deletion invalidates the old binding",
              reissued and expired and refreshed,
              {"distinct_reissue": reissued, "old_binding_denied": expired, "replacement_accepted": refreshed})
    (lab.evidence / "controller-credential-observations.json").write_text(json.dumps({
        "bounded_audience": narrow and other_denied and short, "distinct_reissue": reissued,
        "prior_pod_binding_invalidated": expired, "replacement_accepted": refreshed,
        "provider_token_exchange_tested": False,
    }, indent=2) + "\n")
