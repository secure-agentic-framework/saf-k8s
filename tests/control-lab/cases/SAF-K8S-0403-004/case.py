"""Exercise credential delivery, controlled overlap and actual backend revocation."""

import hashlib
import json
import secrets
import subprocess
import time

from fixtures import container, pod, ready

NS = "saf-test"
BACKEND = "fixture-rotation-backend"
CLIENT = "fixture-rotation-reader"
DELIVERY = "fixture-delivered-auth"
ACL = "fixture-authoritative-acl"
APP_USER = "fixture-reader"
ADMIN_USER = "fixture-authority"
KEY = "fixture:marker"
VALUE = "public-rotation-marker"
IMAGE = ("docker.io/library/redis:7.4.7-alpine@sha256:"
         "02f2cc4882f8bf87c79a220ac958f58c700bdec0dfb9b9ea61b62fb0e8f1bfcf")
SCOPE = (
    "Use the real Redis ACL authenticator in disposable Kind to distinguish Kubernetes Secret "
    "delivery, authorized overlap, and rejection of a retired key on new connections. The "
    "fixture uses temporary random credentials. Backend-enforced lease expiry, long-running "
    "connection invalidation and provider integrations need separate evidence."
)


def private_request(lab, *args, payload=None):
    try:
        result = subprocess.run(["kubectl", "--kubeconfig", str(lab.kubeconfig),
                                 "--context", f"kind-{lab.cluster}", "--namespace", NS,
                                 "--request-timeout=12s", *args], input=payload, text=True,
                                capture_output=True, env=lab.env, timeout=16)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("A private credential-lifecycle fixture operation did not complete")
    return result.returncode, result.stdout, result.stderr


def apply_private_secret(lab, name, values, *, patch=False):
    data = {"stringData": values}
    if patch:
        args = ("patch", "secret/" + name, "--type=merge", "--patch-file=/dev/stdin", "-o", "name")
    else:
        data.update(apiVersion="v1", kind="Secret", metadata={"name": name})
        args = ("create", "-f", "-", "-o", "name")
    rc, _, _ = private_request(lab, *args, payload=json.dumps(data))
    if rc:
        lab.block("The owned credential fixture could not update its private Secret")


def fingerprint(secret):
    return hashlib.sha256(secret.encode()).hexdigest()


def redis(lab, pod_name, addr, user, secret, *command):
    args = ("exec", "-i", pod_name, "--", "sh", "-ec",
            'IFS= read -r REDISCLI_AUTH; export REDISCLI_AUTH; exec redis-cli --no-auth-warning --raw -h "$@"',
            "redis-fixture", addr, "--user", user, *command)
    rc, out, err = private_request(lab, *args, payload=secret + "\n")
    # The caller compares fixed markers and protocol errors only.
    return rc, out.strip(), err.strip()


def marker_decision(result):
    rc, out, err = result
    if rc == 0 and out.strip() == VALUE:
        return "allowed"
    if any(word in out + " " + err for word in ("WRONGPASS", "NOAUTH")):
        return "credential-denied"
    return "unexpected"


def mounted_marker(lab):
    script = (
        'REDISCLI_AUTH=$(cat /delivery/password); export REDISCLI_AUTH; '
        'exec redis-cli --no-auth-warning --raw -h "$@"'
    )
    return marker_decision(private_request(lab, "exec", CLIENT, "--", "sh", "-ec", script,
                                           "redis-fixture", BACKEND, "--user", APP_USER, "GET", KEY))


def mounted_fingerprint(lab):
    rc, out, _ = private_request(lab, "exec", CLIENT, "--", "sha256sum", "/delivery/password")
    return out.split()[0] if rc == 0 else ""


def poll(lab, observe, expected, message, timeout=75):
    expires = time.monotonic() + timeout
    while time.monotonic() < expires:
        if observe() == expected:
            return
        time.sleep(1)
    lab.block(message)


def run(lab):
    previous, replacement, admin, outsider = (secrets.token_urlsafe(24) for _ in range(4))
    old_hash, new_hash = fingerprint(previous), fingerprint(replacement)
    acl = "\n".join(("user default off",
                      f"user {ADMIN_USER} on #{fingerprint(admin)} ~* &* +@all",
                      f"user {APP_USER} on #{old_hash} ~{KEY} +get", ""))
    apply_private_secret(lab, ACL, {"users.acl": acl})
    apply_private_secret(lab, DELIVERY, {"password": previous})
    server = container("redis", image=IMAGE, command=["redis-server", "--aclfile", "/auth/users.acl",
                      "--save", "", "--appendonly", "no"], volumeMounts=[
                      {"name": "acl", "mountPath": "/auth", "readOnly": True}])
    backend = pod(BACKEND, [server], automountServiceAccountToken=False,
                  volumes=[{"name": "acl", "secret": {"secretName": ACL}}])
    backend["metadata"]["labels"] = {"app": BACKEND}
    lab.create(backend)
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": BACKEND},
                "spec": {"selector": {"app": BACKEND}, "ports": [{"port": 6379, "targetPort": 6379}]}})
    ready(lab, BACKEND)

    def manage(*args):
        return redis(lab, BACKEND, "127.0.0.1", ADMIN_USER, admin, *args)[1]

    poll(lab, lambda: manage("PING"), "PONG", "The owned authoritative Redis was unavailable")
    if manage("SET", KEY, VALUE) != "OK":
        lab.block("The owned backend marker could not be seeded")
    reader = container("reader", image=IMAGE, command=["sh", "-c", "sleep 420"], volumeMounts=[
                       {"name": "delivery", "mountPath": "/delivery", "readOnly": True}])
    lab.create(pod(CLIENT, [reader], automountServiceAccountToken=False,
                   volumes=[{"name": "delivery", "secret": {"secretName": DELIVERY}}]))
    ready(lab, CLIENT)
    poll(lab, lambda: mounted_marker(lab), "allowed", "Initial client authentication did not become available")
    initial_consumer = True

    def direct(key):
        return marker_decision(redis(lab, CLIENT, BACKEND, APP_USER, key, "GET", KEY))

    anonymous = lab.kubectl("exec", CLIENT, "--", "redis-cli", "--raw", "-h", BACKEND, "GET", KEY,
                            allow_failure=True)
    anonymous_denied = "NOAUTH" in anonymous.stdout + anonymous.stderr
    lab.kubectl("annotate", "secret/" + DELIVERY, "saf.example.org/fixture-expiry=2000-01-01T00:00:00Z")
    past_annotation_still_valid = direct(previous) == "allowed"

    apply_private_secret(lab, DELIVERY, {"password": replacement}, patch=True)
    lab.kubectl("annotate", "pod/" + CLIENT, "saf.example.org/credential-stage=replacement-delivered")
    poll(lab, lambda: mounted_fingerprint(lab), new_hash, "The mounted replacement did not arrive")
    wrong_only = mounted_marker(lab) == "credential-denied" and direct(previous) == "allowed"
    lab.check("red", "Publishing new bytes or an expiry annotation did not rotate the actual accepting backend",
              initial_consumer and anonymous_denied and past_annotation_still_valid and wrong_only,
              {"initial_consumer_authenticated": initial_consumer, "anonymous_denied": anonymous_denied,
               "past_annotation_does_not_expire_login": past_annotation_still_valid,
               "replacement_delivery_without_authority_change": wrong_only})

    added = manage("ACL", "SETUSER", APP_USER, "#" + new_hash) == "OK"
    overlap = direct(previous) == direct(replacement) == mounted_marker(lab) == "allowed"
    unrelated_denied = direct(outsider) == "credential-denied"
    lab.check("green", "The authoritative ACL activates the replacement and a deliberately bounded overlap retains both approved credentials",
              added and overlap and unrelated_denied,
              {"authority_update": added, "overlap_works": overlap, "unrelated_credential_denied": unrelated_denied})

    withdrawn = manage("ACL", "SETUSER", APP_USER, "!" + old_hash) == "OK"
    expired = direct(previous) == "credential-denied"
    continues = direct(replacement) == mounted_marker(lab) == "allowed"
    least = redis(lab, CLIENT, BACKEND, APP_USER, replacement, "GET", "other:fixture:marker")
    unaffected_scope = "NOPERM" in least[1] + " " + least[2]
    lab.check("positive", "The accepting backend rejects the retired credential and the running consumer keeps approved least-privilege access",
              withdrawn and expired and continues and unaffected_scope,
              {"old_credential_rejected_on_new_connection": expired, "replacement_in_use": continues,
               "unrelated_resource_denied": unaffected_scope})
    (lab.evidence / "credential-rotation-observations.json").write_text(json.dumps({
        "delivery_alone_did_not_change_authority": wrong_only, "past_annotation_did_not_expire_login": past_annotation_still_valid,
        "explicit_authoritative_overlap": overlap, "retired_credential_denied_on_new_connection": expired,
        "running_consumer_uses_replacement": continues, "least_privilege_preserved": unaffected_scope,
        "backend_lease_expiry_tested": False, "existing_authenticated_connections_tested": False,
    }, indent=2) + "\n")
