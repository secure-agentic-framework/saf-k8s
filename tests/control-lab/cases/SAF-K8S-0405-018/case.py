"""Observe encrypted credential storage and actual retirement at its relying API."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
DESTINATION = "/etc/kubernetes/saf-credential-encryption"
MOUNT = "fixture-credential-encryption"
NS = "saf-test"
ANCHOR = "fixture-routine-credential-anchor"
ACCOUNT = "fixture-lifecycle-reader"
INDIVIDUAL = "fixture-independent-reader"
RBAC = "rbac.authorization.k8s.io/v1"
MARKER = "public-saf-storage-comparator"
SCOPE = (
    "A disposable API server rewrites one named test Secret from identity storage into an "
    "encrypted envelope. It then stores only short-lived synthetic credentials in that "
    "encrypted scope. A temporary reader cannot retrieve the store. Replacing the bound "
    "Secret invalidates the original credential after convergence, while replacement and "
    "independent reads work. Keys and credential bytes remain private to the disposable fixture."
)


def configure(path, providers):
    document = {"apiVersion": "apiserver.config.k8s.io/v1", "kind": "EncryptionConfiguration",
                "resources": [{"resources": ["secrets"], "providers": providers}]}
    temp = path.with_suffix(".next")
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(document, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(path)


def prepare_kind(lab, temporary):
    home = temporary / MOUNT
    home.mkdir(mode=0o700)
    configure(home/"provider.json", [{"identity": {}}])
    profile = temporary / "fixture-credential-kind.yaml"
    profile.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: {json.dumps(str(home))}
    containerPath: {DESTINATION}
    readOnly: true
kubeadmConfigPatches:
- |
  apiVersion: kubeadm.k8s.io/v1beta4
  kind: ClusterConfiguration
  apiServer:
    extraArgs:
    - name: encryption-provider-config
      value: {DESTINATION}/provider.json
    - name: encryption-provider-config-automatic-reload
      value: "true"
    extraVolumes:
    - name: saf-fixture-credential-encryption
      hostPath: {DESTINATION}
      mountPath: {DESTINATION}
      readOnly: true
      pathType: Directory
""")
    return profile


def recovery_fixture():
    path = Path(__file__).resolve().parents[1] / "SAF-K8S-0405-020" / "case.py"
    spec = importlib.util.spec_from_file_location("saf_fixture_recovery", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def private(lab, args, *, payload=None):
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
               "--request-timeout=12s", *args]
    result = subprocess.run(command, input=payload, env=lab.env, capture_output=True, text=True, timeout=20)
    if result.returncode:
        lab.block("A case-owned storage request failed without retaining its private output")
    return result.stdout


def anchor(lab):
    document = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": ANCHOR},
                "stringData": {"marker": MARKER}}
    data = private(lab, ("-n", NS, "create", "-f", "-", "-o", "json"), payload=json.dumps(document))
    return json.loads(data)["metadata"]["uid"]


def raw_record(lab):
    key = f"/registry/secrets/{NS}/{ANCHOR}"
    data = private(lab, (
        "-n", "kube-system", "exec", f"etcd-{lab.cluster}-control-plane", "-c", "etcd", "--",
        "etcdctl", "--endpoints=https://127.0.0.1:2379", "--cacert=/etc/kubernetes/pki/etcd/ca.crt",
        "--cert=/etc/kubernetes/pki/etcd/server.crt", "--key=/etc/kubernetes/pki/etcd/server.key",
        "get", key, "--write-out=json",
    ))
    rows = json.loads(data).get("kvs", [])
    if len(rows) != 1 or base64.b64decode(rows[0]["key"], validate=True).decode() != key:
        lab.block("The isolated data store did not return exactly the requested fixture record")
    return base64.b64decode(rows[0]["value"], validate=True)


def encrypted(value):
    return value.startswith(b"k8s:enc:secretbox:v1:fixture-write:") and MARKER.encode() not in value


def enable(lab):
    key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    configure(lab.kubeconfig.parent / MOUNT / "provider.json",
              [{"secretbox": {"keys": [{"name": "fixture-write", "secret": key}]}}, {"identity": {}}])
    deadline = time.monotonic() + 125
    while time.monotonic() < deadline:
        lab.kubectl("annotate", "secret/"+ANCHOR, f"fixture.saf/rewrite={time.monotonic_ns()}",
                    "--overwrite", "-o", "name")
        if encrypted(raw_record(lab)):
            return
        time.sleep(4)
    lab.block("The case-owned Secret encryption provider did not converge")


def store_credential(lab, profile):
    config = json.loads(profile.read_text())
    token = Path(config["users"][0]["user"]["tokenFile"]).read_text().strip()
    private(lab, ("-n", NS, "patch", "secret", ANCHOR, "--type=merge", "--patch-file=/dev/stdin", "-o", "name"),
            payload=json.dumps({"stringData": {"credential": token}}))
    raw = raw_record(lab)
    observed = private(lab, ("-n", NS, "get", "secret", ANCHOR, "-o", "json"))
    retained = base64.b64decode(json.loads(observed)["data"]["credential"], validate=True)
    return {"actual_protected_record_uses_envelope": encrypted(raw),
            "credential_bytes_absent_from_exact_raw_record": token.encode() not in raw,
            "selected_privileged_storage_path_matches": retained == token.encode()}


def run(lab):
    fixture = recovery_fixture()
    assert fixture.REFERENCE == ANCHOR
    first_uid = anchor(lab)
    initial = raw_record(lab)
    red = {"plaintext_marker_visible_before_protection": MARKER.encode() in initial,
           "unprotected_record_has_no_envelope": not initial.startswith(b"k8s:enc:")}
    lab.check("red", "An unprotected named Secret exposes its inert comparator in raw storage",
              all(red.values()), red)
    enable(lab)

    fixture.put(lab, "ConfigMap", fixture.READ, data={"marker": fixture.MARKER})
    fixture.put(lab, "Role", fixture.READ, RBAC, rules=[{
        "apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"], "resourceNames": [fixture.READ],
    }])
    for account in (ACCOUNT, INDIVIDUAL):
        fixture.put(lab, "ServiceAccount", account, automountServiceAccountToken=False)
        fixture.approved(lab, account)
    original = fixture.identity(lab, ACCOUNT, "stored-original", reference=True)
    neighbor = fixture.identity(lab, INDIVIDUAL, "storage-independent")
    storage = store_credential(lab, original)
    unrelated = subprocess.run(
        ["kubectl", "--kubeconfig", str(original), "--context", "fixture",
         "--request-timeout=5s", "get", f"--raw=/api/v1/namespaces/{NS}/secrets/{ANCHOR}"],
        capture_output=True, text=True, env=lab.env, timeout=12,
    )
    green = dict(storage, scoped_credential_performs_allowed_read=fixture.await_read(lab, original, "allowed") == "allowed",
                 ordinary_caller_cannot_read_store=unrelated.returncode != 0 and "(Forbidden)" in unrelated.stderr)
    lab.check("green", "Protected storage conceals the actual fixture credential and preserves least privilege",
              all(green.values()), green)

    lab.kubectl("delete", "secret", ANCHOR, "--wait=true")
    next_uid = anchor(lab)
    replaced = fixture.identity(lab, ACCOUNT, "stored-replacement", reference=True)
    replacement = store_credential(lab, replaced)
    positive = {"replacement_secret_has_new_identity": first_uid != next_uid,
                "previous_bound_credential_rejected": fixture.await_read(lab, original, "unauthenticated") == "unauthenticated",
                "replacement_credential_reads_approved_resource": fixture.read(lab, replaced) == "allowed",
                "replacement_is_protected_at_rest": all(replacement.values()),
                "independent_reader_unchanged": fixture.read(lab, neighbor) == "allowed"}
    lab.check("positive", "Replacement and independent access survive retirement of the previous credential",
              all(positive.values()), positive)
    (lab.evidence / "credential-storage-lifecycle-observations.json").write_text(json.dumps({
        "baseline": red, "protected": green, "retirement": positive,
    }, indent=2) + "\n")
