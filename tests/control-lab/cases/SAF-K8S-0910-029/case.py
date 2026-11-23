"""Exercise an owned two-cluster credential and incident coordination workflow."""
import base64
from contextlib import contextmanager
from hashlib import sha256
import json
import secrets
import subprocess
import time

NS = "saf-test"
NODE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
RBAC = "rbac.authorization.k8s.io/v1"
AUTHORITY = "fixture-coordination-authority"
TARGET = "fixture-affected-artifact"
COMPARATOR = "fixture-independent-artifact"
AFFECTED = "fixture-affected-reader"
UNAFFECTED = "fixture-independent-reader"
ACCESS = "fixture-affected-access"
SECRET = "fixture-shared-version"
TLS = "fixture-serving-certificate"
INCIDENT = "fixture-incident"
PLAN = "fixture-approved-plan"
RECEIPT = "fixture-coordination-receipt"
PUBLIC = "owned-marker"
SCOPE = (
    "Two independent owned Kubernetes clusters apply an approved coordination revision to a public "
    "Secret version, an actual fixture TLS certificate object and an incident access decision. Scoped "
    "RBAC refuses one cluster first. Reconciliation retains that cluster as unresolved and reports "
    "convergence only after the approved change and independently observed effects. This case does "
    "not establish enterprise federation, production identities, trusted key custody or on-wire TLS."
)


class Target:
    def __init__(self, lab, name, config):
        self.lab = lab
        self.name = name
        self.config = config

    def args(self, *args, actor=None):
        identity = [f"--as=system:serviceaccount:{NS}:{actor}"] if actor else []
        return ["kubectl", "--kubeconfig", str(self.config), "--context", "kind-" + self.name,
                "--namespace", NS, "--request-timeout=12s", *identity, *args]

    def kubectl(self, *args, actor=None, **kwargs):
        return self.lab.command(*self.args(*args, actor=actor), timeout=20, **kwargs)

    def create(self, kind, name, api="v1", **fields):
        manifest = {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields}
        self.kubectl("create", "-f", "-", "-o", "name", payload=json.dumps(manifest))

    def patch(self, kind, name, data):
        # The replacement identity bypasses the command transcript and is never archived.
        command = self.args("patch", kind, name, "--type=merge", "--patch-file", "/dev/stdin",
                            "-o", "name", actor=AUTHORITY)
        result = subprocess.run(command, input=json.dumps(data), capture_output=True, text=True,
                                timeout=20, env=self.lab.env)
        return result.returncode, "(Forbidden)" in result.stderr

    def public_field(self, kind, name, field, actor=None):
        return self.kubectl("get", kind, name, "-o", "jsonpath=" + field, actor=actor, allow_failure=True)


@contextmanager
def second_cluster(lab):
    name = "saf-lab-" + secrets.token_hex(6)
    config = lab.kubeconfig.parent / "fixture-second-kubeconfig"
    args = ("kind", "create", "cluster", "--name", name, "--image", NODE,
            "--kubeconfig", str(config), "--wait", "90s")
    if name in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block("The second fixture cluster name is already in use")
    try:
        lab.command(*args, timeout=400)
        target = Target(lab, name, config)
        target.kubectl("create", "namespace", NS)
        yield target
    finally:
        lab.command("kind", "delete", "cluster", "--name", name, "--kubeconfig", str(config), timeout=95)


def template_role(kind, names, verbs, group=""):
    return {"apiGroups": [group], "resources": [kind], "resourceNames": names, "verbs": verbs}


def binding(target, name, role, subject):
    target.create("RoleBinding", name, RBAC, roleRef={
        "apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": role},
        subjects=[{"kind": "ServiceAccount", "namespace": NS, "name": subject}])


def certificate(lab, stem):
    directory = lab.kubeconfig.parent
    key, cert = directory / f"{stem}.key", directory / f"{stem}.crt"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", f"/CN={stem}.fixture.invalid", "-keyout", str(key), "-out", str(cert))
    return cert, key


def encode(data):
    return base64.b64encode(data).decode()


def seed(target, initial):
    for name in (AUTHORITY, AFFECTED, UNAFFECTED):
        target.create("ServiceAccount", name, automountServiceAccountToken=False)
    for name in (TARGET, COMPARATOR):
        target.create("ConfigMap", name, data={"marker": PUBLIC})
    target.create("Secret", SECRET, stringData={"version": "fixture-v1"})
    cert, key = initial
    target.kubectl("create", "secret", "tls", TLS, "--cert=" + str(cert), "--key=" + str(key), "-o", "name")
    target.create("ConfigMap", INCIDENT, data={"status": "pending", "owner": "unassigned"})
    for name, object_id, subject in ((ACCESS, TARGET, AFFECTED),
                                     ("fixture-independent-access", COMPARATOR, UNAFFECTED)):
        target.create("Role", name, RBAC, rules=[template_role("configmaps", [object_id], ["get"])])
        binding(target, name, name, subject)
    target.create("Role", AUTHORITY, RBAC, rules=[
        template_role("secrets", [SECRET, TLS], ["get", "patch"]),
        template_role("configmaps", [INCIDENT], ["get", "patch"]),
        template_role("rolebindings", [ACCESS], ["delete"], "rbac.authorization.k8s.io"),
    ])


def allowed(target, name, actor):
    result = target.public_field("configmap", name, "{.data.marker}", actor)
    return result.returncode == 0 and result.stdout == PUBLIC


def state(target, previous, requested):
    stored = target.public_field("secret", SECRET, "{.data.version}").stdout
    public_pem = target.kubectl("get", "secret", TLS, "-o", 'go-template={{index .data "tls.crt"}}').stdout
    digest = sha256(base64.b64decode(public_pem.strip(), validate=True)).hexdigest()
    return {
        "version": base64.b64decode(stored, validate=True).decode(),
        "certificate": "prior" if digest == previous else "replacement" if digest == requested else "unknown",
        "incident_status": target.public_field("configmap", INCIDENT, "{.data.status}").stdout,
        "incident_owner": target.public_field("configmap", INCIDENT, "{.data.owner}").stdout,
        "affected_access": allowed(target, TARGET, AFFECTED),
        "approved_neighbor_access": allowed(target, COMPARATOR, UNAFFECTED),
    }


def observed_state(target, profiles, expected):
    deadline = time.monotonic() + 12
    result = {}
    while time.monotonic() < deadline:
        result = state(target, *profiles)
        if result == expected:
            break
        time.sleep(.4)
    return result


def apply(target, approved, replacement):
    cert, key = replacement
    requests = (
        ("secret", SECRET, {"data": {"version": encode(approved["version"].encode())}}),
        ("secret", TLS, {"data": {"tls.crt": encode(cert.read_bytes()), "tls.key": encode(key.read_bytes())}}),
        ("configmap", INCIDENT, {"data": {"status": "contained", "owner": approved["owner"]}}),
    )
    outcomes = []
    for kind, name, record in requests:
        outcomes.append(target.patch(kind, name, record))
    removed = target.kubectl("delete", "rolebinding", ACCESS, "--ignore-not-found=true", "--wait=false",
                             actor=AUTHORITY, allow_failure=True)
    outcomes.append((removed.returncode, "(Forbidden)" in removed.stderr))
    if any(code and not forbidden for code, forbidden in outcomes):
        target.lab.block("An unrelated failure interrupted the owned coordination operation")
    return "updated" if all(code == 0 for code, _ in outcomes) else "authorization-unresolved"


def run(lab):
    first = Target(lab, lab.cluster, lab.kubeconfig)
    originals = {name: certificate(lab, name + "-initial") for name in ("east", "west")}
    replacements = {name: certificate(lab, name + "-replacement") for name in originals}
    profiles = {name: (sha256(originals[name][0].read_bytes()).hexdigest(),
                       sha256(replacements[name][0].read_bytes()).hexdigest()) for name in originals}
    initial = {"version": "fixture-v1", "certificate": "prior", "incident_status": "pending",
               "incident_owner": "unassigned", "affected_access": True, "approved_neighbor_access": True}
    resolved = {"version": "fixture-v2", "certificate": "replacement", "incident_status": "contained",
                "incident_owner": "fixture-incident-operator", "affected_access": False, "approved_neighbor_access": True}
    with second_cluster(lab) as second:
        targets = {"east": first, "west": second}
        for key, target in targets.items():
            seed(target, originals[key])
        decision = {"targets": sorted(targets), "version": "fixture-v2", "owner": "fixture-incident-operator"}
        first.create("ConfigMap", PLAN, immutable=True, data={"approved": json.dumps(decision)})
        approved = json.loads(first.public_field("configmap", PLAN, "{.data.approved}").stdout)
        if approved != decision:
            lab.block("The fixture coordination decision lost its exact scope")
        baseline = {key: observed_state(target, profiles[key], initial) for key, target in targets.items()}
        lab.check("red", "A central approval record alone leaves both clusters on their previous state",
                  all(value == initial for value in baseline.values()), baseline)

        binding(first, AUTHORITY, AUTHORITY, AUTHORITY)
        partial = {key: apply(target, approved, replacements[key]) for key, target in targets.items()}
        intermediate = {key: observed_state(target, profiles[key], resolved if key == "east" else initial)
                        for key, target in targets.items()}
        first.create("ConfigMap", RECEIPT, data={"status": json.dumps(partial)})
        expected_partial = {"east": "updated", "west": "authorization-unresolved"}
        saved = json.loads(first.public_field("configmap", RECEIPT, "{.data.status}").stdout)
        lab.check("green", "The workflow retains the unauthorized target as unresolved while resolving the approved one",
                  partial == saved == expected_partial and intermediate == {"east": resolved, "west": initial},
                  {"coordination_receipt": saved, "per_cluster_observations": intermediate})

        binding(second, AUTHORITY, AUTHORITY, AUTHORITY)
        finished = {key: apply(target, approved, replacements[key]) for key, target in targets.items()}
        final = {key: observed_state(target, profiles[key], resolved) for key, target in targets.items()}
        first.kubectl("patch", "configmap", RECEIPT, "--type=merge", "-p",
                      json.dumps({"data": {"status": json.dumps(finished)}}), "-o", "name")
        recorded = json.loads(first.public_field("configmap", RECEIPT, "{.data.status}").stdout)
        lab.check("positive", "Both owned clusters converge only after the approved second grant is effective",
                  recorded == {"east": "updated", "west": "updated"} and all(value == resolved for value in final.values()),
                  {"completion": recorded, "per_cluster_observations": final})
    (lab.evidence / "federated-coordination-observations.json").write_text(json.dumps({
        "initial": baseline, "partial": intermediate, "final": final,
        "second_owned_cluster_cleanup": "deleted",
    }, indent=2) + "\n")
