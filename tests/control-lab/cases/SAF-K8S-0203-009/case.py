"""Check the actual pod-bound identity used by a local authorization boundary."""

import json
from pathlib import Path

SCOPE = "Verify real Kubernetes projected identity and Vault’s native JWT exchange, scoped KV operations, and expiry using disposable fixtures."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
HOST = "fixture-workload-identity.saf-test.svc.cluster.local"
SERVICE = "fixture-workload-identity"
APPROVED = "fixture-workload-approved"
OTHER = "fixture-workload-other"
SERVER = "fixture-workload-reviewer"
AUDIENCE = "saf-fixture-workload"
VAULT_IMAGE = ("docker.io/hashicorp/vault:1.21.4@sha256:"
               "4e33b126a59c0c333b76fb4e894722462659a6bec7c48c9ee8cea56fccfd2569")
VAULT = "fixture-workload-exchange"
VAULT_SERVER = """disable_mlock = true
api_addr = "http://127.0.0.1:8200"
storage "inmem" {}
listener "tcp" {
  address = "127.0.0.1:8200"
  tls_disable = true
}
"""
RBAC = "rbac.authorization.k8s.io"
PROBE = """
import json, ssl, urllib.error, urllib.request
from pathlib import Path
identity = Path('/identity/token').read_text().strip()
context = ssl.create_default_context(cafile='/trust/server.crt')
query = urllib.request.Request('https://fixture-workload-identity.saf-test.svc.cluster.local:8443/v1/identity',
                               headers={'Authorization': 'Bearer ' + identity})
try:
    with urllib.request.urlopen(query, context=context, timeout=5) as result:
        print(json.dumps({'status': result.status, 'body': json.load(result)}))
except urllib.error.HTTPError as error:
    print(json.dumps({'status': error.code}))
"""


def unit(command, mounts):
    return {"name": "fixture", "image": IMAGE, "command": command, "volumeMounts": mounts,
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "5m", "memory": "12Mi"}, "limits": {"cpu": "150m", "memory": "72Mi"}}}


def pod(lab, name, account, container, volumes, *, automount=False, labels=None):
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": labels or {}}, "spec": {
        "restartPolicy": "Never", "serviceAccountName": account, "automountServiceAccountToken": automount,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [container], "volumes": volumes,
    }})
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + name, "--timeout=70s", timeout=80)


def certificates(lab):
    temporary = lab.kubeconfig.parent / "fixture-identity-tls"
    temporary.mkdir(mode=0o700)
    cert, key = temporary / "server.crt", temporary / "server.key"
    lab.command("openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", f"/CN={HOST}", "-addext", f"subjectAltName=DNS:{HOST}",
                "-keyout", str(key), "-out", str(cert))
    lab.kubectl("create", "secret", "generic", SERVICE, f"--from-file={key}", f"--from-file={cert}")
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": SERVICE},
                "data": {"server.crt": cert.read_text(), "identity.py": Path(__file__).with_name("identity.py").read_text()}})


def start(lab, mode):
    server = unit(["python", "-B", "/source/identity.py", mode], [
        {"name": "source", "mountPath": "/source", "readOnly": True},
        {"name": "server-tls", "mountPath": "/tls", "readOnly": True},
    ])
    server["readinessProbe"] = {"tcpSocket": {"port": 8443}, "periodSeconds": 1}
    pod(lab, SERVICE, SERVER, server, [{"name": "source", "configMap": {"name": SERVICE}},
                                        {"name": "server-tls", "secret": {"secretName": SERVICE}}],
        labels={"app": SERVICE}, automount=True)


def client(lab, name, account, audience):
    consumer = unit(["python", "-c", "import time; time.sleep(180)"],
                    [{"name": "identity", "mountPath": "/identity", "readOnly": True},
                     {"name": "trust", "mountPath": "/trust", "readOnly": True}])
    pod(lab, name, account, consumer, [
        {"name": "identity", "projected": {"sources": [{"serviceAccountToken": {
            "path": "token", "expirationSeconds": 600, "audience": audience}}]}},
        {"name": "trust", "configMap": {"name": SERVICE}},
    ])


def observe(lab, name):
    result = lab.kubectl("exec", "pod/" + name, "--", "python", "-c", PROBE, allow_failure=True)
    if result.returncode != 0:
        lab.block("The fixture identity service did not return a verifiable result")
    return json.loads(result.stdout)


def exchange(lab):
    config = json.loads(lab.kubectl("get", "--raw=/.well-known/openid-configuration").stdout)
    public_key = lab.command("docker", "exec", f"{lab.cluster}-control-plane", "cat",
                             "/etc/kubernetes/pki/sa.pub").stdout
    if not public_key.startswith("-----BEGIN PUBLIC KEY-----"):
        lab.block("The Kubernetes service-account issuer public key is unavailable")
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": VAULT}, "immutable": True,
                "data": {"vault.hcl": VAULT_SERVER, "issuer": config["issuer"], "issuer.pub": public_key,
                         "vault-probe.py": Path(__file__).with_name("vault-probe.py").read_text()}})
    fixture_mount = {"name": "fixture", "mountPath": "/fixture", "readOnly": True}
    identity_mount = {"name": "identity", "mountPath": "/identity", "readOnly": True}
    vault = unit(["vault", "server", "-config=/fixture/vault.hcl"], [fixture_mount])
    vault.update(name="vault", image=VAULT_IMAGE, restartPolicy="Always",
                 resources={"requests": {"cpu": "50m", "memory": "70Mi"}, "limits": {"memory": "300Mi"}})
    probe = unit(["python", "-B", "/fixture/vault-probe.py"], [fixture_mount, identity_mount])
    projections = [{"serviceAccountToken": {"path": name, "expirationSeconds": 600, "audience": audience}}
                   for name, audience in (("approved", AUDIENCE), ("other-audience", "saf-other-audience"))]
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": VAULT},
                "spec": {"backoffLimit": 0, "template": {"spec": {
                    "restartPolicy": "Never", "serviceAccountName": APPROVED,
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "initContainers": [vault], "containers": [probe],
                    "volumes": [{"name": "fixture", "configMap": {"name": VAULT}},
                                {"name": "identity", "projected": {"sources": projections}}],
                }}}})
    done = lab.kubectl("wait", "--for=condition=Complete", "job/" + VAULT,
                       "--timeout=100s", timeout=110, allow_failure=True)
    logs = lab.kubectl("logs", "job/" + VAULT, "-c", "fixture", allow_failure=True)
    if done.returncode or logs.returncode:
        lab.block("The owned Vault JWT fixture did not complete; inspect the unprivileged probe logs")
    return json.loads(logs.stdout)


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    for account in (APPROVED, OTHER, SERVER):
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": account},
                    "automountServiceAccountToken": False})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "ClusterRole", "metadata": {"name": SERVER},
                "rules": [{"apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"], "verbs": ["create"]}]})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "ClusterRoleBinding", "metadata": {"name": SERVER},
                "roleRef": {"apiGroup": RBAC, "kind": "ClusterRole", "name": SERVER},
                "subjects": [{"kind": "ServiceAccount", "namespace": "saf-test", "name": SERVER}]})
    certificates(lab)
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": SERVICE},
                "spec": {"selector": {"app": SERVICE}, "ports": [{"port": 8443, "targetPort": 8443}]}})
    start(lab, "shared")
    client(lab, "fixture-approved", APPROVED, AUDIENCE)
    client(lab, "fixture-alternate", OTHER, AUDIENCE)
    client(lab, "fixture-wrong-audience", APPROVED, "saf-other-audience")
    broad = observe(lab, "fixture-alternate")["status"] == 200
    lab.check("red", "The initial shared workload mapping accepts the separately issued alternate identity",
              broad, {"alternate_initially_mapped": broad})
    lab.kubectl("delete", "pod", SERVICE, "--wait=true", "--grace-period=1")
    start(lab, "scoped")
    other_denied = observe(lab, "fixture-alternate")["status"] == 403
    audience_denied = observe(lab, "fixture-wrong-audience")["status"] == 401
    lab.check("green", "The scoped mapping rejects the separate valid subject and the wrong audience",
              other_denied and audience_denied, {"alternate_subject_denied": other_denied, "wrong_audience_denied": audience_denied})
    allowed = observe(lab, "fixture-approved")
    expected = {"status": 200, "body": {"fixture_principal": "fixture-workload-role", "public_marker": "authorized fixture"}}
    lab.check("positive", "The approved projected identity resolves to the intended local principal",
              allowed == expected, {"approved_identity_mapped": allowed == expected})
    native = exchange(lab)
    lab.check("green", "Vault rejects a Kubernetes token with the wrong audience or subject",
              native["audience_http"] == 400 and native["subject_http"] == 400,
              {"native_wrong_audience_denied": native["audience_http"] == 400,
               "native_wrong_subject_denied": native["subject_http"] == 400})
    issued = (native["lease_seconds"] == 16 and not native["renewable"] and native["vault_entity_assigned"]
              and native["granted_policies"] == ["read-public-marker"]
              and native["verified_claim_subject"] == f"system:serviceaccount:saf-test:{APPROVED}")
    lab.check("positive", "Native exchange issues a bounded, nonrenewable credential for the approved identity and policy",
              issued, {"approved_entity_and_policy": issued, "lease_seconds": native["lease_seconds"]})
    permitted = native["allowed_read_http"] == 200 and native["approved_public_marker"]
    rejected = native["out_of_scope_read_http"] == native["out_of_scope_write_http"] == 403
    lab.check("green", "The issued credential reads its owned public marker but has neither wider read nor write access",
              permitted and rejected, {"approved_read": permitted, "wider_read_and_write_denied": rejected})
    lab.check("green", "The same credential loses access after its native lease expires",
              native["expired_read_http"] == 403, {"expired_read_denied": native["expired_read_http"] == 403})
    (lab.evidence / "workload-identity-observations.json").write_text(json.dumps({
        "identity_mapping": allowed, "alternate_subject_rejected": other_denied, "wrong_audience_rejected": audience_denied,
        "native_relying_service": VAULT_IMAGE,
        "native_jwt_and_kv_observations": native,
    }, indent=2) + "\n")
