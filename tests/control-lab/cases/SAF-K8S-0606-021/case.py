"""Sign exact Kubernetes manifest bytes in CI before gated promotion."""
import base64
from hashlib import sha256
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
OPENSSL_IMAGE = ("docker.io/alpine/openssl:3.3.2@sha256:"
                 "5008e829163320a6e8166883c03e68189e8925ade68cde36584dc2a41cfa5248")
PYTHON_IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
                "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
NAMESPACE = "saf-test"
MARKER = "saf-0606-021-signed-manifest"
ACCOUNT = "manifest-promoter"
USERNAME = f"system:serviceaccount:{NAMESPACE}:{ACCOUNT}"
SCOPE = (
    "Kubernetes v1.36.1, two independent fixture signer Jobs, a pinned OpenSSL signature "
    "over exact inert ConfigMap manifest bytes, and a separate scoped promotion Job. "
    "The authorized signature passes, while absent and independently signed untrusted "
    "artifacts are rejected. Enterprise CI identity and approval, key custody, repository "
    "protection and deployment coverage require separate evidence."
)
SIGN = r"""
set -eu
umask 077
trap 'rm -f /scratch/private.pem' EXIT
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /scratch/private.pem 2>/dev/null
openssl pkey -in /scratch/private.pem -pubout -out /scratch/public.pem
openssl dgst -sha256 -sign /scratch/private.pem -out /scratch/manifest.sig /bundle/manifest.json
printf '%s\n' "$(base64 /scratch/public.pem | tr -d '\n')" "$(base64 /scratch/manifest.sig | tr -d '\n')"
"""
VERIFY = r"""
set -eu
if [ -e /var/run/secrets/kubernetes.io/serviceaccount/token ]; then echo unexpected-api-credential; exit 24; fi
if [ ! -s /bundle/manifest.sig ]; then echo missing-signature; exit 21; fi
digest="$(sha256sum /bundle/manifest.json | cut -d ' ' -f 1)"
if [ "$digest" != "$1" ]; then echo digest-mismatch; exit 23; fi
if ! openssl dgst -sha256 -verify /trust/approved.pem -signature /bundle/manifest.sig \
    /bundle/manifest.json >/dev/null 2>&1; then echo untrusted-signature; exit 22; fi
echo trusted-signature
"""


def config(lab, name, files):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                "immutable": True, "binaryData": {
                    key: base64.b64encode(data).decode() for key, data in files.items()}})


def mount(name, directory):
    return {"name": name, "mountPath": directory, "readOnly": name != "scratch"}


def volume(name, source):
    return {"name": name, "configMap": {"name": source}}


def container(name, image, command, mounts):
    return {"name": name, "image": image, "imagePullPolicy": "IfNotPresent", "command": command,
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}}, "volumeMounts": mounts}


def start_job(lab, name, pod):
    defaults = {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "fsGroup": 10001,
                            "seccompProfile": {"type": "RuntimeDefault"}},
    }
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90,
                         "template": {"spec": defaults | pod}}})


def job_outcome(lab, name):
    deadline = time.monotonic() + 95
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", f"job/{name}", "-o", "json").stdout)
        conditions = {r["type"] for r in job.get("status", {}).get("conditions", []) if r["status"] == "True"}
        terminal = conditions & {"Complete", "Failed"}
        if len(terminal) == 1:
            pods = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={name}", "-o", "json").stdout)["items"]
            if len(pods) != 1:
                lab.block(f"Expected one Pod for Job {name}")
            return terminal.pop(), pods[0]["status"]
        time.sleep(1)
    lab.kubectl("describe", f"job/{name}", allow_failure=True)
    lab.block(f"Job {name} did not finish")


def sign(lab, name, document):
    config(lab, name, {"manifest.json": document})
    signer = container("signer", OPENSSL_IMAGE, ["/bin/sh", "-c", SIGN],
                       [mount("bundle", "/bundle"), mount("scratch", "/scratch")])
    start_job(lab, name, {"containers": [signer], "volumes": [
        volume("bundle", name), {"name": "scratch", "emptyDir": {"medium": "Memory"}},
    ]})
    state, _ = job_outcome(lab, name)
    if state != "Complete":
        lab.kubectl("logs", f"job/{name}", allow_failure=True)
        lab.block(f"Signature fixture {name} failed")
    raw = lab.kubectl("logs", f"job/{name}").stdout.splitlines()
    public, signature = (base64.b64decode(line, validate=True) for line in raw)
    (lab.evidence / f"{name}.public-signature.json").write_text(json.dumps({
        "manifest_sha256": sha256(document).hexdigest(), "public_key_base64": raw[0],
        "signature_base64": raw[1],
    }, indent=2) + "\n")
    work = lab.kubeconfig.parent
    paths = [work / f"{name}.{ext}" for ext in ("pub", "sig", "manifest")]
    for path, payload in zip(paths, (public, signature, document)):
        path.write_bytes(payload)
    validation = lab.command("openssl", "dgst", "-sha256", "-verify", str(paths[0]),
                             "-signature", str(paths[1]), str(paths[2]))
    return public, signature, validation.stdout.strip() == "Verified OK"


def activate_identity(lab):
    rbac = "rbac.authorization.k8s.io"
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": ACCOUNT}})
    lab.create({"apiVersion": f"{rbac}/v1", "kind": "Role", "metadata": {"name": ACCOUNT},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["create"]}]})
    lab.create({"apiVersion": f"{rbac}/v1", "kind": "RoleBinding", "metadata": {"name": ACCOUNT},
                "subjects": [{"kind": "ServiceAccount", "name": ACCOUNT, "namespace": NAMESPACE}],
                "roleRef": {"apiGroup": rbac, "kind": "Role", "name": ACCOUNT}})


def promote(lab, name, document, signature):
    digest = sha256(document).hexdigest()
    data = {"manifest.json": document}
    if signature is not None:
        data["manifest.sig"] = signature
    config(lab, name, data)
    init = container("verify", OPENSSL_IMAGE, ["/bin/sh", "-c", VERIFY, "verify", digest],
                     [mount("bundle", "/bundle"), mount("trust", "/trust")])
    credentials = "/var/run/secrets/kubernetes.io/serviceaccount"
    apply = container("promote", PYTHON_IMAGE, ["python", "/code/promote.py", USERNAME, digest],
                      [mount("bundle", "/bundle"), mount("code", "/code"),
                       mount("api-token", credentials)])
    projected = {"name": "api-token", "projected": {"sources": [
        {"serviceAccountToken": {"path": "token", "expirationSeconds": 600}},
        {"configMap": {"name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
    ]}}
    start_job(lab, name, {
        "serviceAccountName": ACCOUNT,
        "initContainers": [init], "containers": [apply],
        "volumes": [volume("bundle", name), volume("trust", "approved-manifest-key"),
                    volume("code", "manifest-promotion-code"), projected],
    })
    state, status = job_outcome(lab, name)
    verifier = status["initContainerStatuses"][0]["state"]["terminated"]["exitCode"]
    reason = lab.kubectl("logs", f"job/{name}", "-c", "verify").stdout.strip()
    present = lab.kubectl("get", f"configmap/{MARKER}", "-o", "json", "--ignore-not-found").stdout
    return digest, state, verifier, reason, json.loads(present) if present.strip() else None


def run(lab):
    source = (HERE / "manifest.json").read_bytes()
    altered = (HERE / "modified-manifest.json").read_bytes()
    trusted_key, approved_sig, trusted_verified = sign(lab, "trusted-ci-signer", source)
    untrusted_key, untrusted_sig, untrusted_verified = sign(lab, "comparison-signer", altered)
    lab.check("positive", "Both signer Jobs produce valid signatures over their exact fixture bytes",
              trusted_verified and untrusted_verified and trusted_key != untrusted_key and source != altered,
              {"both_signatures_verified_with_own_keys": trusted_verified and untrusted_verified,
               "distinct_public_keys": trusted_key != untrusted_key, "distinct_manifests": source != altered})
    config(lab, "approved-manifest-key", {"approved.pem": trusted_key})
    config(lab, "manifest-promotion-code", {"promote.py": (HERE / "promote.py").read_bytes()})
    activate_identity(lab)

    for tag, document, signature, code, expected in (
        ("unsigned", source, None, 21, "missing-signature"),
        ("changed-bytes", altered, approved_sig, 22, "untrusted-signature"),
        ("untrusted", altered, untrusted_sig, 22, "untrusted-signature"),
    ):
        digest, state, exit_code, reason, marker = promote(lab, tag, document, signature)
        lab.check("red", f"The {tag} manifest fails signature promotion",
                  (state, exit_code, reason, marker) == ("Failed", code, expected, None),
                  {"manifest_sha256": digest, "job": state, "exit": exit_code, "reason": reason,
                   "marker_absent": marker is None})

    digest, state, exit_code, reason, marker = promote(lab, "approved", source, approved_sig)
    response = json.loads(lab.kubectl("logs", "job/approved", "-c", "promote").stdout)
    valid_object = marker is not None and marker["data"] == json.loads(source)["data"]
    lab.check("green", "The approved signature reaches the exact inert manifest via the promotion identity",
              (state, exit_code, reason) == ("Complete", 0, "trusted-signature") and valid_object
              and response == {"identity": USERNAME, "manifest_sha256": digest, "object": MARKER},
              {"manifest_sha256": digest, "job": state, "exit": exit_code, "reason": reason,
               "exact_data_present": valid_object, "api_observation": response})
