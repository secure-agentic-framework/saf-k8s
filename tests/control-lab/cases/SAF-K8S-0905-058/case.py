"""Internal model promotion gate using fixture OpenSSL signing Jobs and VAP."""
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import time

IMAGE = "docker.io/alpine/openssl:3.3.2@sha256:5008e829163320a6e8166883c03e68189e8925ade68cde36584dc2a41cfa5248"
NS = "saf-test"
POLICY = "saf-0905-058-model-promotion"
BINDING = POLICY
APPROVAL = "saf-0905-058-approval"
MODEL_CM = "saf-0905-058-model"
DENIAL = "model must match the approved digest and organization signature record"
MODEL = b'{"fixture":"synthetic-linear-model-v1","weights":[0.25,-0.5,1.0]}\n'
DIGEST = hashlib.sha256(MODEL).hexdigest()
SCOPE = (
    "One disposable Kubernetes v1.36.1 cluster. A real OCI registry stores an inert model "
    "by manifest and blob digest. Separate publisher and organization OpenSSL Jobs generate "
    "ephemeral keys and sign the identical model bytes. An independent verifier checks those "
    "signatures before a digest-bound immutable promotion record is written. Native admission "
    "uses that record to gate a model consumer Pod. The allowed Pod fetches and checks exact "
    "registry bytes. Production key custody, registry identity, signer authority, "
    "namespace coverage, and policy enrollment are open."
)
PYTHON = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
REGISTRY = "docker.io/library/registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
REGISTRY_HOST = "model-promotion-registry:5000"
READY_RECORD = "saf-0905-058-release"
CODE = "registry-consumer-code"


def cm(name, *, data=None, binary=None, immutable=False):
    obj = {"apiVersion": "v1", "kind": "ConfigMap",
           "metadata": {"name": name, "namespace": NS}}
    if data is not None:
        obj["data"] = data
    if binary is not None:
        obj["binaryData"] = {k: base64.b64encode(v).decode("ascii") for k, v in binary.items()}
    if immutable:
        obj["immutable"] = True
    return obj


def job(name, script, mounts, volumes):
    return {"apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": name, "namespace": NS},
            "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90,
                     "ttlSecondsAfterFinished": 300,
                     "template": {"metadata": {"labels": {"app": name}},
                                  "spec": {"restartPolicy": "Never",
                                           "automountServiceAccountToken": False,
                                           "securityContext": {"runAsNonRoot": True,
                                                               "runAsUser": 1000,
                                                               "fsGroup": 1000,
                                                               "seccompProfile": {"type": "RuntimeDefault"}},
                                           "containers": [{"name": name, "image": IMAGE,
                                                           "imagePullPolicy": "IfNotPresent",
                                                           "command": ["/bin/sh", "-c", script],
                                                           "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                                                         "limits": {"cpu": "100m", "memory": "64Mi"}},
                                                           "securityContext": {"allowPrivilegeEscalation": False,
                                                                               "readOnlyRootFilesystem": True,
                                                                               "capabilities": {"drop": ["ALL"]}},
                                                           "volumeMounts": mounts + [{"name": "tmp", "mountPath": "/tmp"}]}],
                                           "volumes": volumes + [{"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}}]}}}}


def wait(lab, name):
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        obj = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)
        conditions = {x["type"] for x in obj.get("status", {}).get("conditions", [])
                      if x.get("status") == "True"}
        if "Complete" in conditions:
            return True
        if "Failed" in conditions:
            return False
        time.sleep(0.5)
    lab.block(f"Job {name} timed out")


def logs(lab, name):
    pods = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={name}", "-o", "json").stdout)["items"]
    if len(pods) != 1:
        lab.block(f"Job {name} did not have exactly one pod")
    return lab.kubectl("logs", pods[0]["metadata"]["name"]).stdout


SIGN = r'''set -eu; umask 077; mkdir -p /key
test "$(sha256sum /model/model.bin | cut -d ' ' -f1)" = "$(cat /approval/digest)" || { echo approval-digest-mismatch; exit 31; }
test "$(cat /approval/approved)" = true || { echo approval-required; exit 32; }
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /key/private.pem 2>/dev/null
openssl pkey -in /key/private.pem -pubout -out /tmp/public.pem 2>/dev/null
openssl dgst -sha256 -sign /key/private.pem -out /tmp/model.sig /model/model.bin
openssl dgst -sha256 -verify /tmp/public.pem -signature /tmp/model.sig /model/model.bin >/dev/null
printf 'SIGN_BEGIN\npublic='; base64 /tmp/public.pem | tr -d '\n'; printf '\nsignature='; base64 /tmp/model.sig | tr -d '\n'; printf '\nSIGN_END\n'
'''


def run_signer(lab, name, *, approval=APPROVAL, script=SIGN, denied=False):
    mounts = [{"name": "model", "mountPath": "/model", "readOnly": True},
              {"name": "approval", "mountPath": "/approval", "readOnly": True},
              {"name": "key", "mountPath": "/key"}]
    volumes = [{"name": "model", "configMap": {"name": MODEL_CM}},
               {"name": "approval", "configMap": {"name": approval}},
               {"name": "key", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}}]
    lab.create(job(name, script, mounts, volumes))
    complete = wait(lab, name)
    output = logs(lab, name)
    if denied:
        return not complete and output.strip() == "approval-required"
    if not complete or "SIGN_BEGIN" not in output or "SIGN_END" not in output:
        lab.block(f"Restricted signer Job {name} did not yield a complete public result")
    fields = dict(line.split("=", 1) for line in
                  output.split("SIGN_BEGIN", 1)[1].split("SIGN_END", 1)[0].splitlines() if "=" in line)
    return tuple(base64.b64decode(fields[name], validate=True) for name in ("public", "signature"))


def deployment(name, digest, signer, signature_digest, reference):
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": NS,
                         "labels": {"saf-k8s.example/model-fixture": "synthetic"},
                         "annotations": {"saf-k8s.example/model-sha256": digest,
                                         "saf-k8s.example/signer": signer,
                                         "saf-k8s.example/signature-sha256": signature_digest}},
            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                     "containers": [{"name": "model", "image": PYTHON,
                                     "command": ["python", "-B", "/app/registry.py", "read"],
                                     "env": [{"name": "MODEL_REF", "value": reference},
                                             {"name": "MODEL_DIGEST", "value": digest}],
                                     "volumeMounts": [{"name": "scripts", "mountPath": "/app", "readOnly": True}]}],
                     "volumes": [{"name": "scripts", "configMap": {"name": CODE}}]}}


def request(lab, pod):
    return lab.kubectl("create", "-f", "-", "--dry-run=server", "-o", "json",
                       payload=json.dumps(pod), allow_failure=True)


def observed(result):
    err = result.stderr or ""
    return {"admitted": result.returncode == 0,
            "named_policy": POLICY in err,
            "expected_denial": DENIAL in err}


def install_policy(lab):
    checks = (
        f"has(object.metadata.annotations) && object.metadata.annotations['saf-k8s.example/model-sha256'] == params.data['digest'] && "
        f"object.metadata.annotations['saf-k8s.example/signer'] == params.data['signer'] && "
        f"object.metadata.annotations['saf-k8s.example/signature-sha256'] == params.data['signature-sha256'] && "
        "object.spec.containers.exists(c, c.name == 'model' && "
        "c.env.filter(e, e.name == 'MODEL_REF').size() == 1 && "
        "c.env.filter(e, e.name == 'MODEL_REF').all(e, e.value == params.data['reference']) && "
        "c.env.filter(e, e.name == 'MODEL_DIGEST').size() == 1 && "
        "c.env.filter(e, e.name == 'MODEL_DIGEST').all(e, e.value == params.data['digest']))"
    )
    policy = {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
              "metadata": {"name": POLICY},
              "spec": {"failurePolicy": "Fail",
                       "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
                       "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                                  "operations": ["CREATE", "UPDATE"],
                                                                  "resources": ["pods"], "scope": "Namespaced"}]},
                       "validations": [{"expression": checks, "message": DENIAL, "reason": "Forbidden"}]}}
    binding = {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
               "metadata": {"name": BINDING},
               "spec": {"policyName": POLICY, "validationActions": ["Deny"],
                        "paramRef": {"name": "saf-0905-058-release", "namespace": NS,
                                     "parameterNotFoundAction": "Deny"},
                        "matchResources": {"namespaceSelector": {"matchLabels": {
                            "saf-k8s.example/control": "0905-058-fixture"}}}}}
    lab.kubectl("apply", "-f", "-", payload=json.dumps(policy) + "\n---\n" + json.dumps(binding))


def _seed_registry(lab):
    label = {"app": "model-promotion-registry"}
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "model-promotion-registry"},
                "spec": {"selector": label, "ports": [{"port": 5000}]}})
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "fixture-registry", "labels": label},
                "spec": {"automountServiceAccountToken": False, "containers": [{"name": "registry", "image": REGISTRY,
                    "ports": [{"containerPort": 5000}], "readinessProbe": {"httpGet": {"path": "/v2/", "port": 5000},
                                                                          "periodSeconds": 1}}]}})
    lab.kubectl("wait", "--for=condition=Ready", "pod/fixture-registry", "--timeout=65s", timeout=70)
    lab.create(cm(CODE, data={"registry.py": Path(__file__).with_name("registry.py").read_text()},
                  binary={"model.json": MODEL}, immutable=True))
    seed = deployment("seed-model", DIGEST, "fixture", "fixture", "")
    seed["spec"]["containers"][0]["command"][-1] = "seed"
    lab.create(seed)
    row = _consumer_result(lab, "seed-model")
    if row["model_sha256"] != DIGEST or not row["reference"].startswith(REGISTRY_HOST + "/inert/models@sha256:"):
        lab.block("Fixture registry returned an unexpected model digest or reference")
    return row


def _consumer_result(lab, pod_name):
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", "pod/" + pod_name,
                "--timeout=65s", timeout=70)
    return json.loads(lab.kubectl("logs", "pod/" + pod_name).stdout)


def _independent_verification(lab, publisher, organization):
    with tempfile.TemporaryDirectory(prefix="signing-verifier-", dir=lab.kubeconfig.parent) as folder:
        destination = Path(folder)
        blob, key, signature = (destination / name for name in ("model.json", "signer.pub", "model.sig"))
        def verify(material, public, signed, *, allowed):
            blob.write_bytes(material)
            key.write_bytes(public)
            signature.write_bytes(signed)
            result = lab.command("openssl", "dgst", "-sha256", "-verify", str(key), "-signature",
                                 str(signature), str(blob), allow_failure=True)
            if allowed:
                return result.returncode == 0 and "verified ok" in result.stdout.lower()
            return result.returncode != 0 and "verification failure" in (result.stdout + result.stderr).lower()

        publisher_valid = verify(MODEL, *publisher, allowed=True)
        organization_valid = verify(MODEL, *organization, allowed=True)
        wrong_signer_rejected = verify(MODEL, organization[0], publisher[1], allowed=False)
        changed_rejected = verify(MODEL + b"\n", *organization, allowed=False)
        return {"publisher_signature_valid": publisher_valid, "organization_signature_valid": organization_valid,
                "publisher_signature_rejected_under_organization_key": wrong_signer_rejected,
                "changed_model_bytes_rejected": changed_rejected}


def run(lab):
    registry = _seed_registry(lab)
    ref = registry["reference"]
    lab.kubectl("label", "namespace", NS, "saf-k8s.example/control=0905-058-fixture", "--overwrite")
    lab.create(cm(MODEL_CM, binary={"model.bin": MODEL}, immutable=True))
    lab.create(cm("pending-approval", data={"digest": DIGEST, "approved": "false"}, immutable=True))
    lab.create(cm(APPROVAL, data={"digest": DIGEST, "approved": "true"}, immutable=True))
    discarded = run_signer(lab, "unapproved-org-signer", approval="pending-approval", denied=True)
    lab.check("green", "The organization signer rejects the exact model until approval is present",
              discarded, {"unapproved_signing_refused": discarded})

    publisher = run_signer(lab, "publisher-sign", script="set -eu; umask 077\n" + SIGN[SIGN.index("openssl genpkey"):])
    org = run_signer(lab, "organization-sign")
    fp = lambda data: hashlib.sha256(data).hexdigest()
    upstream = deployment("upstream-only", DIGEST, fp(publisher[0]), fp(publisher[1]), ref)
    before = request(lab, upstream)
    lab.check("red", "The exact upstream-only signed model request is admitted before the promotion control",
              before.returncode == 0, observed(before))

    verification = _independent_verification(lab, publisher, org)
    distinct = org[0] != publisher[0]
    lab.check("green", "Independent verification accepts both correct signatures and rejects the wrong trust key and changed model",
              all(verification.values()) and distinct, {**verification, "distinct_signing_keys": distinct})
    release = {"digest": DIGEST, "signer": fp(org[0]), "signature-sha256": fp(org[1]), "reference": ref}
    lab.create(cm(READY_RECORD, data=release, immutable=True))
    install_policy(lab)

    for index, (claim, candidate) in enumerate((
        ("The exact pre-control upstream-only declaration receives the named admission denial", upstream),
        ("Kubernetes rejects the approved digest with the publisher key fingerprint",
         deployment("wrong-key", DIGEST, fp(publisher[0]), fp(org[1]), ref)),
        ("Kubernetes rejects a mismatched consumer registry manifest even with the correct recorded signer",
         deployment("wrong-artifact", DIGEST, fp(org[0]), fp(org[1]), ref[:-64] + "0" * 64)),
    )):
        deadline = time.monotonic() + (18 if index == 0 else 0)
        while True:
            result = observed(request(lab, candidate))
            if not result["admitted"] or time.monotonic() >= deadline:
                break
            time.sleep(0.3)
        lab.check("green", claim, not result["admitted"] and result["named_policy"] and result["expected_denial"], result)

    eligible = deployment("eligible-consumer", DIGEST, fp(org[0]), fp(org[1]), ref)
    lab.create(eligible)
    fetched = _consumer_result(lab, "eligible-consumer")
    lab.check("positive", "The organization-signed declaration is admitted and consumes the exact registry artifact",
              fetched == registry, {"consumed_model_sha256": fetched["model_sha256"],
                                    "same_registry_manifest": fetched["reference"] == ref})
    evidence = {"promotion_record": release, "verification": verification,
                "publisher_signer_fingerprint": fp(publisher[0]), "consumer": fetched}
    (lab.evidence / "model-promotion.json").write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
