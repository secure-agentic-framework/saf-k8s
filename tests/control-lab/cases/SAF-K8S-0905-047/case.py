"""Run actual training and package Jobs and verify pipeline-generated OCI attestations."""
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import time

HERE = Path(__file__).resolve().parent
PYTHON = "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
OPENSSL = "docker.io/alpine/openssl:3.3.2@sha256:5008e829163320a6e8166883c03e68189e8925ade68cde36584dc2a41cfa5248"
REGISTRY = "docker.io/library/registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
TYPE = "application/vnd.in-toto+json"
TRAIN_INPUT = "training-input-manifest.json"
INTERMEDIATE = "training-intermediate.json"
MODEL = "model.json"
PACKAGE = "model-package.json"
PROVENANCE = "packaging-record.json"

SCOPE = (
    "One disposable Kind cluster runs separate restricted training, packaging and attestation "
    "Jobs over synthetic linear regression records. The attestor generates two in-toto "
    "Statement v1 DSSE envelopes with SLSA Provenance v1 predicates and an ephemeral RSA key. "
    "An independent host verifier checks DSSE authentication, expected step roles and hashes "
    "from measured inputs and outputs. Two envelopes are attached by OCI package digest and "
    "retrieved with byte verification through the Distribution 3.0.0 referrers tag fallback. "
    "SLSA level, trusted production builder identity, managed key custody, durable registry "
    "retention and production workflow coverage remain unverified."
)

SIGN = r'''
set -eu
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /key/private.pem 2>/dev/null
openssl pkey -in /key/private.pem -pubout -out /key/public.pem
printf 'public='
base64 /key/public.pem | tr -d '\n'
printf '\n'
for step in training packaging; do
  openssl dgst -sha256 -sign /key/private.pem -out "/key/$step.sig" "/work/$step.pae"
  printf '%s-payload=' "$step"
  base64 "/work/$step.json" | tr -d '\n'
  printf '\n%s-signature=' "$step"
  base64 "/key/$step.sig" | tr -d '\n'
  printf '\n'
done
'''


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(row):
    return json.dumps(row, sort_keys=True, separators=(",", ":")).encode()


def _volume(name, **sources):
    return {"name": name, **sources}


def _mount(name, path, read_only=True):
    return {"name": name, "mountPath": path, "readOnly": read_only}


def _configmap(lab, name, *, scripts=None, artifacts=None):
    resource = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "immutable": True}
    if scripts is not None:
        resource["data"] = scripts
    if artifacts is not None:
        resource["binaryData"] = {key: base64.b64encode(value).decode() for key, value in artifacts.items()}
    lab.create(resource)


def _container(name, image, command, mounts):
    return {
        "name": name, "image": image, "imagePullPolicy": "IfNotPresent", "command": command,
        "volumeMounts": mounts,
        "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                      "limits": {"cpu": "200m", "memory": "96Mi"}},
        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]}},
    }


def _job(lab, name, container, volumes, init=None):
    pods = {"restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "fsGroup": 1000,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [container], "volumes": volumes}
    if init:
        pods["initContainers"] = [init]
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90,
                         "template": {"metadata": {"labels": {"app": name}}, "spec": pods}}})
    deadline = time.monotonic() + 95
    while time.monotonic() < deadline:
        obj = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)
        status = {row["type"] for row in obj.get("status", {}).get("conditions", []) if row["status"] == "True"}
        if "Failed" in status:
            lab.kubectl("logs", f"job/{name}", "--all-containers=true", allow_failure=True)
            lab.block(f"Pipeline Job {name} failed")
        if "Complete" in status:
            return lab.kubectl("logs", f"job/{name}", "-c", container["name"]).stdout
        time.sleep(0.5)
    lab.block(f"Pipeline Job {name} timed out")


def _step(lab, step, materials, product_names):
    _configmap(lab, step + "-input", artifacts=materials)
    volumes = [_volume("code", configMap={"name": "training-code"}),
               _volume("input", configMap={"name": step + "-input"})]
    container = _container(step, PYTHON, ["python", "-B", "/app/pipeline.py", step],
                           [_mount("code", "/app"), _mount("input", "/input")])
    observed = json.loads(_job(lab, step, container, volumes))
    outputs = {name: base64.b64decode(value, validate=True) for name, value in observed["outputs"].items()}
    assert observed["inputs"] == {name: _digest(data) for name, data in materials.items()}
    assert set(outputs) == set(product_names)
    return outputs


def _attest(lab, all_artifacts):
    _configmap(lab, "attestor-input", artifacts=all_artifacts)
    volumes = [_volume("code", configMap={"name": "training-code"}),
               _volume("input", configMap={"name": "attestor-input"}),
               _volume("work", emptyDir={"sizeLimit": "1Mi"}),
               _volume("key", emptyDir={"medium": "Memory", "sizeLimit": "1Mi"})]
    prepare = _container("prepare", PYTHON, ["python", "-B", "/app/pipeline.py", "attest"],
                         [_mount("code", "/app"), _mount("input", "/input"), _mount("work", "/work", False)])
    signer = _container("sign", OPENSSL, ["/bin/sh", "-c", SIGN],
                        [_mount("work", "/work"), _mount("key", "/key", False)])
    fields = dict(line.split("=", 1) for line in _job(lab, "attest-steps", signer, volumes, prepare).splitlines())
    public = base64.b64decode(fields["public"], validate=True)
    envelopes = {step: _canonical({"payloadType": TYPE, "payload": fields[step + "-payload"],
                                   "signatures": [{"keyid": _digest(public), "sig": fields[step + "-signature"]}]})
                 for step in ("training", "packaging")}
    return public, envelopes


def _verify(lab, public, envelopes, expectations, all_artifacts):
    with tempfile.TemporaryDirectory(prefix="attestation-verify-", dir=lab.kubeconfig.parent) as temp:
        working = Path(temp)
        key = working / "public.pem"
        key.write_bytes(public)
        checked = {}
        for step, (expected_materials, expected_subjects) in expectations.items():
            envelope = json.loads(envelopes[step])
            assert envelope["payloadType"] == TYPE
            entry, = envelope["signatures"]
            assert entry["keyid"] == _digest(public)
            payload = base64.b64decode(envelope["payload"], validate=True)
            kind = envelope["payloadType"].encode("ascii")
            pae = b" ".join((b"DSSEv1", str(len(kind)).encode(), kind,
                             str(len(payload)).encode(), payload))
            (working / "pae").write_bytes(pae)
            (working / "signature").write_bytes(base64.b64decode(entry["sig"], validate=True))
            lab.command("openssl", "dgst", "-sha256", "-verify", str(key),
                        "-signature", str(working / "signature"), str(working / "pae"))
            found = json.loads(payload)
            assert found["_type"] == "https://in-toto.io/Statement/v1"
            assert found["predicateType"] == "https://slsa.dev/provenance/v1"
            definition = found["predicate"]["buildDefinition"]
            assert definition["buildType"] == "https://saf-k8s.example.test/pipeline/v1/" + step
            assert definition["externalParameters"] == {"fixture": "SAF-K8S-0905-047", "step": step}
            assert found["predicate"]["runDetails"]["builder"]["id"] == "https://saf-k8s.example.test/disposable-kind-job"
            assert found["subject"] == [{"name": name, "digest": {"sha256": _digest(all_artifacts[name])}}
                                        for name in expected_subjects]
            assert definition["resolvedDependencies"] == [
                {"uri": "urn:saf-fixture:" + name, "digest": {"sha256": _digest(all_artifacts[name])}}
                for name in expected_materials]
            checked[step] = found
    return checked


def _registry(lab):
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "attestation-registry"},
                "spec": {"selector": {"app": "attestation-registry"}, "ports": [{"port": 5000}]}})
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "attestation-registry",
                                                               "labels": {"app": "attestation-registry"}},
                "spec": {"automountServiceAccountToken": False,
                         "containers": [{"name": "registry", "image": REGISTRY,
                                         "ports": [{"containerPort": 5000}],
                                         "readinessProbe": {"httpGet": {"path": "/v2/", "port": 5000},
                                                            "periodSeconds": 1},
                                         "resources": {"requests": {"cpu": "15m", "memory": "32Mi"},
                                                       "limits": {"cpu": "200m", "memory": "128Mi"}},
                                         "volumeMounts": [_mount("store", "/var/lib/registry", False)]}],
                         "volumes": [_volume("store", emptyDir={"sizeLimit": "64Mi"})]}})
    lab.kubectl("wait", "--for=condition=Ready", "pod/attestation-registry", "--timeout=70s", timeout=80)


def _registry_call(lab, name, phase, artifacts):
    _configmap(lab, name, artifacts=artifacts)
    container = _container("client", PYTHON, ["python", "-B", "/app/registry.py", phase],
                           [_mount("code", "/app"), _mount("artifacts", "/artifacts")])
    volumes = [_volume("code", configMap={"name": "training-code"}),
               _volume("artifacts", configMap={"name": name})]
    return json.loads(_job(lab, name, container, volumes))


def run(lab):
    _configmap(lab, "training-code", scripts={name: (HERE / name).read_text()
                                             for name in ("pipeline.py", "registry.py")})
    materials = {TRAIN_INPUT: _canonical({"dataset": "inert-linear-v1", "records": [[0, 1], [1, 3], [2, 5]]})}
    trained = _step(lab, "training", materials, (INTERMEDIATE, MODEL))
    packaged = _step(lab, "packaging", {**materials, **trained}, (PACKAGE, PROVENANCE))
    all_artifacts = {**materials, **trained, **packaged}
    model = json.loads(trained[MODEL])
    package = json.loads(packaged[PACKAGE])
    lab.check("positive", "Training and packaging produce the permitted release",
              model["parameters"] == {"bias": 1.0, "weight": 2.0}
              and json.loads(trained[INTERMEDIATE]) == model["parameters"] and package["model"] == model,
              {"model_parameters": model["parameters"], "package_sha256": _digest(packaged[PACKAGE])})

    _registry(lab)
    no_attestation = _registry_call(lab, "registry-before-attest", "off", {PACKAGE: packaged[PACKAGE]})
    lab.check("red", "Before attestation generation the model package is retrievable, but has no attestation index",
              no_attestation["referrers_status"] == 404, {"index_status": no_attestation["referrers_status"]})

    public, envelopes = _attest(lab, all_artifacts)
    expectations = {"training": ((TRAIN_INPUT,), (INTERMEDIATE, MODEL)),
                    "packaging": ((TRAIN_INPUT, INTERMEDIATE, MODEL), (PACKAGE, PROVENANCE))}
    statements = _verify(lab, public, envelopes, expectations, all_artifacts)
    lab.check("green", "Each authenticated step statement binds its exact inputs and outputs",
              set(statements) == set(expectations),
              {"steps": {name: [len(materials), len(products)] for name, (materials, products) in expectations.items()}})

    fetched = _registry_call(lab, "registry-after-attest", "on", {
        PACKAGE: packaged[PACKAGE],
        **{step + ".envelope": envelope for step, envelope in envelopes.items()},
    })
    attached = {step: "sha256:" + _digest(envelope) for step, envelope in envelopes.items()}
    lab.check("green", "The two verified OCI attachments round-trip by digest for the original package",
              fetched["subject"] == no_attestation["subject"] and fetched["attestations"] == attached,
              {"subject": fetched["subject"], "attestation_steps": sorted(fetched["attestations"]),
               "attachment_bytes_match": fetched["attestations"] == attached})
    evidence = {"subjects": {name: _digest(raw) for name, raw in all_artifacts.items()},
                "oci_result": fetched, "statements": statements, "fixture_public_key": public.decode(),
                "envelopes": {name: json.loads(value) for name, value in envelopes.items()}}
    (lab.evidence / "training-step-attestations.json").write_text(json.dumps(evidence, indent=2) + "\n")
