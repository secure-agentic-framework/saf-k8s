"""Retrieve and read the fixed inert OCI layer after the existing admission gate."""
import base64
import hashlib
import json
import time
from urllib.parse import urlencode, urlsplit
import urllib.error
import urllib.request


NAMESPACE = "saf-test"
CONSUMER_JOB = "saf-model-fixture-consumer"
CONSUMER_SOURCE = "saf-model-fixture-consumer-source"
EXPECTED_PAYLOAD = b"SAF inert model artifact fixture v1\n"


CONSUMER_PROGRAM = r'''import hashlib, json, os, ssl, urllib.request

base = os.environ["REGISTRY_URL"]
manifest_digest = os.environ["MANIFEST_DIGEST"]
layer_digest = os.environ["LAYER_DIGEST"]
artifact_digest = os.environ["ARTIFACT_DIGEST"]
context = ssl.create_default_context(cafile="/trust/registry-ca.crt")
headers = {"Accept": "application/vnd.oci.image.manifest.v1+json"}
def get(path):
    request = urllib.request.Request(base + path, headers=headers)
    with urllib.request.urlopen(request, context=context, timeout=15) as response:
        return response.read()
manifest_bytes = get("/v2/models/inert-fixture/manifests/" + manifest_digest)
assert "sha256:" + hashlib.sha256(manifest_bytes).hexdigest() == manifest_digest
manifest = json.loads(manifest_bytes)
assert len(manifest.get("layers", [])) == 1
descriptor = manifest["layers"][0]
assert descriptor["digest"] == layer_digest
assert descriptor["mediaType"] == "application/vnd.saf.fixture.model.v1"
layer = get("/v2/models/inert-fixture/blobs/" + layer_digest)
actual = "sha256:" + hashlib.sha256(layer).hexdigest()
assert actual == artifact_digest
assert layer == b"SAF inert model artifact fixture v1\n"
print(json.dumps({"manifest_digest": manifest_digest, "layer_digest": actual,
                  "manifest_retrieved_by_digest": True, "payload_hash_verified": True,
                  "fixed_inert_payload_consumed": True}, sort_keys=True))
'''


def _https(host_port, ca_file, path, method, body=None, content_type=None):
    url = f"https://127.0.0.1:{host_port}{path}"
    headers = {"Accept": "application/vnd.oci.image.manifest.v1+json"}
    if content_type:
        headers["Content-Type"] = content_type
    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=__import__("ssl").create_default_context(cafile=ca_file)),
    )
    try:
        return opener.open(request, timeout=12)
    except urllib.error.HTTPError as error:
        error.close()
        raise RuntimeError(f"Owned OCI registry returned HTTP {error.code} for {method} {urlsplit(path).path}") from None


def _push_blob(host_port, ca_file, repository, payload):
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    stem = f"/v2/{repository}/blobs/uploads/"
    with _https(host_port, ca_file, stem, "POST", b"") as started:
        location = urlsplit(started.headers["Location"])
    query = location.query + ("&" if location.query else "") + urlencode({"digest": digest})
    with _https(host_port, ca_file, location.path + "?" + query, "PUT", payload,
                "application/octet-stream") as uploaded:
        if uploaded.status != 201:
            raise RuntimeError("fixture registry did not accept an exact OCI blob")
    return digest


def _publish_fixture(host_port, ca_file, fixture):
    repository = "models/inert-fixture"
    artifact = base64.b64decode(fixture["artifact"], validate=True)
    config = base64.b64decode(fixture["config"], validate=True)
    manifest_bytes = base64.b64decode(fixture["manifest_canonical_json_base64"], validate=True)
    if hashlib.sha256(artifact).hexdigest() != fixture["artifact_sha256"]:
        raise RuntimeError("fixture layer does not match the signed artifact digest")
    if hashlib.sha256(manifest_bytes).hexdigest() != fixture["manifest_sha256"]:
        raise RuntimeError("fixture manifest does not match the signed manifest digest")
    manifest = json.loads(manifest_bytes)
    config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
    artifact_digest = "sha256:" + fixture["artifact_sha256"]
    if (manifest["config"]["digest"] != config_digest
            or manifest["layers"][0]["digest"] != artifact_digest
            or len(manifest["layers"]) != 1):
        raise RuntimeError("fixture descriptors do not identify the exact inert OCI bytes")
    _push_blob(host_port, ca_file, repository, config)
    _push_blob(host_port, ca_file, repository, artifact)
    with _https(host_port, ca_file, f"/v2/{repository}/manifests/case", "PUT",
                manifest_bytes, "application/vnd.oci.image.manifest.v1+json") as published:
        if published.status != 201:
            raise RuntimeError("fixture registry did not accept the exact OCI manifest")
    with _https(host_port, ca_file, f"/v2/{repository}/manifests/case", "HEAD") as observed:
        if observed.headers.get("Docker-Content-Digest") != "sha256:" + fixture["manifest_sha256"]:
            raise RuntimeError("registry manifest digest differs from the admitted signed digest")
    return repository, "sha256:" + fixture["manifest_sha256"], artifact_digest


def _job(registry_host, manifest_digest, layer_digest, artifact_digest):
    labels = {"saf.example.test/fixture": "0905-009-consumer"}
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": CONSUMER_JOB, "namespace": NAMESPACE, "labels": labels},
        "spec": {"backoffLimit": 0, "template": {"metadata": {"labels": labels}, "spec": {
            "automountServiceAccountToken": False, "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "volumes": [{"name": "source", "configMap": {"name": CONSUMER_SOURCE}},
                        {"name": "trust", "configMap": {"name": CONSUMER_SOURCE,
                                                            "items": [{"key": "registry-ca.crt",
                                                                       "path": "registry-ca.crt"}]}}],
            "containers": [{"name": "reader",
                "image": "docker.io/library/python:3.13.2-alpine@sha256:323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352",
                "imagePullPolicy": "IfNotPresent", "command": ["python", "/app/consume.py"],
                "env": [{"name": "REGISTRY_URL", "value": "https://" + registry_host},
                        {"name": "MANIFEST_DIGEST", "value": manifest_digest},
                        {"name": "LAYER_DIGEST", "value": layer_digest},
                        {"name": "ARTIFACT_DIGEST", "value": artifact_digest},
                        {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}],
                "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                              "limits": {"cpu": "100m", "memory": "96Mi"}},
                "volumeMounts": [{"name": "source", "mountPath": "/app", "readOnly": True},
                                 {"name": "trust", "mountPath": "/trust", "readOnly": True}],
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}}}],
        }}},
    }


def consume_verified_artifact(lab, fixture, helpers):
    """Run only after the accepted Deployment's exact image reference was read back."""
    r = helpers.RegistryFixture(lab)
    try:
        _, host_port = helpers._start_registry(r)
        helpers._registry_chart_values(r, json.loads(
            r.docker("inspect", r.registry_container, "--format",
                     "{{json .NetworkSettings.Networks.kind}}").stdout)["IPAddress"])
        repository, manifest_digest, artifact_digest = _publish_fixture(
            host_port, r.registry_ca, fixture)
        descriptor = json.loads(base64.b64decode(
            fixture["manifest_canonical_json_base64"], validate=True))["layers"][0]
        ca_b64 = base64.b64encode(r.registry_ca.read_bytes()).decode("ascii")
        source = {"apiVersion": "v1", "kind": "ConfigMap",
                  "metadata": {"name": CONSUMER_SOURCE, "namespace": NAMESPACE},
                  "data": {"consume.py": CONSUMER_PROGRAM},
                  "binaryData": {"registry-ca.crt": ca_b64}}
        lab.create(source)
        job = _job(r.registry, manifest_digest, descriptor["digest"], artifact_digest)
        lab.create(job)
        deadline = time.monotonic() + 75
        terminal = set()
        while time.monotonic() < deadline:
            current = json.loads(lab.kubectl("get", "job", CONSUMER_JOB, "-o", "json", timeout=12).stdout)
            terminal = {item["type"] for item in current.get("status", {}).get("conditions", [])
                        if item["status"] == "True"}
            if terminal & {"Complete", "Failed"}:
                break
            time.sleep(1)
        logs = lab.kubectl("logs", "job/" + CONSUMER_JOB, timeout=15, allow_failure=True)
        if "Complete" not in terminal or logs.returncode:
            lab.block("The scoped registry consumer Job did not complete. Its retained command output contains the diagnostic.")
        observed = json.loads(logs.stdout)
        expected = {"manifest_digest": manifest_digest, "layer_digest": artifact_digest,
                    "manifest_retrieved_by_digest": True, "payload_hash_verified": True,
                    "fixed_inert_payload_consumed": True}
        ok = observed == expected
        job_readback = json.loads(lab.kubectl("-n", NAMESPACE, "get", "job/" + CONSUMER_JOB,
                                               "-o", "json").stdout)
        succeeded = job_readback.get("status", {}).get("succeeded") == 1
        lab.check("positive", "The gated case workload retrieves and reads the admitted inert OCI bytes by digest",
                  ok and succeeded,
                  {"outcome": "retrieved-and-consumed", "registry_repository": repository,
                   "manifest_digest": manifest_digest, "layer_digest": artifact_digest,
                   "registry_manifest_digest_matches_admission": True,
                   "workload_job_succeeded": succeeded,
                   "fixed_payload_hash_verified": observed.get("payload_hash_verified") is True,
                   "raw_payload_logged": False})
    finally:
        try:
            r.clean()
        finally:
            for path in (r.work / "registry-ca.key", r.work / "registry.csr",
                         r.work / "registry.ext", r.work / "registry-ca.srl",
                         r.work / "registry-tls" / "tls.key"):
                path.unlink(missing_ok=True)
