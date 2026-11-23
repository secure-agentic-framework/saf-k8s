"""Exercise digest-scoped OCI ML-BOM attachment in an in-cluster registry."""
import hashlib
import json
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


HERE = Path(__file__).parent
NAMESPACE = "saf-test"
REGISTRY_IMAGE = (
    "docker.io/library/registry:3.0.0@sha256:"
    "6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
)
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
EMPTY_TYPE = "application/vnd.oci.empty.v1+json"
EMPTY = b"{}"
EMPTY_DIGEST = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
ARTIFACT_TYPE = "application/vnd.saf.ml-bom.v1+json"
PAYLOAD_TYPE = "application/vnd.saf.ml-bom.payload.v1+json"
REPOSITORY = "saf-fixture/models"
SCOPE = (
    "One disposable local Kubernetes v1.36.1 Kind cluster and the saf-test namespace. "
    "The case runs a digest-pinned Distribution 3.0.0 registry Pod behind an in-cluster "
    "Service, backed by a case-owned hostPath PersistentVolume/PersistentVolumeClaim. It "
    "publishes two inert synthetic OCI model manifests with distinct computed digests, "
    "attaches one synthetic ML-BOM as an OCI artifact to only the first digest, discovers "
    "and retrieves it, then deletes/recreates the registry Pod and repeats retrieval. "
    "Evidence is limited to allowlisted digests, status codes, sizes, Pod UIDs and booleans. "
    "It does not establish production retention, replication, backup, authorization, "
    "promotion workflow coverage, or ML-BOM generation quality."
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def descriptor(media_type, data):
    return {"mediaType": media_type, "digest": digest(data), "size": len(data)}


def model_manifest(model):
    payload = canonical(model["payload"])
    config = canonical({"architecture": "amd64", "os": "linux",
                        "rootfs": {"type": "layers", "diff_ids": [digest(payload)]}})
    manifest = canonical({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": descriptor("application/vnd.oci.image.config.v1+json", config),
        "layers": [descriptor(PAYLOAD_TYPE, payload)],
    })
    return {"manifest": manifest, "digest": digest(manifest), "config": config,
            "payload": payload}


class Registry:
    def __init__(self, base):
        self.base = base
        self.events = []
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(self, path, method="GET", body=None, content_type=None,
                accept=None, expected=(200,)):
        if not path.startswith("/") or "\n" in path:
            raise RuntimeError("invalid internal registry path")
        headers = {}
        if content_type:
            headers["Content-Type"] = content_type
        if accept:
            headers["Accept"] = accept
        request = urllib.request.Request(self.base + path, data=body, method=method,
                                         headers=headers)
        try:
            response = self.opener.open(request, timeout=10)
            status, response_headers, raw = response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            status, response_headers, raw = error.code, error.headers, error.read()
        safe_path = urllib.parse.urlsplit(path).path
        self.events.append({"method": method, "path": safe_path, "status": status,
                            "response_bytes": len(raw)})
        if status not in expected:
            raise RuntimeError(f"registry request failed: {method} {safe_path} returned {status}")
        return status, response_headers, raw

    def upload(self, payload):
        _, headers, _ = self.request(f"/v2/{REPOSITORY}/blobs/uploads/", "POST",
                                     body=b"", expected=(202,))
        location = headers.get("Location")
        if not location:
            raise RuntimeError("registry omitted blob upload location")
        parts = urllib.parse.urlsplit(location)
        if not parts.path.startswith(f"/v2/{REPOSITORY}/blobs/uploads/"):
            raise RuntimeError("registry returned an unexpected upload path")
        query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        query.append(("digest", digest(payload)))
        target = parts.path + "?" + urllib.parse.urlencode(query)
        self.request(target, "PUT", body=payload,
                     content_type="application/octet-stream", expected=(201,))

    def put_manifest(self, reference, raw):
        return self.request(f"/v2/{REPOSITORY}/manifests/{reference}", "PUT", body=raw,
                            content_type=OCI_MANIFEST, expected=(201,))[1]

    def fetch_manifest(self, reference):
        status, headers, raw = self.request(
            f"/v2/{REPOSITORY}/manifests/{urllib.parse.quote(reference, safe=':')}",
            accept=OCI_MANIFEST, expected=(200, 404))
        return status, headers, raw

    def upload_model(self, tag, model):
        for blob in (model["config"], model["payload"]):
            self.upload(blob)
        self.put_manifest(tag, model["manifest"])
        status, headers, raw = self.fetch_manifest(model["digest"])
        if status != 200 or raw != model["manifest"] or headers.get("Docker-Content-Digest") != model["digest"]:
            raise RuntimeError("registry did not return the exact model manifest at its digest")

    def referrers(self, subject_digest):
        path = f"/v2/{REPOSITORY}/referrers/{urllib.parse.quote(subject_digest, safe=':')}"
        status, headers, raw = self.request(path, accept=OCI_INDEX, expected=(200, 404))
        if status == 200:
            if headers.get("Content-Type", "").split(";")[0] != OCI_INDEX:
                raise RuntimeError("registry referrers API returned an unexpected media type")
            return json.loads(raw), "native-referrers-api"
        tag = subject_digest.replace(":", "-", 1)
        status, _, raw = self.request(f"/v2/{REPOSITORY}/manifests/{tag}",
                                      accept=OCI_INDEX, expected=(200, 404))
        if status == 404:
            return {"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": []}, "referrers-tag-fallback"
        return json.loads(raw), "referrers-tag-fallback"


def registry_pod(lab):
    return json.loads(lab.kubectl("get", "pods", "-l", "app=saf-registry", "-o", "json").stdout)


def wait_registry(lab):
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        state = registry_pod(lab)
        ready = [item for item in state.get("items", [])
                 if item.get("status", {}).get("phase") == "Running"
                 and any(c.get("ready") for c in item.get("status", {}).get("containerStatuses", []))]
        if ready:
            return ready[0]
        time.sleep(2)
    lab.block("In-cluster registry did not become Ready")


def start_forward(lab):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
               f"kind-{lab.cluster}", "--namespace", NAMESPACE,
               "port-forward", "--address=127.0.0.1", "service/saf-registry",
               f"{port}:5000"]
    process = subprocess.Popen(command, env=lab.env, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    registry = Registry(f"http://127.0.0.1:{port}")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("registry port-forward exited before readiness")
        try:
            status, _, _ = registry.request("/v2/", expected=(200,))
            if status == 200:
                return process, registry
        except (OSError, urllib.error.URLError, RuntimeError):
            time.sleep(.25)
    process.terminate()
    process.wait(timeout=5)
    raise RuntimeError("registry API did not become reachable through the case-owned port-forward")


def stop_forward(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def push_artifact(registry, subject, subject_manifest, bom):
    registry.upload(EMPTY)
    registry.upload(bom)
    artifact = canonical({
        "schemaVersion": 2, "mediaType": OCI_MANIFEST,
        "artifactType": ARTIFACT_TYPE,
        "config": {"mediaType": EMPTY_TYPE, "digest": EMPTY_DIGEST, "size": len(EMPTY)},
        "layers": [descriptor(PAYLOAD_TYPE, bom)],
        "subject": descriptor(OCI_MANIFEST, subject_manifest),
    })
    artifact_digest = digest(artifact)
    headers = registry.put_manifest(artifact_digest, artifact)
    acknowledged = headers.get("OCI-Subject")
    if acknowledged is not None and acknowledged != subject:
        raise RuntimeError("registry acknowledged attachment to a different subject digest")
    if acknowledged is None:
        index, _ = registry.referrers(subject)
        entry = {**descriptor(OCI_MANIFEST, artifact), "artifactType": ARTIFACT_TYPE}
        if not any(row.get("digest") == artifact_digest for row in index.get("manifests", [])):
            index.setdefault("schemaVersion", 2)
            index.setdefault("mediaType", OCI_INDEX)
            index.setdefault("manifests", []).append(entry)
            tag = subject.replace(":", "-", 1)
            registry.request(f"/v2/{REPOSITORY}/manifests/{tag}", "PUT", body=canonical(index),
                             content_type=OCI_INDEX, expected=(201,))
    return artifact, artifact_digest


def retrieve(registry, subject, expected_model, expected_bom):
    index, method = registry.referrers(subject)
    matches = [row for row in index.get("manifests", [])
               if row.get("artifactType") == ARTIFACT_TYPE]
    if len(matches) != 1:
        raise RuntimeError("expected exactly one discoverable ML-BOM attachment for the subject digest")
    descriptor_row = matches[0]
    status, headers, artifact = registry.fetch_manifest(descriptor_row["digest"])
    if status != 200 or digest(artifact) != descriptor_row["digest"]:
        raise RuntimeError("retrieved OCI artifact manifest failed its descriptor digest")
    if len(artifact) != descriptor_row.get("size"):
        raise RuntimeError("retrieved OCI artifact manifest size differs from its descriptor")
    manifest = json.loads(artifact)
    if manifest.get("subject") != descriptor(OCI_MANIFEST, expected_model["manifest"]):
        raise RuntimeError("retrieved ML-BOM OCI artifact has a different exact subject")
    layer, = manifest["layers"]
    status, _, payload = registry.request(
        f"/v2/{REPOSITORY}/blobs/{urllib.parse.quote(layer['digest'], safe=':')}",
        expected=(200,))
    if status != 200 or digest(payload) != layer["digest"] or payload != expected_bom:
        raise RuntimeError("retrieved ML-BOM bytes did not match their declared payload digest")
    bom = json.loads(payload)
    if bom.get("subject", {}).get("digest") != subject:
        raise RuntimeError("ML-BOM payload names a different model manifest digest")
    return {"artifact_digest": descriptor_row["digest"], "payload_digest": layer["digest"],
            "payload_size": len(payload), "manifest_size": len(artifact),
            "subject_digest": subject, "discovery": method,
            "payload_matches_expected": True, "payload_subject_matches": True}


def run(lab):
    server = json.loads(lab.kubectl("get", "--raw=/version").stdout).get("gitVersion")
    lab.check("positive", "Disposable API server is Kubernetes v1.36.1",
              server == "v1.36.1", {"server": server})
    fixtures = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
    if fixtures.get("format") != "saf-k8s-0905-043-fixtures-v1":
        lab.block("Unexpected synthetic ML-BOM fixture format")
    models = {key: model_manifest(value) for key, value in fixtures["models"].items()}
    version_one, version_two = models[fixtures["attached_version"]], models[fixtures["other_version"]]
    if version_one["digest"] == version_two["digest"]:
        lab.block("Synthetic model versions unexpectedly share a manifest digest")

    pv = {
        "apiVersion": "v1", "kind": "PersistentVolume",
        "metadata": {"name": "saf-0905-043-registry-data"},
        "spec": {"capacity": {"storage": "64Mi"}, "accessModes": ["ReadWriteOnce"],
                 "persistentVolumeReclaimPolicy": "Delete", "storageClassName": "",
                 "hostPath": {"path": "/var/lib/saf-0905-043-registry", "type": "DirectoryOrCreate"}},
    }
    pvc = {
        "apiVersion": "v1", "kind": "PersistentVolumeClaim",
        "metadata": {"name": "saf-registry-data", "namespace": NAMESPACE},
        "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": "",
                 "volumeName": pv["metadata"]["name"],
                 "resources": {"requests": {"storage": "64Mi"}}},
    }
    deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "saf-registry", "namespace": NAMESPACE},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "saf-registry"}},
            "template": {
                "metadata": {"labels": {"app": "saf-registry"}},
                "spec": {
                    "containers": [{
                        "name": "registry", "image": REGISTRY_IMAGE,
                        "ports": [{"containerPort": 5000}],
                        "resources": {"requests": {"cpu": "50m", "memory": "64Mi"},
                                      "limits": {"cpu": "500m", "memory": "256Mi"}},
                        "volumeMounts": [{"name": "registry-data", "mountPath": "/var/lib/registry"}],
                    }],
                    "volumes": [{"name": "registry-data", "persistentVolumeClaim":
                                 {"claimName": "saf-registry-data"}}],
                },
            },
        },
    }
    service = {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "saf-registry", "namespace": NAMESPACE},
        "spec": {"selector": {"app": "saf-registry"},
                 "ports": [{"name": "registry", "port": 5000, "targetPort": 5000}]},
    }
    lab.create(pv)
    lab.create(pvc)
    lab.create(deployment)
    lab.create(service)
    first_pod = wait_registry(lab)
    forward, registry = start_forward(lab)
    try:
        for tag, model in (("model-v1", version_one), ("model-v2", version_two)):
            registry.upload_model(tag, model)
        before_one, discovery = registry.referrers(version_one["digest"])
        before_two, second_discovery = registry.referrers(version_two["digest"])
        absent = not before_one.get("manifests") and not before_two.get("manifests")
        lab.check("red", "Both exact model version digests have no ML-BOM attachment before publication",
                  absent and discovery == second_discovery,
                  {"version_one_digest": version_one["digest"],
                   "version_two_digest": version_two["digest"],
                   "version_one_referrers": len(before_one.get("manifests", [])),
                   "version_two_referrers": len(before_two.get("manifests", [])),
                   "discovery": discovery})

        bom_fixture = fixtures["models"][fixtures["attached_version"]]
        bom = canonical({"bomFormat": "SAF-ML-BOM-fixture", "specVersion": "1",
                         "subject": {"name": bom_fixture["name"], "version": bom_fixture["version"],
                                     "digest": version_one["digest"]},
                         "components": bom_fixture["components"]})
        artifact, artifact_digest = push_artifact(
            registry, version_one["digest"], version_one["manifest"], bom)
        retrieved = retrieve(registry, version_one["digest"], version_one, bom)
        lab.check("green", "OCI discovery retrieves the attached ML-BOM whose manifest subject and payload digest match model v1",
                  retrieved["subject_digest"] == version_one["digest"]
                  and retrieved["payload_matches_expected"]
                  and retrieved["payload_subject_matches"]
                  and retrieved["payload_digest"] == digest(bom)
                  and retrieved["artifact_digest"] == artifact_digest,
                  {**retrieved, "expected_payload_digest": digest(bom),
                   "published_artifact_digest": digest(artifact),
                   "registry_image": REGISTRY_IMAGE})

        other, other_method = registry.referrers(version_two["digest"])
        lab.check("positive", "The distinct model v2 digest remains isolated from model v1 ML-BOM",
                  not other.get("manifests") and other_method == discovery,
                  {"model_v2_digest": version_two["digest"],
                   "model_v2_referrers": len(other.get("manifests", [])),
                   "discovery": other_method})

        prior_events = list(registry.events)
        stop_forward(forward)
        old_uid = first_pod["metadata"]["uid"]
        lab.kubectl("delete", "pod", first_pod["metadata"]["name"], "--wait=true", timeout=60)
        next_pod = wait_registry(lab)
        if next_pod["metadata"]["uid"] == old_uid:
            lab.block("Registry Pod was not recreated for the persistence check")
        forward, registry = start_forward(lab)
        after_restart = retrieve(registry, version_one["digest"], version_one, bom)
        lab.check("green", "The exact ML-BOM artifact and payload remain retrievable after registry Pod restart on case-owned persistent storage",
                  after_restart["artifact_digest"] == retrieved["artifact_digest"]
                  and after_restart["payload_digest"] == retrieved["payload_digest"]
                  and after_restart["subject_digest"] == version_one["digest"],
                  {**after_restart, "registry_pod_recreated": True,
                   "persistent_volume_claim": "saf-registry-data",
                   "artifact_digest_unchanged": after_restart["artifact_digest"] == retrieved["artifact_digest"]})
    finally:
        stop_forward(forward)

    runtime = {"control_id": "SAF-K8S-0905-043", "registry_image": REGISTRY_IMAGE,
               "namespace": NAMESPACE, "storage": "case-owned PVC backed by disposable Kind node hostPath",
               "version_digests": {"v1": version_one["digest"], "v2": version_two["digest"]},
               "attachment_digest": artifact_digest, "payload_digest": digest(bom),
               "pod_uids": {"before_restart": first_pod["metadata"]["uid"],
                            "after_restart": next_pod["metadata"]["uid"]},
               "http_events": prior_events + registry.events,
               "excluded": ["credentials", "request bodies", "response bodies", "registry logs"]}
    (lab.evidence / "registry-runtime.json").write_text(
        json.dumps(runtime, indent=2, sort_keys=True) + "\n", encoding="utf-8")
