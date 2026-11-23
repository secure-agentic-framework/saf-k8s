"""Check deployment-aware retention against a disposable OCI Distribution registry."""
from datetime import datetime, timezone
from hashlib import sha256
from http.client import HTTPConnection
import json
from pathlib import Path
import re
import time
from urllib.parse import parse_qsl, urlencode, urlsplit

from fixtures import BUSYBOX_IMAGE

ROOT = Path(__file__).resolve().parent
REGISTRY = (
    "docker.io/library/registry:3.0.0@sha256:"
    "6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
)
SKOPEO = (
    "quay.io/skopeo/stable:v1.20.0@sha256:"
    "47853bb9fb24202af9110531ebd6e43c5f97701254ca290596640290d17942f4"
)
IMAGE_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
SCOPE = (
    "One owned Kubernetes v1.36.1 cluster and pinned OCI Distribution registry. A running "
    "Deployment uses an exact digest. A disposable direct deletion proves the registry can "
    "remove its manifest despite that running workload. The same digest is restored and "
    "preserved by a cleanup rule that reads the live deployment and uses fixed-age records. "
    "A recent Helm chart and an older retained model fixture remain fetchable, while a "
    "separate expired model manifest and unique blob are collected. Coverage of production "
    "replicas, all workload sources, legal holds, signatures and provider policy remains separate."
)


def request(port, method, path, data=None, headers=None):
    connection = HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request(method, path, body=data, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read(2**22), dict(response.getheaders())
    finally:
        connection.close()


def content_digest(data):
    return "sha256:" + sha256(data).hexdigest()


def descriptor(media_type, content):
    return {"mediaType": media_type, "size": len(content), "digest": content_digest(content)}


def upload_blob(lab, port, repository, content):
    digest = content_digest(content)
    status, _, headers = request(port, "POST", f"/v2/{repository}/blobs/uploads/", b"")
    if status != 202:
        lab.block(f"The owned registry did not open a blob upload: {status}")
    location = urlsplit(headers["Location"])
    prefix = f"/v2/{repository}/blobs/uploads/"
    if not location.path.startswith(prefix):
        lab.block("Unexpected upload location from the owned registry")
    query = urlencode([*parse_qsl(location.query), ("digest", digest)])
    status, _, _ = request(port, "PUT", f"{location.path}?{query}", content,
                           {"Content-Type": "application/octet-stream"})
    if status != 201:
        lab.block(f"The owned registry did not store the fixture blob: {status}")


def model_artifact(lab, port, tag, content):
    repository = "releases/models"
    config = b"{}"
    for blob in (config, content):
        upload_blob(lab, port, repository, blob)
    manifest = json.dumps({
        "schemaVersion": 2, "mediaType": IMAGE_MANIFEST,
        "artifactType": "application/vnd.saf.fixture.model",
        "config": descriptor("application/vnd.oci.empty.v1+json", config),
        "layers": [descriptor("application/vnd.saf.fixture.model.v1+text", content)],
    }, sort_keys=True).encode()
    status, _, _ = request(port, "PUT", f"/v2/{repository}/manifests/{tag}", manifest,
                           {"Content-Type": IMAGE_MANIFEST})
    if status != 201:
        lab.block(f"The owned registry did not store the model manifest: {status}")
    return {"repository": repository, "digest": content_digest(manifest), "type": "model",
            "blob": content_digest(content)}


def manifest(port, record, method="GET"):
    path = f"/v2/{record['repository']}/manifests/{record['digest']}"
    return request(port, method, path, headers={"Accept": IMAGE_MANIFEST})


def contents_available(port, record):
    status, content, _ = manifest(port, record)
    if status != 200 or content_digest(content) != record["digest"]:
        return False
    document = json.loads(content)
    descriptors = [document["config"], *document["layers"]]
    return all(request(port, "HEAD", f"/v2/{record['repository']}/blobs/{layer['digest']}")[0] == 200
               for layer in descriptors)


def registry_port(lab, registry):
    address = lab.command("docker", "port", registry, "5000/tcp").stdout.strip()
    match = re.fullmatch(r"127\.0\.0\.1:(\d+)", address)
    if not match:
        lab.block("The owned registry did not have a loopback-only published port")
    port = int(match[1])
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            if request(port, "GET", "/v2/")[0] == 200:
                return port
        except OSError:
            pass
        time.sleep(0.4)
    lab.block("The owned registry did not become ready")


def seed_image(lab, node, network, alias):
    temporary = lab.kubeconfig.parent
    host = temporary / "hosts.toml"
    host.write_text(f'[host."http://{alias}:5000"]\ncapabilities = ["pull", "resolve"]\n')
    settings = f"/etc/containerd/certs.d/{alias}:5000"
    lab.command("docker", "exec", node, "mkdir", "-p", settings)
    lab.command("docker", "cp", str(host), f"{node}:{settings}/hosts.toml")
    staging = temporary / "seed"
    staging.mkdir(mode=0o700)
    archive = staging / "fixture.tar"
    lab.command("docker", "image", "save", "--output", str(archive), BUSYBOX_IMAGE, timeout=110)
    digest = staging / "image-digest"
    lab.command("docker", "run", "--rm", "--network", network, "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "--volume", f"{staging}:/fixture",
                SKOPEO, "copy", "--format", "oci", "--dest-tls-verify=false",
                "--digestfile", "/fixture/image-digest", "docker-archive:/fixture/fixture.tar",
                f"docker://{alias}:5000/releases/images:deployed", timeout=110)
    return {"repository": "releases/images", "digest": digest.read_text().strip(), "type": "image"}


def seed_chart(lab, port):
    source = lab.kubeconfig.parent / "fixture-chart"
    source.mkdir()
    (source / "Chart.yaml").write_text("apiVersion: v2\nname: fixture-chart\nversion: 0.1.0\n")
    lab.command("helm", "package", str(source), "--destination", str(source))
    lab.command("helm", "push", str(source / "fixture-chart-0.1.0.tgz"),
                f"oci://127.0.0.1:{port}/releases/charts", "--plain-http",
                "--registry-config", str(lab.kubeconfig.parent / "helm-registry.json"))
    repository = "releases/charts/fixture-chart"
    status, data, _ = request(port, "GET", f"/v2/{repository}/manifests/0.1.0",
                              headers={"Accept": IMAGE_MANIFEST})
    if status != 200:
        lab.block("The packaged Helm fixture was not present in the OCI registry")
    return {"repository": repository, "digest": content_digest(data), "type": "chart"}


def deploy(lab, alias, record):
    image = f"{alias}:5000/{record['repository']}@{record['digest']}"
    selector = {"app": "retained-release"}
    lab.create({
        "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "retained-release"},
        "spec": {"replicas": 1, "selector": {"matchLabels": selector}, "template": {
            "metadata": {"labels": selector},
            "spec": {"containers": [{
                "name": "marker", "image": image, "imagePullPolicy": "Always",
                "command": ["sh", "-ec", "printf retained-release; sleep 600"],
            }]},
        }},
    })
    ready = lab.kubectl("rollout", "status", "deployment/retained-release", "--timeout=90s",
                        timeout=100, allow_failure=True)
    if ready.returncode:
        lab.kubectl("describe", "pods", "-l", "app=retained-release", allow_failure=True)
        lab.block("The deployment did not pull and run the exact fixture digest")
    pod = json.loads(lab.kubectl("get", "po", "-l", "app=retained-release", "-o", "json").stdout)["items"][0]
    statuses = pod["status"]["containerStatuses"]
    matched = len(statuses) == 1 and statuses[0]["ready"] and statuses[0]["imageID"].endswith(record["digest"])
    evidence = {"ready": len(statuses) == 1 and statuses[0]["ready"], "exact_digest_used": matched}
    lab.check("positive", "A Ready deployment runs the registry's exact immutable digest", matched, evidence)


def protected_digests(lab):
    deployments = json.loads(lab.kubectl("get", "deployments", "-o", "json").stdout)
    return {
        container["image"].rsplit("@", 1)[-1]
        for item in deployments["items"] if item["status"].get("readyReplicas", 0)
        for container in item["spec"]["template"]["spec"]["containers"]
        if "@sha256:" in container["image"]
    }


def cleanup_candidates(lab, records, clock, retention):
    in_use = protected_digests(lab)
    return [
        record for record in records
        if record["digest"] not in in_use and not record.get("hold", False)
        and (clock - datetime.fromisoformat(record["released_at"])).days >= retention[record["type"]]
    ]


def start_registry(lab, name, network, volume, config, alias):
    lab.command("docker", "run", "--detach", "--name", name, "--network", network,
                "--network-alias", alias, "--publish", "127.0.0.1::5000",
                "--volume", f"{volume}:/var/lib/registry", "--volume", f"{config}:/fixture.yml:ro",
                REGISTRY, "serve", "/fixture.yml")


def exercise(lab, registry, node, network, volume, config, alias):
    port = registry_port(lab, registry)
    image = seed_image(lab, node, network, alias)
    deploy(lab, alias, image)
    status, saved, headers = manifest(port, image)
    if status != 200 or content_digest(saved) != image["digest"]:
        lab.block("Unable to obtain the exact deployed OCI image manifest")
    removed, _, _ = manifest(port, image, "DELETE")
    missing = manifest(port, image)[0] == 404
    deploy_kept_running = image["digest"] in protected_digests(lab)
    lab.check("red", "A running workload does not keep a directly deleted registry manifest available",
              removed == 202 and missing and deploy_kept_running,
              {"registry_delete_accepted": removed == 202, "manifest_missing": missing,
               "deployment_remains_ready": deploy_kept_running})
    stored, _, _ = request(port, "PUT", f"/v2/{image['repository']}/manifests/deployed",
                           saved, {"Content-Type": headers["Content-Type"]})
    if stored != 201 or manifest(port, image)[0] != 200:
        lab.block("Unable to restore the same owned manifest for the green fixture")

    chart = seed_chart(lab, port)
    held = model_artifact(lab, port, "held", b"inert fixture model under hold")
    obsolete = model_artifact(lab, port, "expired", b"inert independently expired fixture")
    records = [
        {**image, "released_at": "2026-01-01T00:00:00+00:00"},
        {**chart, "released_at": "2026-02-08T00:00:00+00:00"},
        {**held, "released_at": "2026-01-01T00:00:00+00:00", "hold": True},
        {**obsolete, "released_at": "2026-01-01T00:00:00+00:00"},
    ]
    retention = json.loads((ROOT / "retention.json").read_text())
    before = {row["digest"]: manifest(port, row)[0] for row in records}
    eligible = cleanup_candidates(lab, records, datetime(2026, 2, 12, tzinfo=timezone.utc), retention)
    if [row["digest"] for row in eligible] != [obsolete["digest"]] or set(before.values()) != {200}:
        lab.block("The owned retention policy did not select exactly the obsolete fixture")
    removal = [manifest(port, row, "DELETE")[0] for row in eligible]
    expired_blob = f"/v2/{obsolete['repository']}/blobs/{obsolete['blob']}"
    pre_gc = request(port, "GET", expired_blob)[0] == 200
    lab.check("green", "Cleanup expires only the unused model manifest and leaves physical collection separate",
              removal == [202] and manifest(port, obsolete)[0] == 404 and pre_gc,
              {"cleanup_only_expired_model": removal == [202], "manifest_absent": manifest(port, obsolete)[0] == 404,
               "orphan_blob_present_before_gc": pre_gc})

    # Stop the fixture registry so the isolated collector owns the storage while it sweeps.
    binary = lab.command("docker", "exec", registry, "sh", "-c", "command -v registry").stdout.strip()
    if not binary.startswith("/"):
        lab.block("Unable to locate the registry garbage collector")
    lab.command("docker", "stop", registry)
    lab.command("docker", "run", "--rm", "--entrypoint", binary,
                "--volume", f"{volume}:/var/lib/registry", "--volume", f"{config}:/fixture.yml:ro",
                REGISTRY, "garbage-collect", "/fixture.yml", timeout=60)
    lab.command("docker", "start", registry)
    port = registry_port(lab, registry)

    retained = {name: contents_available(port, record)
                for name, record in (("deployed_image", image), ("recent_chart", chart), ("held_model", held))}
    expired = manifest(port, obsolete)[0] == 404 and request(port, "GET", expired_blob)[0] == 404
    lab.check("positive", "Garbage collection removes the orphan while kept artifacts remain retrievable",
              all(retained.values()) and expired, {**retained, "expired_manifest_and_blob_absent": expired})
    (lab.evidence / "retention-observations.json").write_text(
        json.dumps({**retained, "workload_still_ready": deploy_kept_running,
                    "expired_manifest_and_blob_absent": expired}, indent=2, sort_keys=True) + "\n")


def run(lab):
    node = f"{lab.cluster}-control-plane"
    registry = f"{lab.cluster}-release-registry"
    network = f"{lab.cluster}-releases"
    volume = f"{lab.cluster}-registry-data"
    config = ROOT / "registry.yml"
    created_network = created_volume = created_registry = False
    try:
        lab.command("docker", "network", "create", network)
        created_network = True
        lab.command("docker", "network", "connect", network, node)
        lab.command("docker", "volume", "create", volume)
        created_volume = True
        start_registry(lab, registry, network, volume, config, registry)
        created_registry = True
        exercise(lab, registry, node, network, volume, config, registry)
    finally:
        removed = True
        if created_registry:
            removed &= lab.command("docker", "rm", "-f", registry, allow_failure=True).returncode == 0
        if created_network:
            lab.command("docker", "network", "disconnect", "-f", network, node, allow_failure=True)
            removed &= lab.command("docker", "network", "rm", network, allow_failure=True).returncode == 0
        if created_volume:
            removed &= lab.command("docker", "volume", "rm", volume, allow_failure=True).returncode == 0
        lab.check("positive", "The fixture registry, network and storage were removed", removed,
                  {"fixture_resources_removed": removed})
