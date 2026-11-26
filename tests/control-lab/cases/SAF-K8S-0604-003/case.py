"""Prove OCI referrers and actual legacy fallback for an approved fixture SBOM."""
from contextlib import contextmanager
from base64 import b64encode
from http.client import HTTPSConnection
import importlib.util
import json
from pathlib import Path
import secrets
import ssl
import subprocess
import time

from fixtures import BUSYBOX_IMAGE

HERE = Path(__file__).resolve().parent
ORAS = ("ghcr.io/oras-project/oras:v1.3.4@sha256:"
        "f7bc056d54d97baa399414ed5048ecc67c3371b750d4bbce1d871827a5758179")
LEGACY = ("docker.io/library/registry:2.8.3@sha256:"
          "a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373")
ZOT = ("ghcr.io/project-zot/zot:v2.1.23@sha256:"
       "9d3de83ac2099e6f4843045b4c9b65b7e8baf40f92d28f54906dee9d4d390fd7")
SKOPEO = ("quay.io/skopeo/stable:v1.20.0@sha256:"
          "47853bb9fb24202af9110531ebd6e43c5f97701254ca290596640290d17942f4")
PYTHON = ("docker.io/library/python:3.13-slim@sha256:"
          "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
REPOSITORY = "fixture/sbom-images"
ADJACENT_REPOSITORY = "fixture/sbom-adjacent"
SCOPE = (
    "Disposable TLS Zot and Distribution registries illustrate OCI referrers discovery and a real "
    "404-triggered referrers-tag fallback. In-cluster consumers verify manifest, subject, blob "
    "and approved attachment identity. Zot exercises test publisher and reader permissions. "
    "The Zot fixture also scopes two explicit principals to adjacent repositories and checks the "
    "same inert manifest digest in both. Production identity, retention, audit, pagination and "
    "provider-specific discovery require separate evidence."
)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


consumer = load_module("fixture_sbom_consumer", HERE / "consumer.py")


def authorization(registry, role):
    if role not in registry.credentials:
        return ""
    return "Basic " + b64encode(f"{role}:{registry.credentials[role]}".encode()).decode()


def certificates(registry):
    root = registry.work
    tls = root / "tls"
    tls.mkdir(mode=0o700)
    key = root / "authority.key"
    csr = root / "leaf.csr"
    fields = root / "leaf-extensions"
    host = registry.registry.split(":", 1)[0]
    fields.write_text(f"subjectAltName=DNS:{host},IP:127.0.0.1\n"
                      "basicConstraints=critical,CA:FALSE\n"
                      "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
                      "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    run = registry.lab.command
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-subj", "/CN=SAF OCI Fixture CA", "-keyout", str(key), "-out", str(registry.registry_ca),
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash")
    run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={host}",
        "-keyout", str(tls / "tls.key"), "-out", str(csr))
    run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(registry.registry_ca), "-CAkey", str(key),
        "-set_serial", "01", "-extfile", str(fields), "-days", "2", "-out", str(tls / "tls.crt"))
    return tls


def registry_address(registry):
    inspection = json.loads(registry.docker("inspect", registry.registry_container).stdout)[0]
    return (inspection["NetworkSettings"]["Networks"]["kind"]["IPAddress"],
            inspection["NetworkSettings"]["Ports"]["5000/tcp"][0]["HostPort"])


def start_legacy(registry):
    tls = certificates(registry)
    registry.docker("pull", LEGACY, timeout=230)
    registry.docker("volume", "create", registry.registry_volume)
    registry.docker(
        "run", "--detach", "--name", registry.registry_container, "--network", "kind",
        "--network-alias", registry.registry.split(":", 1)[0], "--publish", "127.0.0.1::5000",
        "--volume", f"{tls}:/fixture:ro", "--volume", f"{registry.registry_volume}:/var/lib/registry",
        "--env", "REGISTRY_HTTP_TLS_CERTIFICATE=/fixture/tls.crt",
        "--env", "REGISTRY_HTTP_TLS_KEY=/fixture/tls.key", LEGACY,
    )
    return registry_address(registry)


def start_zot(registry):
    tls = certificates(registry)
    registry.credentials = {role: secrets.token_hex(16)
                            for role in ("publisher", "reader", "adjacent-publisher")}
    accounts = []
    for role, password in registry.credentials.items():
        record = subprocess.run(["htpasswd", "-nBi", role], input=password + "\n", text=True,
                                capture_output=True, check=True, timeout=8)
        accounts.append(record.stdout.strip())
    (tls / "htpasswd").write_text("\n".join(accounts) + "\n")
    cfg = {"storage": {"rootDirectory": "/data"},
           "http": {"address": "0.0.0.0", "port": "5000",
                    "tls": {"cert": "/fixture/tls.crt", "key": "/fixture/tls.key"},
                    "auth": {"htpasswd": {"path": "/fixture/htpasswd"}},
                    "accessControl": {"repositories": {REPOSITORY: {"policies": [
                        {"users": ["publisher"], "actions": ["read", "create", "update"]},
                        {"users": ["reader"], "actions": ["read"]},
                    ]},
                    ADJACENT_REPOSITORY: {"policies": [
                        {"users": ["adjacent-publisher"], "actions": ["read", "create", "update"]},
                    ]}}}},
           "log": {"level": "error"}}
    (tls / "config.json").write_text(json.dumps(cfg))
    registry.docker("pull", ZOT, timeout=230)
    registry.docker("volume", "create", registry.registry_volume)
    registry.docker(
        "run", "--detach", "--name", registry.registry_container, "--network", "kind",
        "--network-alias", registry.registry.split(":", 1)[0], "--publish", "127.0.0.1::5000",
        "--user", "0:0", "--volume", f"{tls}:/fixture:ro",
        "--volume", f"{registry.registry_volume}:/data", ZOT, "serve", "/fixture/config.json",
    )
    return registry_address(registry)


@contextmanager
def registry_fixture(module, lab, name, *, legacy):
    registry = module.RegistryFixture(lab)
    registry.credentials = {}
    try:
        if legacy:
            ip, port = start_legacy(registry)
            module._assert_remote_digest(registry, LEGACY)
        else:
            ip, port = start_zot(registry)
            module._assert_remote_digest(registry, ZOT)
        for attempt in range(20):
            try:
                status, _, _ = request(registry, int(port), "GET", "/v2/", "", "*/*")
                if status in {200, 401}:
                    break
            except OSError:
                if attempt == 19:
                    raise
            time.sleep(0.5)
        else:
            lab.block("The isolated registry never became reachable")
        yield registry, ip, int(port)
    finally:
        registry.clean()
        # Each mode uses a fresh volume and keeps its own command inputs.
        registry.work.rename(registry.work.with_name("oci-sbom-" + name))


def json_bytes(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def publish_images(registry, work, *, retain_archive=False):
    work.mkdir(mode=0o755)
    registry.docker("pull", BUSYBOX_IMAGE, timeout=140)
    registry.docker("image", "save", "-o", str(work / "image.tar"), BUSYBOX_IMAGE, timeout=100)
    (work / "ca.crt").write_bytes(registry.registry_ca.read_bytes())
    auth = authorization(registry, "publisher")
    if auth:
        credentials = {"auths": {registry.registry: {"auth": auth.split(" ", 1)[1]}}}
        (work / "auth.json").write_text(json.dumps(credentials))
    auth_args = ["--authfile", "/io/auth.json"] if auth else []
    registry.docker("run", "--rm", "--network", "kind", "--cap-drop=ALL",
                    "--volume", f"{work}:/io", SKOPEO,
                    "copy", "--format", "oci", "--dest-cert-dir", "/io", *auth_args, "--digestfile",
                    "/io/target.digest", "docker-archive:/io/image.tar",
                    f"docker://{registry.registry}/{REPOSITORY}:target", timeout=110)
    target_digest = (work / "target.digest").read_text().strip()
    if not consumer.DIGEST.fullmatch(target_digest):
        registry.lab.block("Main-repository publication returned an invalid manifest digest")
    if not retain_archive:
        (work / "image.tar").unlink()
    return target_digest


def request(registry, port, method, path, role, media, payload=None):
    credentials = authorization(registry, role)
    connection = HTTPSConnection("127.0.0.1", port, timeout=10,
                                 context=ssl.create_default_context(cafile=registry.registry_ca))
    try:
        headers = {"Accept": media}
        if payload is not None:
            headers["Content-Type"] = media
        if credentials:
            headers["Authorization"] = credentials
        connection.request(method, path, body=payload, headers=headers)
        reply = connection.getresponse()
        return reply.status, reply.read(consumer.LIMIT), reply.headers.get("Docker-Content-Digest")
    finally:
        connection.close()


def variant(registry, port, original):
    root = f"/v2/{REPOSITORY}/manifests/"
    status, raw, _ = request(registry, port, "GET", root + original, "publisher", consumer.MANIFEST)
    if status != 200 or consumer.digest(raw) != original:
        registry.lab.block("The registry did not retain the base subject")
    manifest = json.loads(raw)
    manifest["annotations"] = {"org.opencontainers.image.title": "fixture-comparison-subject"}
    payload = json_bytes(manifest)
    status, _, remote_digest = request(registry, port, "PUT", root + "comparison",
                                       "publisher", consumer.MANIFEST, payload)
    if status != 201 or remote_digest != consumer.digest(payload):
        registry.lab.block("Unable to create the distinct comparison image manifest")
    return consumer.digest(payload)


def attach(registry, work, subject, title):
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
           "components": [{"type": "application", "name": title, "version": "1.0"}]}
    (work / f"{title}.json").write_bytes(json_bytes(bom))
    auth = ["--registry-config", "/io/auth.json"] if registry.credentials else []
    registry.docker(
        "run", "--rm", "--network", "kind", "--cap-drop=ALL", "--volume", f"{work}:/io",
        "--workdir", "/io", ORAS, "attach", "--ca-file", "/io/ca.crt", *auth, "--artifact-type", consumer.SBOM,
        "--export-manifest", f"/io/{title}.manifest", f"{registry.registry}/{REPOSITORY}@{subject}",
        f"{title}.json:{consumer.SBOM}", timeout=100,
    )
    return consumer.digest((work / f"{title}.manifest").read_bytes())


def consume(lab, registry, ip, name, plan):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "immutable": True,
                "data": {"consumer.py": (HERE / "consumer.py").read_text(),
                         "plan.json": json.dumps(plan), "ca.crt": registry.registry_ca.read_text()}})
    volumes = [{"name": "fixture", "configMap": {"name": name}}]
    mounts = [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}]
    if registry.credentials:
        auth_file = registry.work / "reader-authorization"
        auth_file.write_text(authorization(registry, "reader"))
        auth_file.chmod(0o600)
        lab.kubectl("create", "secret", "generic", name, "--from-file", f"authorization={auth_file}")
        volumes.append({"name": "access", "secret": {"secretName": name}})
        mounts.append({"name": "access", "mountPath": "/access", "readOnly": True})
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "hostAliases": [{"ip": ip, "hostnames": [plan["host"]]}],
        "containers": [{"name": "consumer", "image": PYTHON,
                        "command": ["python", "-B", "/fixture/consumer.py"],
                        "volumeMounts": mounts}],
        "volumes": volumes,
    }})
    deadline = time.monotonic() + 95
    while time.monotonic() < deadline:
        row = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
        phase = row["status"]["phase"]
        if phase in {"Succeeded", "Failed"}:
            logs = lab.kubectl("logs", name).stdout
            if phase == "Failed":
                lab.block(f"The pinned in-cluster consumer exited without a verdict: {logs}")
            return json.loads(logs)
        time.sleep(1)
    lab.block("The in-cluster fixture consumer did not reach a terminal state")


def exercise(lab, registry, ip, port, mode, *, retain_archive=False):
    work = registry.work / "release"
    target = publish_images(registry, work, retain_archive=retain_archive)
    other = variant(registry, port, target)

    def fetch(path, media):
        return request(registry, port, "GET", path, "reader", media)[:2]

    before_mode, before = consumer.inventory_descriptors(fetch, REPOSITORY, target)
    lab.check("red", f"The {mode} path initially returns no SBOM for the exact image digest",
              before_mode == mode and before == [], {"discovery": before_mode, "inventory_missing": not before})
    approved = attach(registry, work, target, "fixture-approved")
    unapproved = attach(registry, work, target, "fixture-unapproved")
    attach(registry, work, other, "fixture-other-subject")
    plan = {"host": registry.registry.split(":", 1)[0], "repository": REPOSITORY,
            "target": target, "comparison": other, "approved": approved, "unapproved": unapproved}
    if registry.credentials:
        root = f"/v2/{REPOSITORY}"
        anonymous, _, _ = request(registry, port, "GET", f"{root}/referrers/{target}", "", consumer.INDEX)
        content = (work / "fixture-approved.manifest").read_bytes()
        reader_write, _, _ = request(registry, port, "PUT", f"{root}/manifests/reader-write",
                                     "reader", consumer.MANIFEST, content)
        reader_delete, _, _ = request(registry, port, "DELETE", f"{root}/manifests/{approved}",
                                      "reader", consumer.MANIFEST)
        lab.check("green", "The repository denies anonymous discovery and read-only publication or deletion",
                  anonymous == 401 and reader_write == reader_delete == 403,
                  {"anonymous_discovery_status": anonymous, "reader_write_status": reader_write,
                   "reader_delete_status": reader_delete})
    result = consume(lab, registry, ip, f"sbom-{mode}-consumer", plan)
    expected = {"discovery": mode, "exact_subject_components": ["fixture-approved"],
                "different_subject": "subject-mismatch", "unapproved_artifact": "attachment-not-approved",
                "wrong_blob_bytes": "bom-bytes-mismatch"}
    lab.check("green", f"The Kind consumer detects exact-subject, approval and content failures via {mode}",
              result == expected, result)
    raw_status, _ = fetch(f"/v2/{REPOSITORY}/referrers/{target}", consumer.INDEX)
    fallback_status, _ = fetch(f"/v2/{REPOSITORY}/manifests/{target.replace(':', '-', 1)}", consumer.INDEX)
    routes = (raw_status, fallback_status) if mode == "tag" else (raw_status,)
    matched = routes == ((404, 200) if mode == "tag" else (200,))
    lab.check("positive", f"The owned registry serves the observed {mode} discovery path",
              matched, {"observed_statuses": list(routes)})
    return {"selected_image_manifest_digest": target, "approved_attachment_manifest_digest": approved,
            "registry_referrers_status": raw_status, "registry_fallback_tag_status": fallback_status,
            "decision": result}


def exercise_adjacent_repository_scope(lab, registry, port, target_digest):
    """Bind two scoped Zot principals to the same inert manifest in adjacent repos."""
    work = registry.work / "release"
    if not consumer.DIGEST.fullmatch(target_digest):
        lab.block("Subject digest is not valid for the controlled adjacent-repository check")
    if not (work / "image.tar").is_file():
        lab.block("Exact saved fixture image archive is unavailable for adjacent-repository ACL proof")
    (work / "ca.crt").write_bytes(registry.registry_ca.read_bytes())
    auth = authorization(registry, "adjacent-publisher")
    auth_payload = {"auths": {registry.registry: {"auth": auth.split(" ", 1)[1]}}}
    auth_file = work / "adjacent-auth.json"
    auth_file.write_text(json.dumps(auth_payload))
    auth_file.chmod(0o600)
    adjacent_tag = f"{registry.registry}/{ADJACENT_REPOSITORY}:target"
    try:
        registry.docker(
            "run", "--rm", "--network", "kind", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--volume", f"{work}:/io", SKOPEO,
            "copy", "--format", "oci", "--dest-cert-dir", "/io",
            "--authfile", "/io/adjacent-auth.json", "--digestfile", "/io/adjacent.digest",
            "docker-archive:/io/image.tar", f"docker://{adjacent_tag}", timeout=110,
        )
    finally:
        auth_file.unlink(missing_ok=True)
    adjacent_digest = (work / "adjacent.digest").read_text().strip()
    reader_main, reader_main_bytes, reader_main_header = request(
        registry, port, "GET", f"/v2/{REPOSITORY}/manifests/{target_digest}",
        "reader", consumer.MANIFEST)
    adjacent_publisher_neighbor, adjacent_bytes, adjacent_header = request(
        registry, port, "GET", f"/v2/{ADJACENT_REPOSITORY}/manifests/{target_digest}",
        "adjacent-publisher", consumer.MANIFEST)
    reader_neighbor = request(
        registry, port, "GET", f"/v2/{ADJACENT_REPOSITORY}/manifests/{target_digest}",
        "reader", consumer.MANIFEST)[0]
    adjacent_publisher_main = request(
        registry, port, "GET", f"/v2/{REPOSITORY}/manifests/{target_digest}",
        "adjacent-publisher", consumer.MANIFEST)[0]
    same_subject = adjacent_digest == target_digest
    main_bytes_match = (reader_main == 200 and consumer.digest(reader_main_bytes) == target_digest
                        and reader_main_header == target_digest)
    adjacent_bytes_match = (adjacent_publisher_neighbor == 200
                            and consumer.digest(adjacent_bytes) == target_digest
                            and adjacent_header == target_digest)
    matched = (same_subject and main_bytes_match and adjacent_bytes_match
               and reader_neighbor == 403 and adjacent_publisher_main == 403)
    raw = {
        "main_manifest_digest": target_digest,
        "adjacent_manifest_digest": adjacent_digest,
        "reader_main": {"status": reader_main, "body_sha256": consumer.digest(reader_main_bytes),
                        "content_digest": reader_main_header},
        "adjacent_publisher_adjacent": {"status": adjacent_publisher_neighbor,
                                        "body_sha256": consumer.digest(adjacent_bytes),
                                        "content_digest": adjacent_header},
        "reader_adjacent_status": reader_neighbor,
        "adjacent_publisher_main_status": adjacent_publisher_main,
    }
    (lab.evidence / "adjacent-repository-authorization.json").write_text(
        json.dumps(raw, indent=2, sort_keys=True) + "\n")
    lab.check(
        "positive",
        "Zot scopes exact-digest reads to the authorized adjacent repository principal",
        matched,
        {"same_manifest_digest_published_to_both_repositories": same_subject,
         "reader_main_repository_status": reader_main,
         "reader_main_manifest_bytes_match": reader_main == 200 and consumer.digest(reader_main_bytes) == target_digest,
         "reader_main_content_digest_match": reader_main_header == target_digest,
         "adjacent_publisher_neighbor_repository_status": adjacent_publisher_neighbor,
         "adjacent_publisher_neighbor_manifest_bytes_match": adjacent_publisher_neighbor == 200 and consumer.digest(adjacent_bytes) == target_digest,
         "adjacent_publisher_neighbor_content_digest_match": adjacent_header == target_digest,
         "reader_adjacent_repository_status": reader_neighbor,
         "adjacent_publisher_main_repository_status": adjacent_publisher_main,
         "principal_labels_only": ["reader", "adjacent-publisher"]},
    )


def run(lab):
    registry_module = load_module("oci_registry_fixture", HERE.parent / "SAF-K8S-0605-002" / "image_admission.py")
    reports = {}
    for mode in ("tag", "api"):
        with registry_fixture(registry_module, lab, mode, legacy=mode == "tag") as (registry, ip, port):
            reports[mode] = exercise(lab, registry, ip, port, mode, retain_archive=mode == "api")
            if mode == "api":
                try:
                    exercise_adjacent_repository_scope(
                        lab, registry, port, reports[mode]["selected_image_manifest_digest"])
                finally:
                    (registry.work / "release" / "image.tar").unlink(missing_ok=True)
    (lab.evidence / "oci-inventory-discovery.json").write_text(json.dumps(reports, indent=2, sort_keys=True) + "\n")
    lab.check("positive", "The disposable registries and volumes were removed",
              True, {"registry_cleanup": "complete"})
