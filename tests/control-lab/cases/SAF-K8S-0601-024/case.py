"""Verify strict authorization for one synthetic cached private image."""
import base64
from collections import Counter
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid
from urllib.parse import unquote

from fixtures import BUSYBOX_IMAGE


NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
REGISTRY_IMAGE = (
    "docker.io/library/registry:3.0.0@sha256:"
    "6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
)
SKOPEO_IMAGE = (
    "quay.io/skopeo/stable:v1.20.0@sha256:"
    "47853bb9fb24202af9110531ebd6e43c5f97701254ca290596640290d17942f4"
)
PRELOAD_IMAGE = (
    "docker.io/library/busybox:1.36.1@sha256:"
    "73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
)
NAMESPACE = "saf-test"
SCOPE = (
    "One fresh Kubernetes v1.36.1 kind node and a dedicated Docker network attached "
    "only to that node and the fixture registry. A digest-pinned synthetic BusyBox image is pushed to "
    "a temporary authenticated loopback registry, pulled by kubelet into that "
    "node's cache, then challenged with imagePullPolicy Never under effective "
    "KubeletEnsureSecretPulledImages=true and AlwaysVerify. The no-identity Pod "
    "must remain container-free with ErrImageNeverPull; a Pod with the exact same "
    "synthetic registry identity must reuse the cached digest without registry "
    "manifest/blob access. IfNotPresent checks both approved reuse and a rejected "
    "registry fallback. An independently imported private fixture also needs "
    "successful registry authorization before reuse. Provider configuration, "
    "rotation, revocation, multi-node behavior and weaker policies are outside the case."
)

def _quiet(args, *, env, input_text=None, timeout=45, allow_failure=False):
    """Run a credential-adjacent command without copying output to commands.log."""
    try:
        result = subprocess.run(args, input=input_text, text=True, capture_output=True,
                                env=env, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"{Path(args[0]).name} could not complete") from error
    if result.returncode and not allow_failure:
        raise RuntimeError(f"{Path(args[0]).name} returned a failure")
    return result


def prepare_kind(lab, temporary):
    """Configure the owned kubelet before the normal runner provisions it."""
    config = Path(temporary) / "kind.yaml"
    config.write_text(
        "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\n"
        "kubeadmConfigPatches:\n- |\n"
        "  apiVersion: kubelet.config.k8s.io/v1beta1\n"
        "  kind: KubeletConfiguration\n"
        "  featureGates:\n"
        "    KubeletEnsureSecretPulledImages: true\n"
        "  imagePullCredentialsVerificationPolicy: AlwaysVerify\n"
        "nodes:\n- role: control-plane\n",
        encoding="utf-8",
    )
    return config


def _direct_kube(lab, *args, timeout=45, input_text=None):
    """Run kubectl without the standard command logger for sensitive observations."""
    return _quiet(
        ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
         f"kind-{lab.cluster}", f"--request-timeout={timeout - 5}s", *args],
        env=lab.env, input_text=input_text, timeout=timeout,
    )


def _registry_requests(raw):
    requests = []
    for line in raw.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = item.get("http.request.method") or item.get("http", {}).get("request", {}).get("method")
        uri = item.get("http.request.uri") or item.get("http", {}).get("request", {}).get("uri", "")
        status = item.get("http.response.status") or item.get("http", {}).get("response", {}).get("status")
        if isinstance(method, str) and isinstance(uri, str):
            requests.append({"method": method, "uri": unquote(uri.split("?", 1)[0]), "status": status})
    return requests


def _delta(before, after):
    identity = lambda item: (item["method"], item["uri"], item["status"])
    counts = Counter(map(identity, before))
    changed = []
    for item in after:
        key = identity(item)
        if counts[key]:
            counts[key] -= 1
        else:
            changed.append(item)
    return changed


def _registry_log(lab, name):
    result = _quiet(["docker", "logs", name], env=lab.env, allow_failure=True)
    return result.stdout + result.stderr


def _pod(name, image, secret=None, pull_policy="IfNotPresent"):
    spec = {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "containers": [{
            "name": "fixture", "command": ["sleep", "240"], "image": image,
            "imagePullPolicy": pull_policy,
            "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                          "limits": {"cpu": "100m", "memory": "32Mi"}},
            "securityContext": {
                "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                "runAsNonRoot": True, "runAsUser": 65532,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
        }],
    }
    if secret:
        spec["imagePullSecrets"] = [{"name": secret}]
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": NAMESPACE}, "spec": spec}


def _create_pod(lab, pod):
    # Pod data contains only synthetic names and a digest-pinned image reference.
    lab.create(pod)


def _get_pod(lab, name):
    return json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)


def _wait(lab, name, denied_reasons=(), timeout=120):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = _get_pod(lab, name)
        status = last.get("status", {})
        containers = status.get("containerStatuses", [])
        if any(c.get("state", {}).get("waiting", {}).get("reason") in denied_reasons
               for c in containers):
            return last
        if any(c.get("ready") for c in containers):
            return last
        if status.get("phase") in ("Failed", "Succeeded"):
            return last
        time.sleep(2)
    return last


def _effective_config(lab, node):
    raw = _direct_kube(lab, "get", f"--raw=/api/v1/nodes/{node}/proxy/configz").stdout
    config = json.loads(raw)["kubeletconfig"]
    gate = config.get("featureGates", {}).get("KubeletEnsureSecretPulledImages")
    policy = config.get("imagePullCredentialsVerificationPolicy")
    return gate is True and policy == "AlwaysVerify"


def _cached_digest(lab, node, digest):
    result = _quiet(["docker", "exec", node, "crictl", "images", "-o", "json"], env=lab.env)
    images = json.loads(result.stdout).get("images", [])
    return any(digest in json.dumps(image) for image in images)


def _preload_private_fixture(lab, seed, network, node, alias, previously_pulled):
    skopeo = [
        "docker", "run", "--rm", "--network", network, "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "--volume", f"{seed}:/fixture", SKOPEO_IMAGE,
    ]
    preload_archive = seed / "preloaded.tar"
    oci_image = "oci-archive:/fixture/preloaded.tar:busybox-preload"
    repo = f"{alias}:5000/fixture/preloaded"
    present = lab.command("docker", "image", "inspect", "--format", "{{.Id}}",
                          PRELOAD_IMAGE, allow_failure=True)
    if present.returncode:
        lab.command("docker", "pull", PRELOAD_IMAGE, timeout=180)
    lab.command("docker", "image", "save", "--output", str(seed / "preload-source.tar"),
                PRELOAD_IMAGE, timeout=90)
    _quiet(skopeo + ["copy", "--format", "oci", "docker-archive:/fixture/preload-source.tar", oci_image],
           env=lab.env, timeout=90)
    _quiet(skopeo + [
        "copy", "--preserve-digests", "--authfile", "/fixture/auth.json",
        "--dest-tls-verify=false", "--digestfile", "/fixture/preloaded-digest",
        oci_image, f"docker://{repo}:fixture",
    ], env=lab.env, timeout=90)
    digest = (seed / "preloaded-digest").read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        lab.block("The synthetic preload archive has no exact registry digest")
    image = f"{repo}@{digest}"

    runtime = ("docker", "exec", node, "ctr", "-n", "k8s.io", "images")
    # Stream the archive so the import does not depend on the node's tmpfs mounts.
    with preload_archive.open("rb") as archive:
        imported = subprocess.run(
            ["docker", "exec", "-i", node, "ctr", "-n", "k8s.io", "images",
             "import", "--base-name", repo, "-"],
            stdin=archive, capture_output=True, text=True, env=lab.env, timeout=90,
        )
    if imported.returncode != 0:
        lab.block(f"The owned OCI import failed: {imported.stderr.strip()}")
    output = lab.command(*runtime, "ls").stdout
    imported_name = f"{repo}:busybox-preload"
    rows = (line.split(maxsplit=3) for line in output.splitlines())
    if not any(len(row) >= 3 and row[0] == imported_name and row[2] == digest for row in rows):
        lab.block("The container runtime did not resolve the exact imported OCI manifest")
    lab.command(*runtime, "tag", imported_name, image)
    inspect = ["docker", "exec", node, "crictl", "inspecti"]
    earlier = json.loads(_quiet(inspect + [previously_pulled], env=lab.env).stdout)["status"]
    for _ in range(15):
        result = _quiet(inspect + [image], env=lab.env, allow_failure=True)
        if result.returncode == 0:
            status = json.loads(result.stdout)["status"]
            if image in status.get("repoDigests", []):
                if not status.get("id") or status["id"] == earlier.get("id"):
                    lab.block("The externally loaded fixture shares an earlier authorized runtime image identity")
                return image, digest
        time.sleep(1)
    lab.block("The CRI did not recognize the exact preloaded repository digest")


def _wait_registry(host, port):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        conn = HTTPConnection(host, port, timeout=2)
        try:
            conn.request("GET", "/v2/")
            response = conn.getresponse()
            if response.status == 401 and response.getheader("WWW-Authenticate", "").startswith("Basic"):
                return
        except OSError:
            pass
        finally:
            conn.close()
        time.sleep(0.3)
    raise RuntimeError("owned registry did not issue its expected authentication challenge")


def run(lab):
    registry = f"saf-private-registry-{uuid.uuid4().hex[:10]}"
    temp = Path(tempfile.mkdtemp(prefix="saf-private-image-"))
    os.chmod(temp, 0o700)
    registry_started = False
    network_created = False
    connected = False
    node = f"{lab.cluster}-control-plane"
    network = f"{lab.cluster}-private-image"
    try:
        for image in (NODE_IMAGE, REGISTRY_IMAGE, BUSYBOX_IMAGE, SKOPEO_IMAGE):
            lab.command("docker", "image", "inspect", "--format", "{{.Id}}", image)

        if not _effective_config(lab, f"{lab.cluster}-control-plane"):
            lab.block("effective kubelet configuration is not strict AlwaysVerify")

        prior = lab.command("docker", "network", "inspect", network, allow_failure=True)
        if prior.returncode == 0:
            lab.block("Generated Docker network name already exists")
        lab.command("docker", "network", "create", network)
        network_created = True
        lab.command("docker", "network", "connect", network, node)
        connected = True

        username = "saf-fixture-" + secrets.token_hex(6)
        password = secrets.token_urlsafe(32)
        auth_result = _quiet(["htpasswd", "-B", "-n", "-i", username], env=lab.env,
                             input_text=password + "\n")
        htpasswd = temp / "htpasswd"
        htpasswd.write_text(auth_result.stdout, encoding="utf-8")
        htpasswd.chmod(0o600)

        alias = "saf-registry-" + uuid.uuid4().hex[:10]
        lab.command(
            "docker", "run", "--detach", "--rm", "--name", registry,
            "--network", network, "--network-alias", alias,
            "--publish", "127.0.0.1::5000",
            "--env", "REGISTRY_LOG_FORMATTER=json",
            "--env", "REGISTRY_AUTH=htpasswd",
            "--env", "REGISTRY_AUTH_HTPASSWD_REALM=saf-test",
            "--env", "REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd",
            "--volume", f"{htpasswd}:/auth/htpasswd:ro", REGISTRY_IMAGE,
        )
        registry_started = True
        port_text = lab.command("docker", "port", registry, "5000/tcp").stdout.strip().splitlines()[0]
        match = re.fullmatch(r"127\.0\.0\.1:(\d+)", port_text)
        if not match:
            lab.block("owned registry did not bind a loopback-only endpoint")
        host_port = int(match.group(1))
        _wait_registry("127.0.0.1", host_port)

        hosts_dir = temp / "certs.d" / f"{alias}:5000"
        hosts_dir.mkdir(parents=True)
        hosts = hosts_dir / "hosts.toml"
        hosts.write_text(f'[host."http://{alias}:5000"]\ncapabilities = ["pull", "resolve"]\n',
                         encoding="utf-8")
        lab.command("docker", "exec", "--user", "0", node, "mkdir", "-p",
                    f"/etc/containerd/certs.d/{alias}:5000")
        lab.command("docker", "cp", str(hosts), f"{node}:/etc/containerd/certs.d/{alias}:5000/hosts.toml")

        seed = temp / "seed"
        seed.mkdir(mode=0o700)
        auth_value = base64.b64encode(f"{username}:{password}".encode()).decode()
        authfile = seed / "auth.json"
        authfile.write_text(json.dumps({"auths": {f"{alias}:5000": {"auth": auth_value}}}),
                           encoding="utf-8")
        authfile.chmod(0o600)
        del auth_value
        archive = seed / "fixture.tar"
        lab.command("docker", "image", "save", "--output", str(archive), BUSYBOX_IMAGE, timeout=100)
        digest_file = seed / "digest"
        _quiet([
            "docker", "run", "--rm", "--network", network, "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--volume", f"{seed}:/fixture",
            SKOPEO_IMAGE, "copy", "--authfile", "/fixture/auth.json",
            "--dest-tls-verify=false", "--digestfile", "/fixture/digest",
            "docker-archive:/fixture/fixture.tar", f"docker://{alias}:5000/fixture/busybox:owned",
        ], env=lab.env, timeout=180)
        digest = digest_file.read_text(encoding="utf-8").strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            lab.block("synthetic registry copy did not return an immutable digest")
        image = f"{alias}:5000/fixture/busybox@{digest}"

        # Create the Secret from a mode-0600 temporary file. No credential value
        # appears in kubectl arguments, pod payloads, receipt fields or command logs.
        docker_config = {"auths": {f"{alias}:5000": {
            "username": username, "password": password,
            "auth": base64.b64encode(f"{username}:{password}".encode()).decode(),
        }}}
        secret_file = temp / "dockerconfigjson"
        secret_file.write_text(json.dumps(docker_config), encoding="utf-8")
        secret_file.chmod(0o600)
        del docker_config, password
        lab.kubectl("create", "secret", "generic", "registry-identity",
                    "--type=kubernetes.io/dockerconfigjson",
                    "--from-file=.dockerconfigjson=" + str(secret_file))

        cached_before = _cached_digest(lab, node, digest)
        lab.check("red", "The owned node does not already cache the exact seeded registry digest",
                  not cached_before, {"exact_digest_already_cached": cached_before})

        first = "authenticated-first"
        before = _registry_requests(_registry_log(lab, registry))
        _create_pod(lab, _pod(first, image, "registry-identity"))
        first_state = _wait(lab, first)
        first_status = ((first_state or {}).get("status", {}).get("containerStatuses") or [{}])[0]
        first_id = first_status.get("imageID", "")
        after = _registry_requests(_registry_log(lab, registry))
        initial_delta = _delta(before, after)
        manifest_get = any(x["method"] == "GET" and "/manifests/" in x["uri"] and x["status"] == 200
                           for x in initial_delta)
        blob_get = any(x["method"] == "GET" and "/blobs/" in x["uri"] and x["status"] == 200
                       for x in initial_delta)
        first_ok = bool(first_status.get("ready")) and digest in first_id and manifest_get and blob_get
        lab.check("green", "Authenticated kubelet pull fetches and starts the exact pinned fixture",
               first_ok, {"pod_ready": bool(first_status.get("ready")),
                          "image_id_matches_digest": digest in first_id,
                          "registry_manifest_get_200": manifest_get,
                          "registry_blob_get_200": blob_get})

        cached = _cached_digest(lab, node, digest)
        lab.check("positive", "The exact immutable registry digest is present in the owned node cache",
               cached, {"digest_cached": cached, "digest_format": "sha256"})

        denied_name = "missing-identity"
        before = _registry_requests(_registry_log(lab, registry))
        _create_pod(lab, _pod(denied_name, image, pull_policy="Never"))
        denied_state = _wait(lab, denied_name, ("ErrImageNeverPull",))
        denied = denied_state or {}
        statuses = denied.get("status", {}).get("containerStatuses", [])
        waiting = sorted({c.get("state", {}).get("waiting", {}).get("reason", "")
                          for c in statuses} - {""})
        denied_uid = denied.get("metadata", {}).get("uid")
        events = json.loads(lab.kubectl(
            "get", "events", "--field-selector", f"involvedObject.uid={denied_uid}", "-o", "json",
        ).stdout).get("items", [])
        event_reasons = sorted({e.get("reason", "") for e in events})
        container_started = any(c.get("containerID") or c.get("state", {}).get("running") or
                                c.get("state", {}).get("terminated") for c in statuses)
        after = _registry_requests(_registry_log(lab, registry))
        denied_delta = _delta(before, after)
        denial_network = any("/manifests/" in x["uri"] or "/blobs/" in x["uri"] for x in denied_delta)
        scheduled_to_cache_node = denied.get("spec", {}).get("nodeName") == node
        denial_ok = (denied.get("status", {}).get("phase") == "Pending" and scheduled_to_cache_node
                     and "ErrImageNeverPull" in waiting and "ErrImageNeverPull" in event_reasons
                     and not container_started and not denial_network)
        lab.check("green", "Strict cached-only request without the required synthetic identity stays container-free",
               denial_ok, {"phase": denied.get("status", {}).get("phase"),
                           "scheduled_to_cache_node": scheduled_to_cache_node,
                           "expected_kubelet_event": "ErrImageNeverPull" in event_reasons,
                           "expected_waiting_reason": "ErrImageNeverPull" in waiting,
                           "container_started": container_started,
                           "registry_manifest_or_blob_request": denial_network})

        lab.kubectl("delete", "pod", denied_name, "--wait=true")
        second = "authorized-cache-reuse"
        before = _registry_requests(_registry_log(lab, registry))
        _create_pod(lab, _pod(second, image, "registry-identity", pull_policy="Never"))
        second_state = _wait(lab, second)
        second_status = ((second_state or {}).get("status", {}).get("containerStatuses") or [{}])[0]
        second_id = second_status.get("imageID", "")
        after = _registry_requests(_registry_log(lab, registry))
        reuse_delta = _delta(before, after)
        reuse_network = any("/manifests/" in x["uri"] or "/blobs/" in x["uri"] for x in reuse_delta)
        reuse_ok = bool(second_status.get("ready")) and second_id == first_id and digest in second_id and not reuse_network
        lab.check("positive", "The same authorized identity starts the exact cached digest without a registry pull",
               reuse_ok, {"pod_ready": bool(second_status.get("ready")),
                          "image_id_matches_digest": digest in second_id,
                          "image_id_unchanged_since_initial_pull": second_id == first_id,
                          "registry_manifest_or_blob_request": reuse_network,
                          "image_pull_policy": "Never"})
        authorized = "authorized-if-present"
        before = _registry_requests(_registry_log(lab, registry))
        _create_pod(lab, _pod(authorized, image, "registry-identity", pull_policy="IfNotPresent"))
        authorized_pod = _wait(lab, authorized) or {}
        authorized_status = (authorized_pod.get("status", {}).get("containerStatuses") or [{}])[0]
        authorized_delta = _delta(before, _registry_requests(_registry_log(lab, registry)))
        authorized_check = {
            "pod_ready": authorized_status.get("ready") is True,
            "same_cache_node": authorized_pod.get("spec", {}).get("nodeName") == node,
            "same_image_id": authorized_status.get("imageID") == first_id,
            "no_registry_manifest_or_blob_request": not any(
                "/manifests/" in request["uri"] or "/blobs/" in request["uri"]
                for request in authorized_delta
            ),
        }
        lab.check("positive", "IfNotPresent reuses the verified private digest under the authorized identity",
                  all(authorized_check.values()), authorized_check)

        missing = "missing-identity-if-present"
        before = _registry_requests(_registry_log(lab, registry))
        _create_pod(lab, _pod(missing, image, pull_policy="IfNotPresent"))
        missing_pod = _wait(lab, missing, ("ErrImagePull", "ImagePullBackOff")) or {}
        missing_status = (missing_pod.get("status", {}).get("containerStatuses") or [{}])[0]
        waiting = missing_status.get("state", {}).get("waiting", {}).get("reason")
        missing_delta = _delta(before, _registry_requests(_registry_log(lab, registry)))
        rejected = {
            "same_cache_node": missing_pod.get("spec", {}).get("nodeName") == node,
            "pending_image_pull": missing_pod.get("status", {}).get("phase") == "Pending"
            and waiting in ("ErrImagePull", "ImagePullBackOff"),
            "container_free": not missing_status.get("containerID")
            and not any(key in missing_status.get("state", {}) for key in ("running", "terminated")),
            "exact_digest_reported_missing_authorization": (
                digest in missing_status.get("state", {}).get("waiting", {}).get("message", "")
                and "no basic auth credentials" in
                missing_status.get("state", {}).get("waiting", {}).get("message", "")
            ),
            "no_successful_private_manifest_fetch": not any(
                request["uri"].endswith(f"/manifests/{digest}") and request["status"] == 200
                for request in missing_delta
            ),
            "exact_digest_remained_cached": _cached_digest(lab, node, digest),
        }
        lab.check("green", "IfNotPresent requires authorization and registry fallback rejects the unapproved identity",
                  all(rejected.values()), rejected)
        imported, imported_digest = _preload_private_fixture(lab, seed, network, node, alias, image)
        before = _registry_requests(_registry_log(lab, registry))
        preload_missing = "preloaded-no-identity"
        _create_pod(lab, _pod(preload_missing, imported, pull_policy="Never"))
        imported_denial = _wait(lab, preload_missing, ("ErrImageNeverPull",)) or {}
        denied_status = (imported_denial.get("status", {}).get("containerStatuses") or [{}])[0]
        after_denial = _registry_requests(_registry_log(lab, registry))
        denial = {
            "same_cache_node": imported_denial.get("spec", {}).get("nodeName") == node,
            "pending_image_pull": imported_denial.get("status", {}).get("phase") == "Pending"
            and denied_status.get("state", {}).get("waiting", {}).get("reason") == "ErrImageNeverPull",
            "no_container": not denied_status.get("containerID"),
            "no_image_download": not any(
                "/manifests/" in request["uri"] or "/blobs/" in request["uri"]
                for request in _delta(before, after_denial)
            ),
            "exact_preloaded_digest_cached": _cached_digest(lab, node, imported_digest),
            "separate_runtime_image_identity": True,
        }
        lab.check("green", "AlwaysVerify requires credentials for an exactly referenced out-of-band preload",
                  all(denial.values()), denial)

        preload_authorized = "preloaded-authorized-pull"
        _create_pod(lab, _pod(preload_authorized, imported, "registry-identity", pull_policy="Always"))
        imported_accept = _wait(lab, preload_authorized) or {}
        accepted_status = (imported_accept.get("status", {}).get("containerStatuses") or [{}])[0]
        preload_registry_delta = _delta(after_denial, _registry_requests(_registry_log(lab, registry)))
        # Keep only normalized HTTP fields for diagnosing the fixture. No headers or auth data.
        (lab.evidence / "preload-registry-requests.json").write_text(
            json.dumps(preload_registry_delta, indent=2) + "\n", encoding="utf-8",
        )
        comparison = {
            "pod_ready": accepted_status.get("ready") is True,
            "same_cache_node": imported_accept.get("spec", {}).get("nodeName") == node,
            "expected_image_id": imported_digest in accepted_status.get("imageID", ""),
            "registry_saw_exact_manifest_request": any(
                request["method"] in ("HEAD", "GET")
                and request["uri"].endswith(f"/manifests/{imported_digest}")
                for request in preload_registry_delta
            ),
        }
        lab.check("positive", "The authorized out-of-band fixture starts and the registry sees its exact manifest request",
                  all(comparison.values()), comparison)
    finally:
        registry_removed = not registry_started or lab.command(
            "docker", "rm", "--force", registry, allow_failure=True,
        ).returncode == 0
        if connected:
            lab.command("docker", "network", "disconnect", network, node, allow_failure=True)
        network_removed = not network_created or lab.command(
            "docker", "network", "rm", network, allow_failure=True,
        ).returncode == 0
        shutil.rmtree(temp)
    lab.check("positive", "The case removes its temporary authenticated registry and bridge",
              registry_removed and network_removed,
              {"registry_removed": registry_removed, "network_removed": network_removed})
