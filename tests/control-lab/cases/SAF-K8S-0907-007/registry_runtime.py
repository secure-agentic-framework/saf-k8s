"""Exercise kubelet authentication to an isolated TLS-only OCI registry."""
from collections import Counter
import base64
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
BUSYBOX_IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
NAMESPACE = "saf-0907-0071-runtime"
SCOPE = (
    "Disposable Kubernetes v1.36.1 Kind cluster with one node. An ephemeral "
    "Distribution 3.0.0 registry uses TLS and bcrypt htpasswd authentication on "
    "a private Docker bridge shared only with the owned node and pinned Skopeo. "
    "One harmless BusyBox image is copied in, recorded as the run-local synthetic "
    "approved digest, then pulled once without imagePullSecrets and once with the "
    "matching Secret. Registry HTTP observations and Pod status/imageID distinguish "
    "401 refusal from a successful 200 manifest/blob pull. No admission policy or "
    "RBAC rule is installed. The parent 0907-007 placeholder image is not pullable. "
    "No signing, production, external registry, multi-node, or deployed-approval "
    "guarantee is tested."
)


def _quiet(args, *, env, input_text=None, timeout=60, allow_failure=False):
    """Keep credential-adjacent outputs out of the runner's command log."""
    try:
        result = subprocess.run(args, input=input_text, text=True, capture_output=True,
                                env=env, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"{Path(args[0]).name} could not complete") from error
    if result.returncode and not allow_failure:
        raise RuntimeError(f"{Path(args[0]).name} returned a failure")
    return result


def _pod(name, image, *, pull_secret=False):
    spec = {
        "restartPolicy": "Never",
        "automountServiceAccountToken": False,
        "serviceAccountName": "runtime-puller",
        "containers": [{
            "name": "fixture",
            "image": image,
            "imagePullPolicy": "Always",
            "command": ["/bin/sh", "-c", "echo saf-runtime-fixture-ready"],
            "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                          "limits": {"cpu": "100m", "memory": "32Mi"}},
            "securityContext": {
                "allowPrivilegeEscalation": False,
                "capabilities": {"drop": ["ALL"]},
                "runAsNonRoot": True,
                "runAsUser": 65534,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
        }],
    }
    if pull_secret:
        spec["imagePullSecrets"] = [{"name": "registry-identity"}]
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": NAMESPACE}, "spec": spec}


def _requests(raw):
    # Distribution v3 writes Apache combined access rows separately from its
    # structured request messages. The access row contains the actual status
    # sent to the client, including authentication challenges.
    response = re.compile(r'"(HEAD|GET) (\S+) HTTP/[^"]+" (\d{3}) ')
    found = []
    for line in raw.splitlines():
        match = response.search(line)
        if match:
            method, uri, status = match.groups()
            found.append({"method": method, "uri": uri.split("?", 1)[0], "status": int(status)})
    return found


def _delta(before, after):
    ident = lambda item: (item["method"], item["uri"], item["status"])
    counts = Counter(map(ident, before))
    changed = []
    for item in after:
        key = ident(item)
        if counts[key]:
            counts[key] -= 1
        else:
            changed.append(item)
    return changed


def _registry_log(lab, name):
    result = _quiet(["docker", "logs", name], env=lab.env, allow_failure=True)
    return result.stdout + result.stderr


def _pod_json(lab, name):
    return json.loads(lab.kubectl("-n", NAMESPACE, "get", "pod", name, "-o", "json").stdout)


def _registry_auth_denied(waiting):
    message = waiting.get("message", "").lower()
    return waiting.get("reason") in ("ErrImagePull", "ImagePullBackOff") and any(
        value in message for value in (
            "unauthorized", "authentication required", "not authorized", "no basic auth credentials",
        )
    )


def _wait_pod(lab, name, *, denied, timeout=100):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = _pod_json(lab, name)
        statuses = last.get("status", {}).get("containerStatuses", [])
        if denied:
            for status in statuses:
                waiting = status.get("state", {}).get("waiting", {})
                if _registry_auth_denied(waiting):
                    return last
        elif last.get("status", {}).get("phase") == "Succeeded" and any(
            status.get("state", {}).get("terminated", {}).get("reason") == "Completed" for status in statuses
        ):
            return last
        time.sleep(1)
    return last


def _wait_registry(lab, name):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        # Check the owned process log only; all HTTP traffic remains TLS-only.
        result = _quiet(["docker", "logs", name], env=lab.env, allow_failure=True)
        if "listening on" in (result.stdout + result.stderr).lower():
            return
        time.sleep(.25)
    raise RuntimeError("owned TLS registry did not report a listening endpoint")


def _issue_tls(lab, temp, alias):
    tls = temp / "tls"
    tls.mkdir(mode=0o700)
    ca_key, ca_cert = tls / "ca.key", tls / "ca.crt"
    leaf_key, leaf_csr, leaf_cert = tls / "tls.key", tls / "tls.csr", tls / "tls.crt"
    ext = tls / "tls.ext"
    ext.write_text(
        f"subjectAltName=DNS:{alias}\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n", encoding="ascii")
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", "/CN=SAF ephemeral runtime registry CA", "-keyout", str(ca_key),
                "-out", str(ca_cert), "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj",
                f"/CN={alias}", "-keyout", str(leaf_key), "-out", str(leaf_csr))
    lab.command("openssl", "x509", "-req", "-in", str(leaf_csr), "-CA", str(ca_cert),
                "-CAkey", str(ca_key), "-CAcreateserial", "-extfile", str(ext),
                "-days", "2", "-out", str(leaf_cert))
    return tls, ca_cert, leaf_key, leaf_cert


def _write_secret(temp, alias, username, password):
    raw = f"{username}:{password}".encode()
    config = {"auths": {f"{alias}:5000": {
        "username": username, "password": password,
        "auth": base64.b64encode(raw).decode("ascii"),
    }}}
    path = temp / "dockerconfigjson"
    path.write_text(json.dumps(config), encoding="utf-8")
    path.chmod(0o600)
    return path


def _requests_match(rows, method, route, status):
    return any(row["method"] == method and route in row["uri"] and row["status"] == status
               for row in rows)


def run(lab):
    # The supervisor must provision the pinned node; this assertion avoids
    # silently running the evidence on a different Kubernetes base image.
    expected_node_id = lab.command("docker", "image", "inspect", "--format", "{{.Id}}",
                                   NODE_IMAGE).stdout.strip()
    for image in (REGISTRY_IMAGE, SKOPEO_IMAGE, BUSYBOX_IMAGE):
        lab.command("docker", "image", "inspect", "--format", "{{.Id}}", image)

    node = f"{lab.cluster}-control-plane"
    actual_node_id = lab.command("docker", "inspect", "--format", "{{.Image}}", node).stdout.strip()
    if actual_node_id != expected_node_id:
        lab.block("owned Kind node is not running the pinned node image digest")
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout).get("items", [])
    if len(nodes) != 1 or nodes[0].get("metadata", {}).get("name") != node:
        lab.block("case requires exactly the one pinned Kind control-plane node")
    version = json.loads(lab.kubectl("version", "-o", "json").stdout)
    server_version = version.get("serverVersion", {}).get("gitVersion")
    if server_version != "v1.36.1":
        lab.block(f"expected Kubernetes v1.36.1, observed {server_version!r}")
    network = f"{lab.cluster}-runtime-registry"
    registry = f"saf-0907-registry-{uuid.uuid4().hex[:10]}"
    volume = registry + "-data"
    alias = "saf-registry-" + uuid.uuid4().hex[:10]
    temp = Path(tempfile.mkdtemp(prefix="saf-0907-runtime-"))
    os.chmod(temp, 0o700)
    created_network = created_registry = attached_node = created_volume = created_namespace = False
    node_registry_config = False
    registry_removed = network_removed = volume_removed = namespace_removed = node_config_removed = node_image_removed = True
    approved_image = None
    evidence = {}
    try:
        if lab.command("docker", "network", "inspect", network, allow_failure=True).returncode == 0:
            lab.block("Generated private network name already exists")
        if (lab.command("docker", "inspect", registry, allow_failure=True).returncode == 0
                or lab.command("docker", "volume", "inspect", volume, allow_failure=True).returncode == 0):
            lab.block("Generated registry container or volume name already exists")
        existing_namespace = lab.kubectl("get", "namespace", NAMESPACE, allow_failure=True)
        if existing_namespace.returncode == 0:
            lab.block("Case namespace already exists")
        lab.kubectl("create", "namespace", NAMESPACE)
        created_namespace = True
        lab.kubectl("create", "serviceaccount", "runtime-puller", "-n", NAMESPACE)

        lab.command("docker", "network", "create", "--internal", network)
        created_network = True
        lab.command("docker", "network", "connect", network, node)
        attached_node = True

        username = "saf-fixture-" + secrets.token_hex(6)
        password = secrets.token_urlsafe(32)
        htpasswd_result = _quiet(["htpasswd", "-B", "-n", "-i", username], env=lab.env,
                                 input_text=password + "\n")
        htpasswd = temp / "htpasswd"
        htpasswd.write_text(htpasswd_result.stdout, encoding="utf-8")
        htpasswd.chmod(0o600)
        tls, ca_cert, leaf_key, leaf_cert = _issue_tls(lab, temp, alias)

        lab.command("docker", "volume", "create", volume)
        created_volume = True
        lab.command("docker", "run", "--detach", "--rm", "--name", registry,
                    "--network", network, "--network-alias", alias,
                    "--env", "REGISTRY_LOG_FORMATTER=json", "--env", "REGISTRY_LOG_ACCESSLOG_DISABLED=false",
                    "--env", "REGISTRY_HTTP_TLS_CERTIFICATE=/tls/tls.crt",
                    "--env", "REGISTRY_HTTP_TLS_KEY=/tls/tls.key",
                    "--env", "REGISTRY_AUTH=htpasswd",
                    "--env", "REGISTRY_AUTH_HTPASSWD_REALM=saf-0907-runtime",
                    "--env", "REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd",
                    "--volume", f"{tls}:/tls:ro", "--volume", f"{htpasswd}:/auth/htpasswd:ro",
                    "--volume", f"{volume}:/var/lib/registry", REGISTRY_IMAGE)
        created_registry = True
        _wait_registry(lab, registry)

        # Configure only this disposable node's containerd registry trust.
        hostdir = temp / "certs.d" / f"{alias}:5000"
        hostdir.mkdir(parents=True)
        ca_copy = hostdir / "ca.crt"
        shutil.copyfile(ca_cert, ca_copy)
        hosts = hostdir / "hosts.toml"
        hosts.write_text(
            f'[host."https://{alias}:5000"]\n'
            'capabilities = ["pull", "resolve"]\n'
            f'ca = "/etc/containerd/certs.d/{alias}:5000/ca.crt"\n', encoding="utf-8")
        lab.command("docker", "exec", "--user", "0", node, "mkdir", "-p",
                    f"/etc/containerd/certs.d/{alias}:5000")
        node_registry_config = True
        lab.command("docker", "cp", str(hosts),
                    f"{node}:/etc/containerd/certs.d/{alias}:5000/hosts.toml")
        lab.command("docker", "cp", str(ca_copy),
                    f"{node}:/etc/containerd/certs.d/{alias}:5000/ca.crt")

        # Copy a pinned benign image to the private registry using verified TLS.
        # Credentials travel only in mode-0600 files, never argv or evidence.
        source = temp / "source.tar"
        lab.command("docker", "image", "save", "--output", str(source), BUSYBOX_IMAGE, timeout=120)
        username_for_registry = username
        password_for_registry = password
        auth = {"auths": {f"{alias}:5000": {
            "username": username_for_registry, "password": password_for_registry,
            "auth": base64.b64encode(f"{username_for_registry}:{password_for_registry}".encode()).decode(),
        }}}
        authfile = temp / "auth.json"
        authfile.write_text(json.dumps(auth), encoding="utf-8")
        authfile.chmod(0o600)
        certroot = temp / "skopeo-certs"
        certdir = certroot / f"{alias}:5000"
        certdir.mkdir(parents=True)
        shutil.copyfile(ca_cert, certdir / "ca.crt")
        (temp / "digest").touch(mode=0o600)
        skopeo = lab.command(
            "docker", "run", "--rm", "--network", network, "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--volume", f"{temp}:/fixture", SKOPEO_IMAGE,
            "copy", "--authfile", "/fixture/auth.json", "--digestfile", "/fixture/digest",
            "--dest-cert-dir", f"/fixture/skopeo-certs/{alias}:5000", "--dest-tls-verify=true",
            "docker-archive:/fixture/source.tar",
            f"docker://{alias}:5000/fixture/model:approved", timeout=180)
        del skopeo
        digest_path = temp / "digest"
        digest = digest_path.read_text(encoding="ascii").strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            lab.block("Skopeo did not return an immutable OCI digest")
        approved_image = f"{alias}:5000/fixture/model@{digest}"
        # A case-local inert approval record ties the Pod image string to the
        # exact immutable manifest this run staged. It is not the parent's
        # example.invalid placeholder or an external promotion decision.
        record = {"status": "approved", "model-id": "fixture-model-a",
                  "promotion-record": "promotion-fixture-runtime-001", "image": approved_image}
        lab.kubectl("-n", NAMESPACE, "create", "configmap", "model-promotion",
                    "--from-literal=status=approved",
                    "--from-literal=model-id=fixture-model-a",
                    "--from-literal=promotion-record=promotion-fixture-runtime-001",
                    "--from-literal=image=" + approved_image)
        configmap = json.loads(lab.kubectl("-n", NAMESPACE, "get", "configmap", "model-promotion", "-o", "json").stdout)
        approval_matches = configmap["data"] == record
        lab.check("positive", "The run-local approved image reference is the exact staged digest",
                  approval_matches, {"approval_record_matches": approval_matches})

        # No host port is published. Assert the fact directly from Docker state.
        bindings = json.loads(lab.command("docker", "inspect", "--format", "{{json .HostConfig.PortBindings}}",
                                          registry).stdout or "null")
        no_host_ports = not bindings
        lab.check("positive", "The TLS registry exposes no host port",
                  no_host_ports, {"host_port_bindings": bindings})

        secret_file = _write_secret(temp, alias, username, password)
        del password, auth, username_for_registry, password_for_registry
        lab.kubectl("-n", NAMESPACE, "create", "secret", "generic", "registry-identity",
                    "--type=kubernetes.io/dockerconfigjson",
                    "--from-file=.dockerconfigjson=" + str(secret_file))

        # First prove that a Pod with no registry identity reaches the registry
        # and is refused. This precedes the authorized pull, so the digest is not
        # in the node's content store when the refusal is evaluated.
        missing_name = "missing-registry-authorization"
        before = _requests(_registry_log(lab, registry))
        lab.kubectl("-n", NAMESPACE, "create", "-f", "-", "-o", "json",
                    payload=json.dumps(_pod(missing_name, approved_image)))
        missing_state = _wait_pod(lab, missing_name, denied=True)
        after = _requests(_registry_log(lab, registry))
        missing_delta = _delta(before, after)
        statuses = missing_state.get("status", {}).get("containerStatuses", []) if missing_state else []
        waiting = [status.get("state", {}).get("waiting", {}) for status in statuses]
        unauthorized = any(_registry_auth_denied(item) and approved_image.lower() in item.get("message", "").lower()
                           for item in waiting)
        manifest_401 = any(_requests_match(missing_delta, method, f"/v2/fixture/model/manifests/{digest}", 401)
                           for method in ("HEAD", "GET"))
        authenticated_registry_challenge = manifest_401 or any(
            _requests_match(missing_delta, method, path, 401)
            for path in ("/v2", "/v2/") for method in ("HEAD", "GET")
        )
        (lab.evidence / "registry-denial-observation.json").write_text(
            json.dumps({"attempted_exact_digest": unauthorized, "requests": missing_delta}, indent=2) + "\n")
        no_successful_content = not any(
            row["status"] == 200 and ("/manifests/" in row["uri"] or "/blobs/" in row["uri"])
            for row in missing_delta)
        missing_ok = (unauthorized and authenticated_registry_challenge and no_successful_content
                      and missing_state.get("status", {}).get("phase") == "Pending")
        lab.check("red", "Without registry authorization the exact pull is refused",
                  missing_ok, {"pod_phase": missing_state.get("status", {}).get("phase"),
                               "pod_reports_registry_auth_failure": unauthorized,
                               "registry_authentication_challenge_401": authenticated_registry_challenge,
                               "registry_successful_manifest_or_blob_read": not no_successful_content})
        events = json.loads(lab.kubectl("-n", NAMESPACE, "get", "events", "--field-selector",
                                       f"involvedObject.name={missing_name}", "-o", "json").stdout).get("items", [])
        evidence["missing_authorization"] = {
            "pod": {"phase": missing_state.get("status", {}).get("phase"),
                    "containerStatuses": statuses,
                    "eventReasons": sorted({event.get("reason", "") for event in events})},
            "registryRequests": missing_delta,
        }
        lab.kubectl("-n", NAMESPACE, "delete", "pod", missing_name, "--wait=true", timeout=40)

        # Authorized Pod requests the same exact digest with a namespace-local
        # Docker config Secret. A successful process plus imageID proves runtime
        # execution of the staged digest; registry reads prove it was pulled.
        authorized_name = "authorized-runtime-pull"
        before = _requests(_registry_log(lab, registry))
        lab.kubectl("-n", NAMESPACE, "create", "-f", "-", "-o", "json",
                    payload=json.dumps(_pod(authorized_name, approved_image, pull_secret=True)))
        authorized_state = _wait_pod(lab, authorized_name, denied=False, timeout=120)
        after = _requests(_registry_log(lab, registry))
        authorized_delta = _delta(before, after)
        authorized_statuses = authorized_state.get("status", {}).get("containerStatuses", []) if authorized_state else []
        status = authorized_statuses[0] if authorized_statuses else {}
        manifest_200 = _requests_match(authorized_delta, "GET", f"/v2/fixture/model/manifests/{digest}", 200)
        blob_200 = any(row["method"] == "GET" and "/blobs/" in row["uri"] and row["status"] == 200
                       for row in authorized_delta)
        exact_runtime_digest = digest in status.get("imageID", "")
        completion = lab.kubectl("-n", NAMESPACE, "logs", authorized_name, allow_failure=True).stdout.strip()
        success = (authorized_state.get("status", {}).get("phase") == "Succeeded"
                   and "Completed" == status.get("state", {}).get("terminated", {}).get("reason")
                   and exact_runtime_digest and completion == "saf-runtime-fixture-ready"
                   and manifest_200 and blob_200)
        lab.check("green", "The authenticated runtime pulls and runs the exact approved benign digest",
                  success, {"pod_phase": authorized_state.get("status", {}).get("phase"),
                            "runtime_digest_matches": exact_runtime_digest,
                            "fixture_completed": completion == "saf-runtime-fixture-ready",
                            "registry_manifest_get_200": manifest_200,
                            "registry_blob_get_200": blob_200})
        evidence["authorized_pull"] = {
            "pod": {"phase": authorized_state.get("status", {}).get("phase"),
                    "image": approved_image, "imageID": status.get("imageID"),
                    "terminated": status.get("state", {}).get("terminated"),
                    "fixtureLog": completion},
            "registryRequests": authorized_delta,
        }
        evidence["scope"] = {
            "clusterNodeImage": NODE_IMAGE,
            "registryImage": REGISTRY_IMAGE,
            "copyToolImage": SKOPEO_IMAGE,
            "sourceBenignImage": BUSYBOX_IMAGE,
            "approvedImage": approved_image,
            "noHostPorts": no_host_ports,
            "tls": True,
            "registryAuthentication": "ephemeral bcrypt htpasswd over TLS",
            "kubernetesAdmissionOrRbacUsed": False,
            "externalRegistryMutated": False,
            "imageSigningTested": False,
        }
        (lab.evidence / "runtime-pull-observations.json").write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    finally:
        # Explicit cleanup is attempted on success and failure. Deleting the
        # namespace removes both Pods, the transient Secret, and the local record.
        if created_namespace:
            ns = lab.kubectl("delete", "namespace", NAMESPACE, "--wait=true", "--timeout=60s",
                             timeout=75, allow_failure=True)
            namespace_removed = not ns.returncode
        else:
            namespace_removed = True
        if approved_image:
            lab.command("docker", "exec", node, "crictl", "rmi", approved_image,
                        allow_failure=True)
            remaining = lab.command("docker", "exec", node, "crictl", "images", "-o", "json",
                                    allow_failure=True)
            if remaining.returncode:
                node_image_removed = False
            else:
                node_image_removed = not any(
                    digest in json.dumps(image)
                    for image in json.loads(remaining.stdout).get("images", [])
                )
        if created_registry:
            registry_removed = not lab.command("docker", "rm", "--force", registry,
                                                allow_failure=True).returncode
        if node_registry_config:
            path = f"/etc/containerd/certs.d/{alias}:5000"
            node_config_removed = not lab.command("docker", "exec", "--user", "0", node,
                                                   "rm", "-rf", path, allow_failure=True).returncode
        if attached_node:
            lab.command("docker", "network", "disconnect", network, node, allow_failure=True)
        if created_network:
            network_removed = not lab.command("docker", "network", "rm", network,
                                               allow_failure=True).returncode
        if created_volume:
            volume_removed = not lab.command("docker", "volume", "rm", volume,
                                              allow_failure=True).returncode
        shutil.rmtree(temp, ignore_errors=True)
        lab.check("positive", "Ephemeral registry, volume, bridge, node config, namespace, and credentials are removed",
                  registry_removed and volume_removed and network_removed and namespace_removed
                  and node_config_removed and node_image_removed,
                  {"registry_removed": registry_removed, "registry_volume_removed": volume_removed,
                   "private_network_removed": network_removed, "namespace_removed": namespace_removed,
                   "node_registry_config_removed": node_config_removed,
                   "run_image_removed_from_node": node_image_removed,
                   "credential_files_removed": not temp.exists()})
