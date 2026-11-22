"""Observe vCluster API object behavior using ordinary owner-authorized calls.

The host is one disposable kind cluster. Two vCluster releases use the official
0.37.7 chart with its default sync configuration. This is evidence about API/control-plane object
behavior only; it is not evidence of complete tenant isolation.
"""
from base64 import b64decode
from binascii import Error as InvalidBase64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tarfile
import time


NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
CHART_REPO = "https://charts.loft.sh"
CHART_SHA256 = "bc858bd6d75b02f09f4397ce3278807eff9f92132a58252b0108145272c50f94"
VCLUSTER_VERSION = "0.37.7"
K8S_IMAGE_TAG = "v1.36.6@sha256:967b956bd407adcacc5e6323bb20346c58e190d8a292cc63dea7cef60b5e9cbc"
VCLUSTER_IMAGE_TAG = "0.37.7@sha256:799ba08e9622e8454f4d9574fd81b17567b6b0a4ad936b74507ae7798d91a489"
TENANTS = (("tenant-a", "saf-vcluster-a"), ("tenant-b", "saf-vcluster-b"))
SCOPE = (
    "One disposable Kubernetes v1.36.1 kind host with two vCluster 0.37.7 APIs "
    "installed from the SHA-256-pinned official chart and digest-pinned control-plane images. "
    "Ordinary vCluster-owner API requests show CRD collision within tenant A, the "
    "same CRD and namespaced objects in independent tenant APIs, and host API absence. "
    "The host and tenant control planes still share the kind node/kernel and cluster "
    "administration boundary. Default chart sync settings can create selected real "
    "host objects; this case does not test sync policy, workloads, network, storage, "
    "host privilege, or complete isolation."
)


def _run(lab, command, *, input_text=None, timeout=120, env=None, action="command"):
    """Run without persisting command bodies, credentials, stdout, or stderr."""
    try:
        result = subprocess.run(command, input=input_text, text=True,
                                capture_output=True, env=env or lab.env,
                                timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        lab.block(f"{action} could not complete")
    if result.returncode:
        lab.block(f"{action} failed (exit {result.returncode})")
    return result


def _kubectl(lab, kubeconfig, context, *args, payload=None, timeout=90,
             allow_failure=False, action="Kubernetes API request"):
    command = ["kubectl", "--kubeconfig", str(kubeconfig)]
    if context:
        command.extend(["--context", context])
    command.extend([f"--request-timeout={max(5, timeout - 5)}s", *args])
    try:
        result = subprocess.run(command, input=payload, text=True, capture_output=True,
                                env=lab.env, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        lab.block(f"{action} could not complete")
    if result.returncode and not allow_failure:
        lab.block(f"{action} failed (exit {result.returncode})")
    return result


def _fetch_chart(lab, temp):
    _run(lab, ["helm", "pull", "vcluster", "--repo", CHART_REPO, "--version",
               VCLUSTER_VERSION, "--destination", str(temp)],
         timeout=120, action="download pinned vCluster chart")
    chart = temp / f"vcluster-{VCLUSTER_VERSION}.tgz"
    digest = hashlib.sha256(chart.read_bytes()).hexdigest()
    if digest != CHART_SHA256:
        lab.block("The supplied vCluster chart archive does not match its pinned SHA-256")
    try:
        with tarfile.open(chart, "r:gz") as archive:
            chart_file = archive.extractfile("vcluster/Chart.yaml")
            if chart_file is None:
                lab.block("The pinned chart archive has no Chart.yaml")
            # Chart.yaml is a small, simple YAML document. Read version fields
            # without requiring a YAML package just to validate its identity.
            metadata = chart_file.read().decode("utf-8")
            version = re.search(r"(?m)^version:\s*['\"]?([^\s'\"]+)", metadata)
            app_version = re.search(r"(?m)^appVersion:\s*['\"]?([^\s'\"]+)", metadata)
    except (OSError, tarfile.TarError, UnicodeError):
        lab.block("The pinned vCluster chart archive could not be read")
    if not version or version.group(1) != VCLUSTER_VERSION or not app_version or app_version.group(1) != VCLUSTER_VERSION:
        lab.block("The supplied chart metadata is not vCluster 0.37.7")
    return chart, {"chart": "vcluster", "version": VCLUSTER_VERSION, "sha256": digest}


def _host_context(lab):
    return f"kind-{lab.cluster}"


def _install(lab, chart, release, namespace):
    _kubectl(lab, lab.kubeconfig, _host_context(lab), "create", "namespace", namespace,
             action=f"create host namespace {namespace}")
    _run(lab, ["helm", "install", release, str(chart),
               "--namespace", namespace, "--kubeconfig", str(lab.kubeconfig),
               "--kube-context", _host_context(lab), "--wait", "--timeout", "8m",
               "--set", "controlPlane.proxy.extraSANs[0]=127.0.0.1",
               "--set", "telemetry.enabled=false",
               "--set-string", f"controlPlane.distro.k8s.image.tag={K8S_IMAGE_TAG}",
               "--set-string", f"controlPlane.statefulSet.image.tag={VCLUSTER_IMAGE_TAG}"],
         timeout=510, action=f"install vCluster {release}")


def _free_loopback_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        return server.getsockname()[1]


def _start_forward(lab, release, namespace, port):
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
               _host_context(lab), "-n", namespace, "port-forward",
               "--address=127.0.0.1", f"service/{release}", f"{port}:443"]
    try:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, env=lab.env,
                                   text=True)
    except OSError:
        lab.block(f"loopback port-forward for {release} could not start")
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process.poll() is not None:
            lab.block(f"loopback port-forward for {release} exited")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return process
        except OSError:
            time.sleep(0.25)
    process.terminate()
    process.wait(timeout=5)
    lab.block(f"loopback port-forward for {release} did not become ready")


def _tenant_kubeconfig(lab, release, namespace, port, path):
    """Use only the owned chart's fixture export and keep its content out of logs."""
    exported = _kubectl(lab, lab.kubeconfig, _host_context(lab), "-n", namespace,
                        "get", "secret", f"vc-{release}", "-o", "jsonpath={.data.config}",
                        action=f"obtain the {release} fixture kubeconfig")
    try:
        content = b64decode(exported.stdout.strip(), validate=True)
    except InvalidBase64:
        lab.block(f"the {release} fixture exported an invalid kubeconfig")
    if not content:
        lab.block(f"the {release} fixture kubeconfig was unavailable")
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
        output.write(content)

    result = _kubectl(lab, path, "", "config", "view", "--raw", "-o", "json",
                      action=f"normalize {release} fixture kubeconfig")
    try:
        data = json.loads(result.stdout)
        cluster, = data["clusters"]
        settings = cluster["cluster"]
        users = data["users"]
        usable = data["current-context"] and len(data["contexts"]) == 1
    except (KeyError, ValueError):
        lab.block(f"the {release} fixture exported an unexpected config shape")
    if not usable or not settings.get("certificate-authority-data") or settings.get("insecure-skip-tls-verify"):
        lab.block(f"the {release} fixture does not provide verified TLS")
    if any(set(user["user"]) & {"exec", "auth-provider", "client-key", "client-certificate", "tokenFile"}
           for user in users):
        lab.block(f"the {release} fixture requires a local credential helper or file")
    settings["server"] = f"https://127.0.0.1:{port}"
    settings.pop("proxy-url", None)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _request(lab, kubeconfig, *args, payload=None, allow_failure=False, action="tenant request"):
    return _kubectl(lab, kubeconfig, "", *args, payload=payload,
                    allow_failure=allow_failure, action=action)


def _crd(name, group):
    return {
        "apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
        "metadata": {"name": name},
        "spec": {
            "group": group, "scope": "Namespaced",
            "names": {"plural": "isolationrecords", "singular": "isolationrecord",
                      "kind": "IsolationRecord"},
            "versions": [{"name": "v1", "served": True, "storage": True,
                          "schema": {"openAPIV3Schema": {
                              "type": "object", "properties": {
                                  "spec": {"type": "object",
                                           "x-kubernetes-preserve-unknown-fields": True}}}}}],
        },
    }


def _record(group, name, namespace, owner):
    return {"apiVersion": f"{group}/v1", "kind": "IsolationRecord",
            "metadata": {"name": name, "namespace": namespace},
            "spec": {"owner": owner}}


def _wait_established(lab, kubeconfig, name, owner):
    _request(lab, kubeconfig, "wait", "--for=condition=Established",
             f"crd/{name}", "--timeout=45s", action=f"wait for {owner} CRD")


def _read_marker(lab, kubeconfig, name, namespace):
    return _request(lab, kubeconfig, "get", "configmap", name,
                    "--namespace", namespace, "-o", "jsonpath={.data.owner}",
                    action=f"read {namespace} ConfigMap").stdout.strip()


def _is_not_found(result):
    return result.returncode != 0 and bool(
        re.search(r"\bNotFound\b|not found", result.stderr, flags=re.IGNORECASE))


def run(lab):
    temp = lab.kubeconfig.parent / "saf-0702-022"
    temp.mkdir(mode=0o700)
    chart, chart_evidence = _fetch_chart(lab, temp)
    lab.check("positive", "The official vCluster chart matches its pinned version and digest",
              True, chart_evidence)
    installed = []
    forwards = []
    tenant_configs = {}
    try:
        for release, namespace in TENANTS:
            _install(lab, chart, release, namespace)
            installed.append((release, namespace))
        for release, namespace in TENANTS:
            _kubectl(lab, lab.kubeconfig, _host_context(lab), "-n", namespace,
                     "wait", "--for=condition=Ready", "pod",
                     "-l", f"app=vcluster,release={release}", "--timeout=5m",
                     timeout=310, action=f"wait for {release} control plane")
            port = _free_loopback_port()
            forwards.append(_start_forward(lab, release, namespace, port))
            config_path = temp / f"{release}-kubeconfig.json"
            tenant_configs[release] = _tenant_kubeconfig(
                lab, release, namespace, port, config_path)

        namespace = "api-object-fixture"
        group = "inventory.example.invalid"
        crd_name = f"isolationrecords.{group}"
        record_name = "same-record"
        cm_name = "same-config"
        crd = _crd(crd_name, group)
        configmaps = {}
        custom_resources = {}

        # Owner-authorized positive requests establish that tenant A's API is
        # live and accepts the intended cluster-scoped object.
        _request(lab, tenant_configs["tenant-a"], "create", "namespace", namespace,
                 action="create tenant-A fixture namespace")
        _request(lab, tenant_configs["tenant-a"], "create", "-f", "-",
                 payload=json.dumps(crd), action="create tenant-A CRD")
        _wait_established(lab, tenant_configs["tenant-a"], crd_name, "tenant A")

        # Red is the normal uniqueness rule inside one owned API. It does not
        # use another tenant's credentials or test an authorization bypass.
        collision = _request(lab, tenant_configs["tenant-a"], "create", "-f", "-",
                             payload=json.dumps(crd), allow_failure=True,
                             action="repeat tenant-A CRD create")
        collision_seen = collision.returncode != 0 and bool(
            re.search(r"AlreadyExists|already exists", collision.stderr,
                      flags=re.IGNORECASE))
        lab.check("red", "A duplicate CRD name collides within tenant A's owned API",
                  collision_seen,
                  {"api": "tenant-a", "object": crd_name,
                   "api_result": "AlreadyExists" if collision_seen else "unexpected response"})

        for release, _ in TENANTS:
            if release == "tenant-b":
                _request(lab, tenant_configs[release], "create", "namespace", namespace,
                         action="create tenant-B fixture namespace")
                _request(lab, tenant_configs[release], "create", "-f", "-",
                         payload=json.dumps(crd), action="create same-named tenant-B CRD")
                _wait_established(lab, tenant_configs[release], crd_name, "tenant B")
            _request(lab, tenant_configs[release], "create", "configmap", cm_name,
                     "--namespace", namespace, "--from-literal=owner=" + release,
                     action=f"create {release} ConfigMap")
            configmaps[release] = _read_marker(lab, tenant_configs[release], cm_name, namespace)
            _request(lab, tenant_configs[release], "create", "-f", "-",
                     payload=json.dumps(_record(group, record_name, namespace, release)),
                     action=f"create {release} custom resource")

        for release in ("tenant-a", "tenant-b"):
            value = _request(lab, tenant_configs[release], "get", f"isolationrecords.{group}",
                             record_name, "--namespace", namespace,
                             "-o", "jsonpath={.spec.owner}",
                             action=f"read {release} custom resource").stdout.strip()
            custom_resources[release] = value
            if value != release:
                lab.block(f"the {release} custom resource owner marker did not match")

        lab.check("green", "Tenant A and tenant B independently accept the same CRD name",
                  configmaps == {"tenant-a": "tenant-a", "tenant-b": "tenant-b"},
                  {"apis": ["tenant-a", "tenant-b"], "same_crd_name": crd_name,
                   "same_namespace_and_configmap": f"{namespace}/{cm_name}",
                   "observed_owner_values": configmaps,
                   "custom_resource_name": record_name,
                   "same_named_custom_resource_owner_values": custom_resources})

        host_crd = _kubectl(lab, lab.kubeconfig, _host_context(lab), "get", "crd",
                            crd_name, "-o", "name", allow_failure=True,
                            action="check host API for tenant CRD")
        tenant_b_crd = _request(lab, tenant_configs["tenant-b"], "get", "crd",
                                crd_name, "-o", "name", allow_failure=True,
                                action="check tenant-B API for tenant-A collision")
        # Both virtual clusters intentionally own a same-named CRD. Confirm the
        # host serves neither (and tenant B's successful object remains its own).
        host_absent = _is_not_found(host_crd)
        tenant_b_present = tenant_b_crd.returncode == 0 and crd_name in tenant_b_crd.stdout
        tenant_a_present = _request(lab, tenant_configs["tenant-a"], "get", "crd",
                                     crd_name, "-o", "name",
                                     action="confirm tenant-A CRD").stdout.strip() == f"customresourcedefinition.apiextensions.k8s.io/{crd_name}"
        lab.check("positive", "Same-named API objects remain readable in both tenants while the host API does not serve the CRD",
                  host_absent and tenant_b_present and tenant_a_present,
                  {"tenant_a_crd": tenant_a_present, "tenant_b_crd": tenant_b_present,
                   "host_crd_result": "NotFound" if host_absent else "unexpected response",
                   "host_api": "kind host API"})
        print("Residual boundary: vCluster control planes share the kind host node/kernel and its cluster-admin boundary; default synchronization may create selected real host objects.")
        print("Candidate scope: API object behavior only; this run does not establish isolation for workloads, network, storage, node, kernel, sync policy, or host administration.")
    finally:
        for process in reversed(forwards):
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for release, namespace in reversed(installed):
            # Helm's explicit namespace and disposable host kubeconfig are used
            # throughout; errors stay credential-free and the harness also
            # deletes the entire case-owned kind cluster.
            try:
                result = subprocess.run(
                    ["helm", "uninstall", release, "--namespace", namespace,
                     "--kubeconfig", str(lab.kubeconfig), "--kube-context", _host_context(lab),
                     "--wait", "--timeout", "3m"], capture_output=True, text=True,
                    env=lab.env, timeout=210)
                if result.returncode:
                    print(f"Cleanup note: helm uninstall for {release} returned {result.returncode}; the disposable host cluster cleanup remains authoritative.")
            except (OSError, subprocess.TimeoutExpired):
                print(f"Cleanup note: helm uninstall for {release} did not complete; the disposable host cluster cleanup remains authoritative.")
        for path in tenant_configs.values():
            path.unlink(missing_ok=True)
        for path in temp.glob("tenant-*-kubeconfig.json"):
            path.unlink(missing_ok=True)
