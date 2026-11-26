"""Compare a shared host API with two owned virtual tenant APIs."""
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
SCOPE = ("A real local host API and two pinned vCluster tenant APIs on a shared Kind node, "
         "with scoped host authorization reviews and two independently observed inert ConfigMap "
         "synchronization lifecycles in the expected release namespaces.")
TENANT_NAMESPACE = "isolation-fixture"


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
               "--set-string", f"controlPlane.statefulSet.image.tag={VCLUSTER_IMAGE_TAG}",
               "--set", "sync.toHost.configMaps.enabled=true",
               "--set", "sync.toHost.configMaps.all=true"],
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
    deadline = time.monotonic() + 75
    encoded = None
    while time.monotonic() < deadline:
        exported = _kubectl(lab, lab.kubeconfig, _host_context(lab), "-n", namespace,
                            "get", "secret", f"vc-{release}", "-o", "jsonpath={.data.config}",
                            timeout=12, allow_failure=True,
                            action=f"obtain the {release} fixture kubeconfig")
        if exported.returncode == 0 and exported.stdout.strip():
            encoded = exported.stdout.strip()
            break
        if exported.returncode and not _is_not_found(exported):
            lab.block(f"The owned API could not read the {release} fixture export")
        time.sleep(0.5)
    if encoded is None:
        names = _kubectl(lab, lab.kubeconfig, _host_context(lab), "-n", namespace,
                          "get", "secrets", "-o", "name", timeout=12,
                          action=f"inspect exact names for the owned {release} export")
        lab.block(f"The {release} kubeconfig was unavailable after controller startup. "
                  f"Expected export present: {f'secret/vc-{release}' in names.stdout.splitlines()}.")
    try:
        content = b64decode(encoded, validate=True)
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


def _synced_configmap(lab, host_namespace, sync_id, expected):
    """Return only a stable owned-fixture sync decision, never the full object."""
    selector = f"saf.test/sync-id={sync_id}"
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        result = _kubectl(lab, lab.kubeconfig, _host_context(lab), "get", "configmaps",
                          "--all-namespaces", "--selector", selector, "-o", "json",
                          action="read the exact owned host-sync marker")
        try:
            items = json.loads(result.stdout).get("items", [])
        except (ValueError, AttributeError):
            lab.block("the host sync marker response was not valid JSON")
        if len(items) == 1:
            item = items[0]
            metadata = item.get("metadata", {})
            labels = metadata.get("labels", {})
            annotations = metadata.get("annotations", {})
            data = item.get("data", {})
            observed = {
                "single_host_object": True,
                "host_namespace_is_release_namespace": metadata.get("namespace") == host_namespace,
                "source_name_matches": annotations.get("vcluster.loft.sh/object-name") == "sync-marker",
                "source_namespace_matches": annotations.get("vcluster.loft.sh/object-namespace") == TENANT_NAMESPACE,
                "managed_label_present": bool(labels.get("vcluster.loft.sh/managed-by")),
                "marker_matches": data.get("fixture") == expected,
            }
            return all(observed.values()), observed
        time.sleep(0.5)
    return False, {"single_host_object": False, "host_object_absent_or_ambiguous": True}


def _host_sync_marker_count(lab, sync_id):
    selector = f"saf.test/sync-id={sync_id}"
    result = _kubectl(lab, lab.kubeconfig, _host_context(lab), "get", "configmaps",
                      "--all-namespaces", "--selector", selector, "-o", "json",
                      action="confirm the owned host-sync marker is removed")
    try:
        items = json.loads(result.stdout).get("items", [])
    except (ValueError, AttributeError):
        lab.block("the host sync marker response was not valid JSON")
    return len(items)


def _wait_established(lab, kubeconfig, name, owner):
    _request(lab, kubeconfig, "wait", "--for=condition=Established",
             f"crd/{name}", "--timeout=45s", action=f"wait for {owner} CRD")


def _is_not_found(result):
    return result.returncode != 0 and bool(
        re.search(r"\bNotFound\b|not found", result.stderr, flags=re.IGNORECASE))


def host_decision(lab, user, verb, resource, group="", namespace=""):
    outcome = lab.create({"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview",
                          "spec": {"user": user, "groups": ["system:authenticated"], "resourceAttributes": {
                              "verb": verb, "resource": resource, "group": group, "namespace": namespace}}})["status"]
    if outcome.get("evaluationError"):
        lab.block("The host authorization review could not evaluate the fixture subject")
    return outcome.get("allowed", False)


def close_forward(process):
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=6)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run(lab):
    group = "isolation010.example.invalid"
    crd_name = f"isolationrecords.{group}"
    crd = _crd(crd_name, group)
    host = _host_context(lab)
    for namespace in ("host-scope-a", "host-scope-b"):
        lab.kubectl("create", "namespace", namespace)
    _kubectl(lab, lab.kubeconfig, host, "-n", "host-scope-a", "create", "-f", "-",
             payload=json.dumps(crd), action="create the cluster-scoped host comparison CRD")
    duplicate = _kubectl(lab, lab.kubeconfig, host, "-n", "host-scope-b", "create", "-f", "-",
                         payload=json.dumps(crd), allow_failure=True, action="observe host scope on a second named namespace")
    collision = duplicate.returncode != 0 and bool(re.search(r"AlreadyExists|already exists", duplicate.stderr, re.IGNORECASE))
    lab.check("red", "The same host cluster-scoped object collides when requested from a different namespace argument",
              collision, {"cluster_scoped_collision_across_host_namespaces": collision})

    temporary = lab.kubeconfig.parent / "saf-0702-010"
    temporary.mkdir(mode=0o700)
    chart, chart_evidence = _fetch_chart(lab, temporary)
    forwards = []
    markers = {}
    try:
        for release, namespace in TENANTS:
            _install(lab, chart, release, namespace)
            _kubectl(lab, lab.kubeconfig, host, "-n", namespace, "wait", "--for=condition=Ready", "pod",
                     "-l", f"app=vcluster,release={release}", "--timeout=5m", timeout=310,
                     action=f"wait for {release} control plane")
            port = _free_loopback_port()
            forwards.append(_start_forward(lab, release, namespace, port))
            path = _tenant_kubeconfig(lab, release, namespace, port, temporary / f"{release}-kubeconfig.json")
            _request(lab, path, "create", "namespace", TENANT_NAMESPACE, action="create owned tenant fixture namespace")
            _request(lab, path, "create", "-f", "-", payload=json.dumps(crd), action="create the owned virtual CRD")
            _wait_established(lab, path, crd_name, release)
            record = _record(group, "same-marker", TENANT_NAMESPACE, f"public-{release}")
            _request(lab, path, "create", "-f", "-", payload=json.dumps(record), action="create the owned virtual marker")
            read = _request(lab, path, "-n", TENANT_NAMESPACE, "get", f"isolationrecords.{group}", "same-marker",
                            "-o", "json", action="read the marker from the owned tenant API")
            markers[release] = json.loads(read.stdout)["spec"]["owner"] == f"public-{release}"
        lab.check("green", "Both live tenant APIs independently accept the same cluster-scoped CRD and retain distinct marker values",
                  markers == {"tenant-a": True, "tenant-b": True}, {"virtual_marker_matches": markers})

        host_absent = _kubectl(lab, lab.kubeconfig, host, "get", "namespace", TENANT_NAMESPACE,
                              allow_failure=True, action="read owned host comparison state")
        namespace_absent = _is_not_found(host_absent)
        decisions = {}
        for release, namespace in TENANTS:
            subject = f"fixture-external-{release}"
            decisions[release] = {
                "host_nodes_allowed": host_decision(lab, subject, "list", "nodes"),
                "host_synced_namespace_read_allowed": host_decision(lab, subject, "get", "configmaps", namespace=namespace),
                "host_crd_create_allowed": host_decision(lab, subject, "create", "customresourcedefinitions", "apiextensions.k8s.io")}
        lab.check("positive", "The virtual namespace is absent from the host API and owned tenant subjects have no tested host grant",
                  namespace_absent and all(not any(result.values()) for result in decisions.values()),
                  {"virtual_namespace_absent_on_host": namespace_absent, "host_authorization": decisions})

        sync_results = {}
        for release, host_namespace in TENANTS:
            sync_id = f"{release}-inert-configmap"
            marker = f"public-{release}-sync-marker"
            config = {"apiVersion": "v1", "kind": "ConfigMap",
                      "metadata": {"name": "sync-marker", "namespace": TENANT_NAMESPACE,
                                   "labels": {"saf.test/sync-id": sync_id}},
                      "data": {"fixture": marker}}
            _request(lab, temporary / f"{release}-kubeconfig.json", "create", "-f", "-",
                     payload=json.dumps(config), action="create owned tenant ConfigMap sync marker")
            synced, observed = _synced_configmap(lab, host_namespace, sync_id, marker)
            tenant_kubeconfig = temporary / f"{release}-kubeconfig.json"
            _request(lab, tenant_kubeconfig, "delete", "configmap", "sync-marker",
                     "--namespace", TENANT_NAMESPACE, "--wait=true", "--timeout=30s",
                     action="delete owned tenant ConfigMap sync marker")
            source_after_delete = _request(lab, tenant_kubeconfig, "get", "configmap", "sync-marker",
                                           "--namespace", TENANT_NAMESPACE, "-o", "name",
                                           allow_failure=True,
                                           action="read back deleted tenant ConfigMap sync marker")
            source_deleted = _is_not_found(source_after_delete)
            removed = False
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                if _host_sync_marker_count(lab, sync_id) == 0:
                    removed = True
                    break
                time.sleep(0.5)
            sync_results[release] = {**observed, "sync_observed": synced,
                                     "source_deleted": source_deleted, "host_copy_removed": removed}
        sync_ok = all(
            result.get("single_host_object") and result.get("host_namespace_is_release_namespace")
            and result.get("source_name_matches") and result.get("source_namespace_matches")
            and result.get("managed_label_present")
            and result.get("marker_matches") and result.get("sync_observed")
            and result.get("source_deleted") and result.get("host_copy_removed")
            for result in sync_results.values())
        lab.check("positive", "An owned inert ConfigMap syncs only to its vCluster host namespace and is removed with its tenant source",
                  sync_ok, {"tenant_host_sync": sync_results, "all_host_copies_removed": sync_ok})
        (lab.evidence / "virtual-cluster-observations.json").write_text(json.dumps(
            {"chart": chart_evidence, "shared_host_namespace_collision": collision, "tenant_markers_independent": markers,
             "virtual_namespace_absent_on_host": namespace_absent, "synthetic_host_subject_decisions": decisions,
             "owned_configmap_sync_and_removal": sync_results,
             "node_and_kernel_shared": True}, indent=2) + "\n")
    finally:
        for process in reversed(forwards):
            close_forward(process)
