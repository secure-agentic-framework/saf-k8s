"""Run a native kubeadm upgrade and an etcd recovery in the owned Kind fixture."""
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import tempfile
import time
from types import SimpleNamespace

from fixtures import BUSYBOX_IMAGE


BASELINE = "v1.36.1"
TARGET = "v1.36.6"
LOCAL_TARGET = "saf-lab-kindest:v1.36.6-b98364acbd4c"
NAMESPACE = "saf-native-upgrade"
NAME = "versioned-service"
BODY = "saf-native-workload-ok"
KUBEADM = "/usr/local/bin/saf-native-kubeadm"
KUBELET_STAGE = "/usr/local/bin/saf-native-kubelet"
BINARIES = {
    "kubeadm": "b4b626884434eb9db3c784ea67c1ee5c5b799bd5bfd652e60a222397da1dc881",
    "kubelet": "14c52637849edf6abdcfb2d094c5ff69f257309d6a6cae2f707f9113fab91d39",
}
IMAGES = {
    "kube-apiserver": "sha256:3621ec967dcc2c487231eea36a125e5aae5864375be425b1f268495822660e5a",
    "kube-controller-manager": "sha256:805a143625da8e948cb8776ac58ae6dc7eb6d246abc30a2e477284f998168f43",
    "kube-proxy": "sha256:2a561cc8fa314ab0e0a4a218247f7b0bc9a0d632c204fce0547b8c1a5923d689",
    "kube-scheduler": "sha256:4ee20f92b255396089db2b746f8dc6a664c8a97e18b5dcf6780206a151070473",
}
EXPORT = """set -eu
address=/tmp/saf-export.sock
containerd --address "$address" --state /tmp/saf-export-state >/tmp/saf-export.log 2>&1 &
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if ctr --address "$address" version >/dev/null 2>&1; then break; fi
    sleep 1
done
ctr --address "$address" -n k8s.io images export --platform linux/arm64 - "$@"
"""


def image_ref(component):
    return f"registry.k8s.io/{component}:{TARGET}"


def _copy_target_assets(lab, staging, nodes):
    target = os.environ.get("SAF_UPGRADE_NODE_IMAGE") or LOCAL_TARGET
    local = lab.command("docker", "image", "inspect", target, "--format", "{{.Id}} {{.Architecture}}",
                        allow_failure=True)
    words = local.stdout.split()
    if local.returncode or len(words) != 2 or words[1] != "arm64" or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", words[0]
    ):
        lab.block("Prepare the pinned ARM64 target image described in the case README")
    image_id = words[0]
    archive = staging / "target-images.tar"
    source = lab.command(
        "docker", "create", "--name", f"{lab.cluster}-arm64-assets", "--network=none",
        "--entrypoint=/bin/sh", image_id, "-ec", EXPORT, "saf-export",
        *(image_ref(component) for component in IMAGES),
    ).stdout.strip()
    try:
        for binary, digest in BINARIES.items():
            path = staging / binary
            lab.command("docker", "cp", f"{source}:/usr/bin/{binary}", str(path))
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                lab.block(f"The target {binary} does not match the reviewed ARM64 binary")
        with archive.open("xb") as stream:
            result = subprocess.run(["docker", "start", "--attach", source], stdout=stream,
                                    stderr=subprocess.PIPE, env=lab.env, timeout=150, check=False)
        if result.returncode or not archive.stat().st_size:
            lab.block("Could not extract the pinned, local control-plane images")
    finally:
        lab.command("docker", "rm", "-f", source, allow_failure=True)
    expected = {image_ref(component): digest for component, digest in IMAGES.items()}
    for node in nodes:
        for binary, destination in (("kubeadm", KUBEADM), ("kubelet", KUBELET_STAGE)):
            lab.command("docker", "cp", str(staging / binary), f"{node}:{destination}")
            lab.command("docker", "exec", node, "chmod", "0755", destination)
        with archive.open("rb") as stream:
            result = subprocess.run(
                ["docker", "exec", "-i", node, "ctr", "-n", "k8s.io",
                 "images", "import", "--platform", "linux/arm64", "-"],
                stdin=stream, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                env=lab.env, timeout=135, check=False,
            )
        if result.returncode:
            lab.block("Could not import the reviewed target images into the owned node")
        listing = lab.command("docker", "exec", node, "ctr", "-n", "k8s.io", "images", "ls")
        rows = (line.split(maxsplit=3) for line in listing.stdout.splitlines())
        manifests = {row[0]: row[2] for row in rows if len(row) >= 3 and row[0] in expected}
        if manifests != expected:
            lab.block("The owned node did not receive all of the exact target image manifests")
    return {"binaries_sha256": BINARIES, "component_manifest_digests": IMAGES}


def _get(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def _create(lab, namespace, resource):
    return json.loads(lab.kubectl("-n", namespace, "create", "-f", "-", "-o", "json",
                                  payload=json.dumps(resource)).stdout)


def _server(lab):
    return json.loads(lab.kubectl("get", "--raw=/version").stdout)["gitVersion"]


def _observed_nodes(lab, control_plane, worker):
    nodes = _get(lab, "get", "nodes")["items"]
    roles = {control_plane: "control_plane", worker: "worker"}
    if {item["metadata"]["name"] for item in nodes} != set(roles):
        lab.block("The API node inventory is outside the owned maintenance topology")
    return {
        roles[node["metadata"]["name"]]: {
            "uid": node["metadata"]["uid"],
            "version": node["status"]["nodeInfo"]["kubeletVersion"],
            "ready": any(c.get("type") == "Ready" and c.get("status") == "True"
                         for c in node["status"].get("conditions", [])),
        } for node in nodes
    }


def _fixture_workload(lab):
    lab.kubectl("create", "namespace", NAMESPACE)
    labels = {"app": NAME}
    pod = {
        "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "tolerations": [{"key": "node-role.kubernetes.io/control-plane", "operator": "Exists",
                         "effect": "NoSchedule"}],
        "affinity": {"podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [
            {"labelSelector": {"matchLabels": labels}, "topologyKey": "kubernetes.io/hostname"},
        ]}},
        "containers": [{"name": "fixture", "image": BUSYBOX_IMAGE,
                        "command": ["sh", "-ec", (
                            "mkdir -p /tmp/saf-site; printf '%s' " + BODY
                            + " >/tmp/saf-site/status; exec httpd -f -p 8080 -h /tmp/saf-site"
                        )],
                        "readinessProbe": {"httpGet": {"path": "/status", "port": 8080}, "periodSeconds": 2},
                        "securityContext": {"allowPrivilegeEscalation": False,
                                            "capabilities": {"drop": ["ALL"]}}}],
    }
    resources = (
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": NAME},
         "spec": {"replicas": 2, "selector": {"matchLabels": labels},
                  "template": {"metadata": {"labels": labels}, "spec": pod}}},
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": NAME},
         "spec": {"selector": labels, "ports": [{"port": 8080, "targetPort": 8080}]}},
        {"apiVersion": "policy/v1", "kind": "PodDisruptionBudget", "metadata": {"name": NAME},
         "spec": {"minAvailable": 1, "selector": {"matchLabels": labels}}},
    )
    for item in resources:
        item["metadata"]["namespace"] = NAMESPACE
        _create(lab, NAMESPACE, item)
    return {"deployment": _get(lab, "-n", NAMESPACE, "get", "deployment", NAME)["metadata"]["uid"],
            "service": _get(lab, "-n", NAMESPACE, "get", "service", NAME)["metadata"]["uid"]}


def _observe_workload(lab, label, initial_uid, nodes):
    lab.kubectl("-n", NAMESPACE, "rollout", "status", f"deployment/{NAME}", "--timeout=120s", timeout=135)
    probe = f"native-http-{label}"
    _create(lab, NAMESPACE, {
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": probe, "namespace": NAMESPACE},
        "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never",
                 "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                     "seccompProfile": {"type": "RuntimeDefault"}},
                 "containers": [{"name": "probe", "image": BUSYBOX_IMAGE,
                                 "command": ["sh", "-ec", (
                                     "for n in 1 2 3 4 5; do "
                                     f"if wget -qO- -T 3 http://{NAME}.{NAMESPACE}.svc.cluster.local:8080/status; "
                                     "then exit 0; fi; sleep 2; done; exit 1"
                                 )],
                                 "securityContext": {"allowPrivilegeEscalation": False,
                                                     "capabilities": {"drop": ["ALL"]}}}]},
    })
    lab.kubectl("-n", NAMESPACE, "wait", "--for=jsonpath={.status.phase}=Succeeded",
                f"pod/{probe}", "--timeout=65s", timeout=80)
    output = lab.kubectl("-n", NAMESPACE, "logs", probe).stdout
    lab.kubectl("-n", NAMESPACE, "delete", "pod", probe, "--wait=true")
    deployment = _get(lab, "-n", NAMESPACE, "get", "deployment", NAME)
    service = _get(lab, "-n", NAMESPACE, "get", "service", NAME)
    pods = _get(lab, "-n", NAMESPACE, "get", "pods", "-l", f"app={NAME}")["items"]
    slices = _get(lab, "-n", NAMESPACE, "get", "endpointslices",
                  "-l", f"kubernetes.io/service-name={NAME}")["items"]
    expected = {pod["metadata"]["uid"] for pod in pods if not pod["metadata"].get("deletionTimestamp")
                and any(c.get("type") == "Ready" and c.get("status") == "True"
                        for c in pod["status"].get("conditions", []))}
    actual = [endpoint for s in slices for endpoint in s["endpoints"]
              if endpoint.get("conditions", {}).get("ready") is True]
    return {
        "dns_routed_http_body_matches": output == BODY,
        "deployment_and_service_identity_preserved": deployment["metadata"]["uid"] == initial_uid["deployment"]
        and service["metadata"]["uid"] == initial_uid["service"],
        "both_expected_backends_are_ready": len(expected) == len(actual) == 2
        and {ep["targetRef"]["uid"] for ep in actual} == expected
        and {ep.get("nodeName") for ep in actual} == set(nodes),
    }


def _new_kubelet(lab, node):
    # Both paths are inside a runner-owned node and replacement is atomic.
    lab.command("docker", "exec", node, "sh", "-ec",
                f"install -m 0755 {KUBELET_STAGE} /usr/bin/kubelet.saf-next; "
                "mv /usr/bin/kubelet.saf-next /usr/bin/kubelet; "
                "systemctl daemon-reload; systemctl restart kubelet; systemctl is-active kubelet",
                timeout=70)
    lab.command("docker", "exec", node, "kubelet", "--version")
    for _ in range(30):
        observed = _get(lab, "get", "node", node)
        if observed["status"]["nodeInfo"]["kubeletVersion"] == TARGET and any(
            c.get("type") == "Ready" and c.get("status") == "True" for c in observed["status"]["conditions"]
        ):
            return
        time.sleep(2)
    lab.block("The exact upgraded kubelet version and Ready condition were not observed")


def _addons(lab, nodes, cni_image):
    for resource in ("deployment/coredns", "daemonset/kube-proxy", "daemonset/kindnet"):
        lab.kubectl("-n", "kube-system", "rollout", "status", resource, "--timeout=130s", timeout=145)
    pods = _get(lab, "-n", "kube-system", "get", "pods", "-l", "k8s-app=kube-proxy")["items"]
    live = [pod for pod in pods if not pod["metadata"].get("deletionTimestamp")]
    dns = _get(lab, "-n", "kube-system", "get", "deployment", "coredns")
    network = _get(lab, "-n", "kube-system", "get", "daemonset", "kindnet")
    static_components = ("kube-apiserver", "kube-controller-manager", "kube-scheduler")
    # The API can read restored etcd state before kubelet publishes Ready on every mirror Pod.
    lab.kubectl("-n", "kube-system", "wait", "--for=condition=Ready",
                *(f"pod/{component}-{nodes[0]}" for component in static_components),
                "--timeout=80s", timeout=95)
    static_pods = {
        component: _get(lab, "-n", "kube-system", "get", "pod", f"{component}-{nodes[0]}")
        for component in static_components
    }
    return {
        "static_control_plane_target_images_ready": all(
            pod["spec"]["containers"][0]["image"] == image_ref(component)
            and pod["status"]["containerStatuses"][0]["ready"]
            and bool(pod["status"]["containerStatuses"][0].get("imageID"))
            for component, pod in static_pods.items()
        ),
        "baseline_kindnet_image_still_ready_on_both_nodes": (
            network["spec"]["template"]["spec"]["containers"][0]["image"] == cni_image
            and network["status"].get("numberReady") == network["status"].get("desiredNumberScheduled")
            == len(nodes)
        ),
        "kube_proxy_target_image_ready_on_each_node": len(live) == len(nodes)
        and {pod["spec"]["nodeName"] for pod in live} == set(nodes)
        and all(pod["spec"]["containers"][0]["image"] == image_ref("kube-proxy")
                and pod["status"]["containerStatuses"][0]["ready"]
                and pod["status"]["containerStatuses"][0].get("imageID") for pod in live),
        "coredns_expected_image_and_rollout_available": (
            dns["spec"]["template"]["spec"]["containers"][0]["image"] == "registry.k8s.io/coredns/coredns:v1.14.2"
            and dns["status"].get("availableReplicas") == dns["spec"]["replicas"] > 0
        ),
    }


def _recover(lab, control_plane, staging, recovery):
    namespace = recovery["NAMESPACE"]
    sentinel = recovery["OBJECT_NAME"]
    label = "saf-k8s.example/fixture"
    etcd_pod = f"etcd-{control_plane}"
    etcd = _get(lab, "-n", "kube-system", "get", "pod", etcd_pod)
    if etcd["spec"]["nodeName"] != control_plane or len(etcd["spec"]["containers"]) != 1:
        lab.block("The etcd mirror is outside the owned single-member profile")
    member = etcd["spec"]["containers"][0]
    if member["image"] != "registry.k8s.io/etcd:3.6.8-0" or not any(
        row.get("hostPath", {}).get("path") == recovery["DATA_DIRECTORY"] for row in etcd["spec"]["volumes"]
    ):
        lab.block("The observed etcd version or storage layout is outside the reviewed fixture")
    flags = dict(value[2:].split("=", 1) for value in member.get("command", []) + member.get("args", [])
                 if value.startswith("--") and "=" in value)
    initial = flags["initial-cluster"]
    if "," in initial or initial != f"{flags['name']}={flags['initial-advertise-peer-urls']}":
        lab.block("The etcd mirror does not describe the single owned recovery member")
    manifest = lab.command("docker", "exec", control_plane, "cat", "/etc/kubernetes/manifests/etcd.yaml").stdout
    if manifest.count("path: /var/lib/etcd") != 1:
        lab.block("The owned static manifest does not have the reviewed hostPath")

    lab.kubectl("create", "namespace", namespace)
    baseline = _create(lab, namespace, {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": sentinel, "namespace": namespace, "labels": {label: "post-upgrade-recovery"}},
        "data": {"state": "healthy-after-upgrade"},
    })
    backup_dir = staging / "recovery"
    backup_dir.mkdir(mode=0o700)
    artifact = backup_dir / "post-upgrade.db"
    mount = f"type=bind,source={backup_dir},target=/backup"
    recovery["snapshot"](lab, control_plane, etcd_pod, artifact)
    digest = recovery["sha256"](artifact)
    revision = recovery["native_snapshot_revision"](lab, mount, artifact.name)
    if not revision:
        lab.block("The candidate-platform recovery snapshot failed native verification")
    lab.kubectl("-n", namespace, "patch", "configmap", sentinel, "--type=merge",
                "-p", '{"data":{"state":"simulated-data-loss"}}')
    changed = recovery["api_object"](lab)
    injected = changed["metadata"]["uid"] == baseline["metadata"]["uid"] and (
        changed["data"]["state"] == "simulated-data-loss"
    )
    lab.check("red", "The injected post-upgrade state loss is visible through the target API",
              injected, {"fixture_state_loss_observed": injected, "snapshot_native_status_valid": bool(revision)})
    def wait_for_restored_api(*args, **kwargs):
        if args != ("get", "--raw=/readyz"):
            return lab.kubectl(*args, **kwargs)
        deadline = time.monotonic() + 70
        while time.monotonic() < deadline:
            result = lab.kubectl(*args, timeout=12, allow_failure=True)
            if result.returncode == 0 and result.stdout.strip() == "ok":
                return result
            time.sleep(2)
        lab.block("The restored API did not complete its readiness checks")

    # The legacy recovery routine makes one final readiness call. The upgraded
    # API can return the snapshot sentinel before its post-start hooks finish.
    restored_lab = SimpleNamespace(env=lab.env, command=lab.command,
                                   kubectl=wait_for_restored_api, block=lab.block)
    restored, ready = recovery["restore_api"](
        restored_lab, control_plane, flags["name"], initial, flags["initial-advertise-peer-urls"],
        manifest, artifact, backup_dir, mount, digest, "healthy-after-upgrade",
    )
    listing = json.loads(lab.kubectl(
        "get", f"--raw=/api/v1/namespaces/{namespace}/configmaps?fieldSelector=metadata.name%3D{sentinel}"
    ).stdout)
    checks = {
        "restored_exact_uid_and_data": restored["metadata"]["uid"] == baseline["metadata"]["uid"]
        and restored["data"] == baseline["data"],
        "control_plane_became_ready": ready,
        "target_server_version_preserved": _server(lab) == TARGET,
        "recovery_revision_bumped": int(listing["metadata"]["resourceVersion"])
        >= revision + recovery["REVISION_BUMP"],
    }
    lab.check("green", "Verified post-upgrade etcd restore recovers the original API state on the target version",
              all(checks.values()), checks)
    return checks


def run_native_upgrade(lab):
    control_plane = f"{lab.cluster}-control-plane"
    worker = f"{lab.cluster}-worker"
    nodes = (control_plane, worker)
    observed = set(lab.command("kind", "get", "nodes", "--name", lab.cluster).stdout.splitlines())
    if observed != set(nodes) or _server(lab) != BASELINE:
        lab.block("The owned two-node Kind cluster and exact baseline are required")
    recovery_path = Path(__file__).resolve().parents[1] / "SAF-K8S-1005-030" / "case.py"
    if not recovery_path.is_file():
        lab.block("The published SAF-K8S-1005-030 recovery helper is required")
    recovery = runpy.run_path(str(recovery_path))
    recovery_sha256 = hashlib.sha256(recovery_path.read_bytes()).hexdigest()
    baseline_nodes = _observed_nodes(lab, *nodes)
    cni_image = _get(lab, "-n", "kube-system", "get", "daemonset", "kindnet")[
        "spec"]["template"]["spec"]["containers"][0]["image"]
    identity = _fixture_workload(lab)
    before = _observe_workload(lab, "baseline", identity, nodes)
    lab.check("positive", "The baseline routes an HTTP request to the healthy synthetic Service",
              all(before.values()), before)

    with tempfile.TemporaryDirectory(prefix="saf-native-", dir=lab.kubeconfig.parent) as directory:
        staging = Path(directory)
        assets = _copy_target_assets(lab, staging, nodes)
        lab.command("docker", "exec", control_plane, KUBEADM, "upgrade", "apply", TARGET,
                    "--dry-run", "--yes", "--etcd-upgrade=false", timeout=120)
        dry_run = _server(lab) == BASELINE and _observed_nodes(lab, *nodes) == baseline_nodes
        lab.check("positive", "Native kubeadm dry-run preserves the baseline server and node versions",
                  dry_run, {"version_and_ready_baseline_preserved": dry_run})

        lab.command("docker", "exec", control_plane, KUBEADM, "upgrade", "apply", TARGET,
                    "--yes", "--etcd-upgrade=false", timeout=385)
        upgraded_server = _server(lab)
        skew = _observed_nodes(lab, *nodes)
        intermediate = {
            "api_server_at_exact_target": upgraded_server == TARGET,
            "worker_stayed_on_baseline_until_its_turn": skew["worker"] == baseline_nodes["worker"],
        }
        lab.check("green", "Native control-plane upgrade precedes the worker transition",
                  all(intermediate.values()), intermediate)
        _new_kubelet(lab, control_plane)
        lab.kubectl("drain", worker, "--ignore-daemonsets", "--timeout=100s", timeout=115)
        lab.command("docker", "exec", worker, KUBEADM, "upgrade", "node", timeout=100)
        _new_kubelet(lab, worker)
        lab.kubectl("uncordon", worker)

        upgraded = _observed_nodes(lab, *nodes)
        worker_results = {
            "both_upgraded_nodes_are_ready": all(row["version"] == TARGET and row["ready"]
                                                for row in upgraded.values()),
            "both_original_node_uids_preserved": all(row["uid"] == baseline_nodes[role]["uid"]
                                                     for role, row in upgraded.items()),
            **_addons(lab, nodes, cni_image),
            **_observe_workload(lab, "upgraded", identity, nodes),
        }
        lab.check("positive", "Upgraded kubelets and native add-ons serve the same workload through real DNS and HTTP",
                  all(worker_results.values()), worker_results)

        recovered = _recover(lab, control_plane, staging, recovery)
        after_nodes = _observed_nodes(lab, *nodes)
        after = {
            "both_node_versions_and_identities_preserved": after_nodes == upgraded,
            **_addons(lab, nodes, cni_image),
            **_observe_workload(lab, "recovered", identity, nodes),
        }
        lab.check("positive", "Recovered infrastructure still runs the upgraded add-ons and original workload",
                  all(after.values()), after)

    (lab.evidence / "native-upgrade.raw.json").write_text(json.dumps({
        "baseline_server": BASELINE, "target_server": upgraded_server, "binaries_and_images": assets,
        "dry_run_preserved_baseline": dry_run, "upgrade_order": intermediate,
        "worker_and_addon_checks": worker_results, "post_upgrade_etcd_recovery": recovered,
        "post_recovery_checks": after, "etcd_binary_upgrade_requested": False,
        "unchanged_cni_image": cni_image, "recovery_helper_sha256": recovery_sha256,
    }, indent=2) + "\n", encoding="utf-8")
