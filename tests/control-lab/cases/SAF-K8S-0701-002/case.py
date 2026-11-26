"""Bounded filesystem-only test of the pinned upstream CSI hostpath demo."""
import json
import runpy
import time
from pathlib import Path

from fixtures import pod

NAMESPACE = "saf-0701-002-csi"
DRIVER_NAMESPACE = "saf-0701-002-driver"
DRIVER_SA = "csi-hostpathplugin-sa"
DRIVER_POD = "csi-hostpathplugin-0"
PVC = "saf-0701-002-pvc"
WORKLOAD = "saf-0701-002-volume-check"
MARKER = "saf-0701-002-marker-v1"
SCOPE = (
    "One fresh single-node Kubernetes v1.36.1 Kind cluster. Preserves the prior "
    "authenticated workload identity checks, and adapts the pinned upstream "
    "Kubernetes v1.36.1 SIG Storage hostpath e2e fixture to "
    "filesystem provisioning with the pinned hostpathplugin, node-driver-registrar "
    "and external-provisioner images. The upstream fixture uses one shared CSI "
    "ServiceAccount for its combined node/controller Pod; this case checks that "
    "actual shared identity's effective authorization and does not claim separate "
    "node/controller identities. A benign PVC marker is written and read back. "
    "No snapshots, block devices, resize, attachment, external sockets or user host mounts."
)

PINS_PATH = Path(__file__).with_name("pins.json")
PINS = json.loads(PINS_PATH.read_text())
IMAGE = {name: entry["image"] for name, entry in PINS["images"].items()}
NODE_IMAGE = PINS["kind_node_image"]


def prepare_kind(_lab, temporary):
    config = temporary / "kind.yaml"
    config.write_bytes(Path(__file__).with_name("kind.yaml").read_bytes())
    return config


def _obj(api, kind, name, namespace=None, **fields):
    metadata = {"name": name}
    if namespace:
        metadata["namespace"] = namespace
    return {"apiVersion": api, "kind": kind, "metadata": metadata, **fields}


def _create(lab, resource):
    namespace = resource["metadata"].get("namespace")
    if namespace is None:
        return lab.create(resource)
    return json.loads(lab.kubectl("create", "-n", namespace, "-f", "-", "-o", "json",
                                  payload=json.dumps(resource)).stdout)


def _wait(lab, description, predicate, timeout=100):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(1)
    lab.block(f"Timed out waiting for {description}")


def _sar(lab, verb, group, resource, *, name="", namespace=""):
    subject = f"system:serviceaccount:{DRIVER_NAMESPACE}:{DRIVER_SA}"
    groups = ["system:serviceaccounts", f"system:serviceaccounts:{DRIVER_NAMESPACE}",
              "system:authenticated"]
    attrs = {"verb": verb, "group": group, "resource": resource}
    if name:
        attrs["name"] = name
    if namespace:
        attrs["namespace"] = namespace
    review = {
        "apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview",
        "spec": {"user": subject, "groups": groups, "resourceAttributes": attrs},
    }
    result = lab.kubectl("create", "-f", "-", "-o", "json",
                         payload=json.dumps(review))
    status = json.loads(result.stdout)["status"]
    if status.get("evaluationError"):
        return None
    return status.get("allowed") is True


def _pod_details(lab):
    item = json.loads(lab.kubectl("get", "pod", DRIVER_POD, "-n", DRIVER_NAMESPACE,
                                  "-o", "json").stdout)
    return item


def _verify_node_container_is_unbound(lab):
    # Query only bind destinations and modes. The sole allowed bind is the
    # ordinary read-only kernel module path, outside the deployed CSI host paths.
    node = f"{lab.cluster}-control-plane"
    template = '{{range .Mounts}}{{if eq .Type "bind"}}{{.Destination}}:{{.RW}} {{end}}{{end}}'
    raw = lab.command("docker", "inspect", node, "--format", template)
    return raw.stdout.split() in ([], ["/lib/modules:false"])


def run(lab):
    if PINS["kubernetes_e2e_tag"] != "v1.36.1":
        lab.block("Image pin metadata does not match the v1.36.1 upstream fixture")
    if PINS["upstream_manifest_blob"] != "2fe67ffb719cb2165364420581c3e7b835755f54":
        lab.block("Upstream manifest blob differs from the reviewed v1.36.1 fixture")
    if PINS["kind_node_image"] != "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5":
        lab.block("Kind node image pin differs from the existing v1.36.1 lab runner pin")
    for name in ("hostpath", "registrar", "provisioner"):
        image = IMAGE.get(name, "")
        if "@sha256:" not in image or len(image.rsplit("@sha256:", 1)[-1]) != 64:
            lab.block(f"Missing immutable image digest for {name}")

    kind_profile = Path(__file__).with_name("kind.yaml").read_text()
    no_extra_mounts = "extraMounts:" not in kind_profile
    lab.check("positive", "The reviewed Kind profile declares no host extraMounts",
              no_extra_mounts, {"kind_profile_has_no_extra_mounts": no_extra_mounts})
    if not no_extra_mounts:
        lab.block("Refusing CSI node hostPath deployment when Kind extraMounts are configured")
    node_unbound = _verify_node_container_is_unbound(lab)
    lab.check("positive", "The disposable Kind node has no user host bind mounts",
              node_unbound, {"kind_node_has_no_user_host_bind_mounts": node_unbound})
    if not node_unbound:
        lab.block("Refusing CSI node hostPath deployment when the Kind node has user host bind mounts")

    runpy.run_path(str(Path(__file__).with_name("identity_fixture.py")))["run"](lab)

    lab.kubectl("create", "namespace", DRIVER_NAMESPACE)
    lab.kubectl("create", "namespace", NAMESPACE)
    _create(lab, _obj("v1", "ServiceAccount", DRIVER_SA, DRIVER_NAMESPACE,
                      automountServiceAccountToken=False))

    # Minimal controller permissions for the selected external-provisioner mode.
    # No attach, snapshot, resize, Secret, or namespace-administration rules.
    role = _obj("rbac.authorization.k8s.io/v1", "ClusterRole", "saf-0701-002-provisioner")
    role["rules"] = [
        {"apiGroups": [""], "resources": ["persistentvolumes"],
         "verbs": ["get", "list", "watch", "create", "delete", "patch"]},
        {"apiGroups": [""], "resources": ["persistentvolumeclaims"],
         "verbs": ["get", "list", "watch", "update"]},
        {"apiGroups": [""], "resources": ["events"],
         "verbs": ["list", "watch", "create", "update", "patch"]},
        {"apiGroups": ["storage.k8s.io"], "resources": ["storageclasses", "csinodes"],
         "verbs": ["get", "list", "watch"]},
        {"apiGroups": [""], "resources": ["nodes"],
         "verbs": ["get", "list", "watch"]},
    ]
    lab.create(role)
    binding = _obj("rbac.authorization.k8s.io/v1", "ClusterRoleBinding",
                   "saf-0701-002-provisioner")
    binding.update(subjects=[{"kind": "ServiceAccount", "name": DRIVER_SA,
                              "namespace": DRIVER_NAMESPACE}],
                   roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                            "name": "saf-0701-002-provisioner"})
    lab.create(binding)

    driverinfo = _obj("storage.k8s.io/v1", "CSIDriver", "hostpath.csi.k8s.io")
    driverinfo["spec"] = {"attachRequired": False, "podInfoOnMount": True,
                          "fsGroupPolicy": "File", "volumeLifecycleModes": ["Persistent"]}
    lab.create(driverinfo)

    # This is the reviewed filesystem-only subset of the pinned upstream e2e Pod:
    # no /dev mount, no external Service/NodePort, no attacher/resizer/snapshotter.
    pod_labels = {"app.kubernetes.io/name": "csi-hostpathplugin",
                  "saf.example/fixture": "0701-002"}
    service = _obj("v1", "Service", "csi-hostpathplugin", DRIVER_NAMESPACE,
                   spec={"clusterIP": "None", "selector": pod_labels})
    _create(lab, service)
    pod_spec = {
        "serviceAccountName": DRIVER_SA,
        "automountServiceAccountToken": False,
        "containers": [
            {"name": "hostpath", "image": IMAGE["hostpath"],
             "imagePullPolicy": "IfNotPresent",
             "args": ["--drivername=hostpath.csi.k8s.io", "--v=2",
                      "--endpoint=$(CSI_ENDPOINT)", "--nodeid=$(KUBE_NODE_NAME)"],
             "env": [
                 {"name": "CSI_ENDPOINT", "value": "unix:///csi/csi.sock"},
                 {"name": "KUBE_NODE_NAME", "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}},
             ],
             "securityContext": {"privileged": True},
             "volumeMounts": [
                 {"name": "socket-dir", "mountPath": "/csi"},
                 {"name": "mountpoint-dir", "mountPath": "/var/lib/kubelet/pods",
                  "mountPropagation": "Bidirectional"},
                 {"name": "plugins-dir", "mountPath": "/var/lib/kubelet/plugins",
                  "mountPropagation": "Bidirectional"},
                 {"name": "registration-dir", "mountPath": "/registration"},
                 {"name": "csi-data-dir", "mountPath": "/csi-data-dir"},
             ]},
            {"name": "node-driver-registrar", "image": IMAGE["registrar"],
             "imagePullPolicy": "IfNotPresent",
             "args": ["--v=2", "--csi-address=/csi/csi.sock",
                      "--kubelet-registration-path=/var/lib/kubelet/plugins/csi-hostpath/csi.sock"],
             "env": [{"name": "KUBE_NODE_NAME", "valueFrom":
                      {"fieldRef": {"fieldPath": "spec.nodeName"}}}],
             "volumeMounts": [{"name": "socket-dir", "mountPath": "/csi"},
                              {"name": "registration-dir", "mountPath": "/registration"}]},
            {"name": "csi-provisioner", "image": IMAGE["provisioner"],
             "imagePullPolicy": "IfNotPresent",
             "args": ["--v=2", "--csi-address=/csi/csi.sock",
                      "--feature-gates=Topology=true", "--leader-election=false"],
             "volumeMounts": [{"name": "socket-dir", "mountPath": "/csi"},
                              {"name": "api-credentials",
                               "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
                               "readOnly": True}]},
        ],
        "volumes": [
            {"name": "socket-dir", "hostPath": {"path": "/var/lib/kubelet/plugins/csi-hostpath",
                                                   "type": "DirectoryOrCreate"}},
            {"name": "mountpoint-dir", "hostPath": {"path": "/var/lib/kubelet/pods",
                                                       "type": "Directory"}},
            {"name": "plugins-dir", "hostPath": {"path": "/var/lib/kubelet/plugins",
                                                    "type": "Directory"}},
            {"name": "registration-dir", "hostPath": {"path": "/var/lib/kubelet/plugins_registry",
                                                         "type": "Directory"}},
            {"name": "csi-data-dir", "hostPath": {"path": "/var/lib/csi-hostpath-data",
                                                     "type": "DirectoryOrCreate"}},
            {"name": "api-credentials", "projected": {"sources": [
                {"serviceAccountToken": {"path": "token", "expirationSeconds": 3600}},
                {"configMap": {"name": "kube-root-ca.crt", "items": [
                    {"key": "ca.crt", "path": "ca.crt"}]}},
                {"downwardAPI": {"items": [
                    {"path": "namespace", "fieldRef": {"fieldPath": "metadata.namespace"}}]}},
            ]}},
        ],
        "tolerations": [{"operator": "Exists"}],
        "terminationGracePeriodSeconds": 10,
    }
    statefulset = _obj("apps/v1", "StatefulSet", "csi-hostpathplugin", DRIVER_NAMESPACE,
                       spec={"serviceName": "csi-hostpathplugin", "replicas": 1,
                             "selector": {"matchLabels": pod_labels},
                             "template": {"metadata": {"labels": pod_labels}, "spec": pod_spec}})
    _create(lab, statefulset)

    def driver_ready():
        try:
            item = _pod_details(lab)
        except Exception:
            return None
        if item.get("status", {}).get("phase") != "Running":
            return None
        statuses = item.get("status", {}).get("containerStatuses", [])
        if len(statuses) != 3 or not all(c.get("ready") for c in statuses):
            return None
        return item

    driver_pod = _wait(lab, "pinned CSI controller/node fixture readiness", driver_ready)
    architecture = json.loads(lab.kubectl("get", "node", "-o", "json").stdout)["items"][0]["status"]["nodeInfo"]["architecture"]
    platform = {"arm64": "linux/arm64", "amd64": "linux/amd64"}.get(architecture)
    if platform is None:
        lab.block(f"No reviewed hostpath image descriptor for node architecture {architecture}")
    status_images = {c["name"]: c.get("imageID", "")
                     for c in driver_pod["status"]["containerStatuses"]}
    pin_keys = {"hostpath": "hostpath", "node-driver-registrar": "registrar",
                "csi-provisioner": "provisioner"}
    spec_images = {c["name"]: c["image"] for c in driver_pod["spec"]["containers"]}
    image_match = True
    for container, key in pin_keys.items():
        image = IMAGE[key]
        repository_and_tag, index = image.split("@", 1)
        repository = repository_and_tag.rsplit(":", 1)[0]
        allowed_ids = {f"{repository}@{digest}" for digest in
                       (index, PINS["images"][key][platform])}
        image_match &= (spec_images.get(container) == image
                        and status_images.get(container) in allowed_ids)
    mounts = {container["name"]: [m["mountPath"] for m in container.get("volumeMounts", [])]
              for container in driver_pod["spec"]["containers"]}
    no_device_mount = all("/dev" not in paths for paths in mounts.values())
    credential_mount = "/var/run/secrets/kubernetes.io/serviceaccount"
    token_only_controller = (mounts["csi-provisioner"].count(credential_mount) == 1
                             and credential_mount not in mounts["hostpath"]
                             and credential_mount not in mounts["node-driver-registrar"]
                             and driver_pod["spec"].get("automountServiceAccountToken") is False)
    shared_sa = driver_pod["spec"].get("serviceAccountName") == DRIVER_SA
    privileged = next(c for c in driver_pod["spec"]["containers"] if c["name"] == "hostpath")
    privileged_only_driver = privileged.get("securityContext", {}).get("privileged") is True and all(
        c.get("securityContext", {}).get("privileged") is not True
        for c in driver_pod["spec"]["containers"] if c["name"] != "hostpath")
    lab.check("positive", "The exact upstream driver and required sidecars run with only the reviewed node privilege/mount profile",
              image_match and no_device_mount and shared_sa and privileged_only_driver
              and token_only_controller,
              {"pinned_images_match": image_match, "no_dev_mount": no_device_mount,
               "shared_actual_service_account": shared_sa,
               "privileged_only_hostpath_container": privileged_only_driver,
               "api_token_mounted_only_in_provisioner": token_only_controller,
               "node_mount_paths_are_kind_internal": True})

    effective = {
        "pv-create": _sar(lab, "create", "", "persistentvolumes"),
        "pvc-watch": _sar(lab, "watch", "", "persistentvolumeclaims"),
        "storageclass-get": _sar(lab, "get", "storage.k8s.io", "storageclasses"),
        "storageclass-create": _sar(lab, "create", "storage.k8s.io", "storageclasses"),
        "snapshot-create": _sar(lab, "create", "snapshot.storage.k8s.io", "volumesnapshots"),
        "secret-list": _sar(lab, "list", "", "secrets"),
        "namespace-delete": _sar(lab, "delete", "", "namespaces"),
    }
    expected_access = {"pv-create": True, "pvc-watch": True, "storageclass-get": True,
                       "storageclass-create": False, "snapshot-create": False,
                       "secret-list": False, "namespace-delete": False}
    access_ok = effective == expected_access
    lab.check("green", "The actual shared CSI ServiceAccount has only the selected provisioner authorization",
              access_ok, {"effective_sar_decisions": effective,
                          "all_expected": access_ok, "service_account_name": DRIVER_SA,
                          "controller_and_node_share_identity": True})

    sc = _obj("storage.k8s.io/v1", "StorageClass", "saf-0701-002-hostpath")
    sc["provisioner"] = "hostpath.csi.k8s.io"
    sc["reclaimPolicy"] = "Delete"
    sc["volumeBindingMode"] = "WaitForFirstConsumer"
    lab.create(sc)
    pvc = _obj("v1", "PersistentVolumeClaim", PVC, NAMESPACE,
               spec={"accessModes": ["ReadWriteOnce"],
                     "storageClassName": "saf-0701-002-hostpath",
                     "resources": {"requests": {"storage": "16Mi"}}})
    _create(lab, pvc)
    workload = pod(WORKLOAD, [{
        "name": "marker", "image": IMAGE["workload"],
        "command": ["sh", "-ec", f"printf '%s' '{MARKER}' > /data/marker; test \"$(cat /data/marker)\" = '{MARKER}'; echo CSI_MARKER_READBACK_OK; sleep 3600"],
        "securityContext": {"allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True,
                            "runAsUser": 65534,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "volumeMounts": [{"name": "owned", "mountPath": "/data"}],
    }], serviceAccountName="default", automountServiceAccountToken=False,
        securityContext={"fsGroup": 65534}, terminationGracePeriodSeconds=1,
        volumes=[{"name": "owned", "persistentVolumeClaim": {"claimName": PVC}}])
    workload["metadata"]["namespace"] = NAMESPACE
    _create(lab, workload)
    _wait(lab, "owned PVC binding and workload scheduling",
          lambda: (lambda state: True if state[0] and state[1] else None)(
              (json.loads(lab.kubectl("get", "pvc", PVC, "-n", NAMESPACE, "-o", "json").stdout)
               .get("status", {}).get("phase") == "Bound",
               json.loads(lab.kubectl("get", "pod", WORKLOAD, "-n", NAMESPACE, "-o", "json").stdout)
               .get("status", {}).get("phase") == "Running")), timeout=140)
    output = lab.kubectl("logs", WORKLOAD, "-n", NAMESPACE, "-c", "marker").stdout
    marker_ok = output.strip() == "CSI_MARKER_READBACK_OK"
    workload_state = json.loads(lab.kubectl("get", "pod", WORKLOAD, "-n", NAMESPACE,
                                            "-o", "json").stdout)
    workload_image_ok = (workload_state["spec"]["containers"][0]["image"] == IMAGE["workload"])
    pvc_state = json.loads(lab.kubectl("get", "pvc", PVC, "-n", NAMESPACE, "-o", "json").stdout)
    pv_name = pvc_state.get("spec", {}).get("volumeName", "")
    claim_uid = pvc_state["metadata"]["uid"]
    if pv_name != f"pvc-{claim_uid}":
        lab.block("Bound PV name does not match the case-owned PVC UID")
    pv = json.loads(lab.kubectl("get", "pv", pv_name, "-o", "json").stdout)
    reference = pv["spec"].get("claimRef", {})
    owned_pv = (reference.get("uid") == claim_uid and reference.get("namespace") == NAMESPACE
                and reference.get("name") == PVC
                and pv["spec"].get("csi", {}).get("driver") == "hostpath.csi.k8s.io")
    if not owned_pv:
        lab.block("The bound volume does not match the case-owned claim and pinned CSI driver")
    lab.check("positive", "An owned CSI PVC is provisioned and its inert marker is read back through the mounted volume",
              marker_ok and workload_image_ok,
              {"pvc_bound": True, "marker_readback_matches": marker_ok,
                          "workload_image_matches_pinned_reference": workload_image_ok,
                          "volume_uid_present": bool(claim_uid),
                          "pv_matches_case_claim_and_csi_driver": owned_pv})
    lab.kubectl("delete", "pod", WORKLOAD, "-n", NAMESPACE, "--wait=true", "--timeout=45s")
    lab.kubectl("delete", "pvc", PVC, "-n", NAMESPACE, "--wait=true", "--timeout=45s")
    _wait(lab, "case-owned PV reclamation",
          lambda: (lab.kubectl("get", "pv", pv_name, "-o", "json", allow_failure=True)
                   .returncode != 0), timeout=60)
    remaining = json.loads(lab.kubectl("get", "pv", "-o", "json").stdout)["items"]
    owned_remaining = any(item.get("metadata", {}).get("name") == pv_name for item in remaining)
    lab.check("positive", "The case-owned PVC and dynamically provisioned PV are reclaimed before cluster deletion",
              bool(pv_name) and not owned_remaining,
              {"owned_pv_reclaimed": bool(pv_name) and not owned_remaining,
               "owned_volume_attachment_expected": False})
