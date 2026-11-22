"""Exercise classification-selected storage and NetworkPolicy on kind."""
import ipaddress
import json
import time

from fixtures import container, pod


SENSITIVE = "saf-0702-029-sensitive"
LOWER = "saf-0702-029-lower"
CLASSIFICATION = "saf-k8s.example/data-classification"
REQUIRED = "saf-k8s.example/required-classification"
APP = "saf-k8s.example/0702-029-role"
CONFIDENTIAL = "synthetic-confidential"
INTERNAL = "synthetic-internal"
PORT = 8080
MARKERS = {SENSITIVE: "synthetic-confidential-endpoint",
           LOWER: "synthetic-internal-endpoint"}
STORAGE_CLASS = "saf-0702-029-local"
PV_NAME = "saf-0702-029-confidential-pv"
PVC_NAME = "saf-0702-029-confidential-claim"
FILE_MARKER = "synthetic-classified-storage-marker"
FILE_PATH = "/data/saf-k8s-0702-029-marker"

SCOPE = (
    "One disposable Kubernetes v1.36.1 kind cluster with the bundled kindnet CNI, "
    "two fixture namespaces carrying synthetic required-classification labels, and "
    "case-owned Pods. Exercises one IPv4 TCP/8080 request allowed to a same-class "
    "listener and denied to a lower-class listener after an egress NetworkPolicy; "
    "also guards a case-owned PVC through native admission and verifies a bound local PV "
    "with a synthetic write/read across Pods. Uses no external targets or "
    "real data. Does not establish production CNI behavior, general storage access "
    "authorization, full hostPath isolation, other protocols/address families, or "
    "organization-wide classification governance."
)


def create(lab, resource):
    namespace = resource.get("metadata", {}).get("namespace")
    args = ("-n", namespace) if namespace else ()
    lab.kubectl(*args, "create", "-f", "-", payload=json.dumps(resource))


def labels(classification):
    return {CLASSIFICATION: classification}


def listener(lab, namespace, classification):
    name = "fixed-listener"
    command = ["sh", "-ec", f"printf %s {MARKERS[namespace]} >/tmp/index.html; "
               f"exec httpd -f -p {PORT} -h /tmp"]
    workload = pod(name, [container("listener", command=command)],
                   automountServiceAccountToken=False)
    workload["metadata"].update(namespace=namespace,
                                labels={**labels(classification), APP: "listener"})
    create(lab, workload)
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=90s", timeout=100)
    current = json.loads(lab.kubectl("-n", namespace, "get", f"pod/{name}", "-o", "json").stdout)
    address = current.get("status", {}).get("podIP")
    if not address or ipaddress.ip_address(address).version != 4:
        lab.block("Fixture listener has no owned IPv4 Pod address")
    return address


def client(lab):
    workload = pod("classified-client", [container("client")],
                   automountServiceAccountToken=False)
    workload["metadata"].update(namespace=SENSITIVE,
                                labels={**labels(CONFIDENTIAL), APP: "client"})
    create(lab, workload)
    lab.kubectl("-n", SENSITIVE, "wait", "--for=condition=Ready", "pod/classified-client",
                "--timeout=90s", timeout=100)


def request(lab, destination):
    result = lab.kubectl(
        "-n", SENSITIVE, "exec", "pod/classified-client", "--", "wget", "-T", "2",
        "-O", "-", f"http://{destination}:{PORT}/", allow_failure=True, timeout=12,
    )
    if result.returncode == 0:
        if result.stdout.strip() not in MARKERS.values():
            lab.block("Fixture HTTP request returned an unexpected response")
        return result.stdout.strip()
    output = (result.stdout + result.stderr).lower()
    if any(reason in output for reason in (
            "timed out", "connection refused", "no route to host", "network is unreachable")):
        return None
    lab.block("HTTP probe did not execute or return an ordinary network outcome")


def expect_path(lab, phase, destination, expected_marker, allowed, claim):
    deadline = time.monotonic() + 30
    consecutive = 0
    observed = None
    while time.monotonic() < deadline:
        observed = request(lab, destination)
        matched = observed == expected_marker if allowed else observed is None
        consecutive = consecutive + 1 if matched else 0
        if consecutive == 2:
            break
        time.sleep(0.5)
    lab.check(phase, claim, consecutive == 2,
              {"expected_reachable": allowed, "observed_marker": observed,
               "two_consecutive_observations": consecutive == 2,
               "destination_port": PORT})


def namespace(lab, name, classification):
    lab.kubectl("create", "namespace", name)
    lab.kubectl("label", "namespace", name,
                f"{REQUIRED}={classification}")


def static_volume(name, classification):
    return {
        "apiVersion": "v1", "kind": "PersistentVolume",
        "metadata": {"name": name, "labels": labels(classification)},
        "spec": {
            "capacity": {"storage": "1Mi"}, "accessModes": ["ReadWriteOnce"],
            "persistentVolumeReclaimPolicy": "Retain", "storageClassName": STORAGE_CLASS,
            "hostPath": {"path": f"/var/lib/saf-k8s-0702-029/{classification}",
                         "type": "Directory"},
        },
    }


def claim():
    return {
        "apiVersion": "v1", "kind": "PersistentVolumeClaim",
        "metadata": {"name": PVC_NAME, "namespace": SENSITIVE,
                     "labels": labels(CONFIDENTIAL)},
        "spec": {
            "storageClassName": STORAGE_CLASS, "accessModes": ["ReadWriteOnce"],
            "resources": {"requests": {"storage": "1Mi"}},
            "selector": {"matchLabels": labels(CONFIDENTIAL)},
        },
    }


def storage_pod(name, command):
    workload = pod(name, [container("storage-probe", command=command,
                                     volumeMounts=[{"name": "classified-volume",
                                                    "mountPath": "/data"}])],
                   automountServiceAccountToken=False,
                   volumes=[{"name": "classified-volume",
                             "persistentVolumeClaim": {"claimName": PVC_NAME}}])
    workload["metadata"].update(namespace=SENSITIVE,
                                labels={**labels(CONFIDENTIAL), APP: "storage-probe"})
    return workload


def expect_pod_exit(lab, name):
    lab.kubectl("-n", SENSITIVE, "wait", "--for=jsonpath={.status.phase}=Succeeded",
                f"pod/{name}", "--timeout=60s", timeout=70)


def guarded_storage(lab):
    name = "classification-storage"
    message = "the synthetic confidential claim requires a matching Pod classification"
    low = storage_pod("wrong-class-storage", ["true"])
    low["metadata"]["labels"][CLASSIFICATION] = INTERNAL
    before = lab.kubectl("-n", SENSITIVE, "create", "-f", "-", "--dry-run=server",
                         payload=json.dumps(low))
    lab.check("red", "Before the storage policy, the lower-class Pod can declare the fixture claim",
              before.returncode == 0, {"admitted_before_policy": before.returncode == 0})
    create(lab, {
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": name},
        "spec": {"failurePolicy": "Fail",
                 "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                        "operations": ["CREATE", "UPDATE"],
                                                        "resources": ["pods"]}]},
                 "validations": [{
                     "expression": (
                         f'!has(object.spec.volumes) || !object.spec.volumes.exists(volume, '
                         f'has(volume.persistentVolumeClaim) && volume.persistentVolumeClaim.claimName == "{PVC_NAME}") || '
                         f'(has(object.metadata.labels) && "{CLASSIFICATION}" in object.metadata.labels && '
                         f'object.metadata.labels["{CLASSIFICATION}"] == "{CONFIDENTIAL}")'
                     ), "message": message, "reason": "Forbidden",
                 }]},
    })
    create(lab, {
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": name},
        "spec": {"policyName": name, "validationActions": ["Deny"],
                 "matchResources": {"namespaceSelector": {"matchLabels": {
                     "kubernetes.io/metadata.name": SENSITIVE
                 }}}},
    })
    deadline = time.monotonic() + 20
    while True:
        after = lab.kubectl("-n", SENSITIVE, "create", "-f", "-", "--dry-run=server",
                            payload=json.dumps(low), allow_failure=True)
        denied = after.returncode != 0 and message in after.stderr and f"'{name}'" in after.stderr
        if denied or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check("green", "The same lower-class Pod is denied a reference to the classified PVC",
              denied, {"denied_by_storage_policy": denied})


def storage_path(lab):
    for classification in (CONFIDENTIAL, INTERNAL):
        lab.command("docker", "exec", f"{lab.cluster}-control-plane", "install", "-d",
                    "-m", "0750", "-o", "65534", "-g", "65534",
                    f"/var/lib/saf-k8s-0702-029/{classification}", timeout=15)
    create(lab, static_volume(PV_NAME, CONFIDENTIAL))
    # A decoy in the same class proves the PVC selector chooses by classification.
    create(lab, static_volume("saf-0702-029-internal-pv", INTERNAL))
    create(lab, claim())
    lab.kubectl("-n", SENSITIVE, "wait", f"pvc/{PVC_NAME}",
                "--for=jsonpath={.status.phase}=Bound", "--timeout=60s", timeout=70)
    bound = json.loads(lab.kubectl("-n", SENSITIVE, "get", f"pvc/{PVC_NAME}", "-o", "json").stdout)
    volume_name = bound.get("spec", {}).get("volumeName")
    pv = json.loads(lab.kubectl("get", "pv", volume_name, "-o", "json").stdout)
    exact_binding = (volume_name == PV_NAME
                     and pv.get("metadata", {}).get("labels", {}).get(CLASSIFICATION) == CONFIDENTIAL)
    lab.check("positive", "The classified PVC binds only to its matching labeled PV",
              bound.get("status", {}).get("phase") == "Bound" and exact_binding,
              {"claim_phase": bound.get("status", {}).get("phase"),
               "bound_volume": volume_name,
               "bound_volume_classification": pv.get("metadata", {}).get("labels", {}).get(CLASSIFICATION),
               "storage_class": bound.get("spec", {}).get("storageClassName")})

    guarded_storage(lab)
    writer = storage_pod("storage-writer", ["sh", "-ec", f"printf %s {FILE_MARKER} >{FILE_PATH}"])
    create(lab, writer)
    expect_pod_exit(lab, "storage-writer")
    reader = storage_pod("storage-reader", ["sh", "-ec", f"cat {FILE_PATH}"])
    create(lab, reader)
    expect_pod_exit(lab, "storage-reader")
    output = lab.kubectl("-n", SENSITIVE, "logs", "pod/storage-reader").stdout.strip()
    lab.check("positive", "A second Pod reads the synthetic marker from the bound claim",
              output == FILE_MARKER,
              {"read_marker_matches": output == FILE_MARKER,
               "persistent_volume": volume_name,
               "file_path": FILE_PATH})


def run(lab):
    kind_version = lab.command("kind", "version").stdout.strip()
    if not kind_version.startswith("kind v0.32.0"):
        lab.block(f"Expected kind v0.32.0 with bundled kindnet, got {kind_version!r}")
    server = json.loads(lab.kubectl("version", "-o", "json").stdout).get("serverVersion", {})
    if server.get("gitVersion") != "v1.36.1":
        lab.block(f"Expected Kubernetes v1.36.1, got {server.get('gitVersion')!r}")
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet",
                "--timeout=60s", timeout=70)
    net = json.loads(lab.kubectl(
        "-n", "kube-system", "get", "daemonset", "kindnet", "-o", "json").stdout)
    images = [item["image"] for item in net["spec"]["template"]["spec"]["containers"]]
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    lab.check("positive", "The installed policy-capable kindnet CNI is ready and identified",
              len(nodes) == 1 and any("kindnetd" in image for image in images),
              {"kind_version": kind_version,
               "kubernetes_version": server.get("gitVersion"),
               "cni_daemonset": "kube-system/kindnet",
               "cni_images": images,
               "node_count": len(nodes)})

    namespace(lab, SENSITIVE, CONFIDENTIAL)
    namespace(lab, LOWER, INTERNAL)
    sensitive_address = listener(lab, SENSITIVE, CONFIDENTIAL)
    lower_address = listener(lab, LOWER, INTERNAL)
    client(lab)

    # Baseline reachability proves the request reaches the case-owned listener before policy.
    expect_path(lab, "red", lower_address, MARKERS[LOWER], True,
                "Before policy, the sensitive client reaches the live lower-class listener")
    storage_path(lab)

    create(lab, {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": "classification-egress", "namespace": SENSITIVE},
        "spec": {
            "podSelector": {"matchLabels": {**labels(CONFIDENTIAL), APP: "client"}},
            "policyTypes": ["Egress"],
            "egress": [{
                "to": [{
                    "namespaceSelector": {"matchLabels": {REQUIRED: CONFIDENTIAL}},
                    "podSelector": {"matchLabels": {**labels(CONFIDENTIAL), APP: "listener"}},
                }],
                "ports": [{"protocol": "TCP", "port": PORT}],
            }],
        },
    })
    expect_path(lab, "green", lower_address, MARKERS[LOWER], False,
                "Classification egress policy blocks the lower-class listener")
    expect_path(lab, "positive", sensitive_address, MARKERS[SENSITIVE], True,
                "The same-class listener remains reachable under the policy")
