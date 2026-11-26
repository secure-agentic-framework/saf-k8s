"""Optional KubeRay 1.8.0 namespace-scoped supplement for SAF-K8S-0901-007.

Call run_kuberay_supplement(lab) after the original case's fixtures are applied.
This function intentionally does not create or start a Kind cluster.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time


HERE = Path(__file__).resolve().parent
CONTROL_ID = "SAF-K8S-0901-007"
CHART = HERE / "vendor" / "kuberay-operator-1.8.0.tgz"
CHART_SHA256 = "5a52af6c4781fb2e85404cda7c88c759a7dfd3697fa1246e59a46768f17da29f"
OPERATOR_IMAGE = (
    "quay.io/kuberay/operator:v1.8.0@sha256:"
    "3c3fa129852bdf8801e885189c0561d8848e73be5745f2204a49760216d42a58"
)
IMAGE_TAG = "quay.io/kuberay/operator:v1.8.0"
PROBE_IMAGE = (
    "docker.io/library/python:3.13.16-slim@sha256:"
    "70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f"
)
OPERATOR_NS = "saf-0901-007-operator"
ADJACENT_NS = "saf-0901-007-adjacent"
OPERATOR_SA = "kuberay-operator"
RELEASE = "kuberay-operator"
RAYCLUSTER = "saf-0901-007-kuberay-watched"
ADJACENT_RAYCLUSTER = "saf-0901-007-kuberay-adjacent"
PROBE_CONFIG = "saf-0901-007-kuberay-authz-probe"
PROBE_POD = "saf-0901-007-kuberay-authz-probe"
EXPECTED_SUBJECT = f"system:serviceaccount:{OPERATOR_NS}:{OPERATOR_SA}"
CRD_NAMES = (
    "rayclusters.ray.io",
    "raycronjobs.ray.io",
    "rayjobs.ray.io",
    "rayservices.ray.io",
)
EXPECTED_OBJECTS = Counter({
    ("CustomResourceDefinition", "rayclusters.ray.io"): 1,
    ("CustomResourceDefinition", "raycronjobs.ray.io"): 1,
    ("CustomResourceDefinition", "rayjobs.ray.io"): 1,
    ("CustomResourceDefinition", "rayservices.ray.io"): 1,
    ("Role", "kuberay-operator"): 1,
    ("Role", "kuberay-operator-leader-election"): 1,
    ("RoleBinding", "kuberay-operator"): 1,
    ("RoleBinding", "kuberay-operator-leader-election"): 1,
    ("ServiceAccount", "kuberay-operator"): 1,
    ("Service", "kuberay-operator"): 1,
    ("Deployment", "kuberay-operator"): 1,
})


def _kubectl(lab, namespace, *args, timeout=45, **kwargs):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
        f"kind-{lab.cluster}", f"--request-timeout={timeout - 5}s",
        "-n", namespace, *args, timeout=timeout, **kwargs,
    )


def _documents(text):
    pieces = []
    for piece in re.split(r"(?m)^---\s*$", text):
        piece = re.sub(r"(?m)^# Source:.*\n?", "", piece).strip()
        if piece:
            pieces.append(piece)
    return pieces


def _top_value(document, key):
    match = re.search(rf"(?m)^{re.escape(key)}:\s*([^\s#]+)\s*$", document)
    return match.group(1).strip("'\"") if match else None


def _metadata_values(document):
    match = re.search(r"(?m)^metadata:\s*\n((?:^[ \t]+.*\n)*)", document)
    if not match:
        return None, None
    block = match.group(1)
    name = re.search(r"(?m)^  name:\s*([^\s#]+)\s*$", block)
    namespace = re.search(r"(?m)^  namespace:\s*([^\s#]+)\s*$", block)
    return (name.group(1).strip("'\"") if name else None,
            namespace.group(1).strip("'\"") if namespace else None)


def _render_and_partition(lab):
    if not CHART.is_file():
        lab.block("The reviewed KubeRay 1.8.0 chart archive is missing")
    chart_hash = hashlib.sha256(CHART.read_bytes()).hexdigest()
    if chart_hash != CHART_SHA256:
        lab.block("The KubeRay chart archive digest does not match the official index")
    argv = [
        "helm", "template", RELEASE, str(CHART), "--namespace", OPERATOR_NS,
        "--include-crds",
        "--set", "singleNamespaceInstall=true",
        "--set", "crNamespacedRbacEnable=true",
        "--set", "rbacEnable=true",
        "--set", "webhooks.enabled=false",
        "--set", "nodeEventForwarder.enabled=false",
        "--set", "batchScheduler.enabled=false",
        "--set", "image.repository=quay.io/kuberay/operator",
        "--set", "image.tag=v1.8.0",
    ]
    # Helm output contains four large CRD schemas. Capture it directly rather than
    # copying tens of thousands of lines into the lab command log.
    try:
        result = subprocess.run(argv, capture_output=True, text=True, env=lab.env,
                               timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        lab.block(f"Unable to render the reviewed KubeRay chart: {error}")
    if result.returncode:
        lab.block("Helm failed to render the reviewed KubeRay chart")
    with (lab.evidence / "commands.log").open("a", encoding="utf-8") as log:
        log.write("$ " + " ".join(argv) + "\n")
        log.write(f"[captured render: {len(result.stdout)} characters; exit 0]\n\n")
    rendered = result.stdout
    docs = _documents(rendered)
    inventory = Counter()
    crds, namespaced = [], []
    for document in docs:
        kind = _top_value(document, "kind")
        name, namespace = _metadata_values(document)
        if not kind or not name:
            lab.block("Rendered KubeRay chart contains an unrecognized object")
        inventory[(kind, name)] += 1
        if kind == "CustomResourceDefinition":
            crds.append(document)
        else:
            if kind in {"ClusterRole", "ClusterRoleBinding", "MutatingWebhookConfiguration",
                        "ValidatingWebhookConfiguration", "Namespace"}:
                lab.block("Single-namespace chart rendered an out-of-scope cluster object")
            if namespace != OPERATOR_NS:
                lab.block("A rendered namespaced KubeRay resource escaped the operator namespace")
            namespaced.append(document)
    if inventory != EXPECTED_OBJECTS or len(crds) != 4 or len(namespaced) != 7:
        lab.block("KubeRay render inventory differs from the reviewed namespace-scoped chart")

    deployment_matches = [i for i, document in enumerate(namespaced)
                          if _top_value(document, "kind") == "Deployment"
                          and _metadata_values(document)[0] == "kuberay-operator"]
    if len(deployment_matches) != 1:
        lab.block("Rendered chart did not contain exactly one KubeRay operator Deployment")
    index = deployment_matches[0]
    image_pattern = re.compile(
        rf"(?m)^(\s*image:\s*)([\"']?){re.escape(IMAGE_TAG)}\2\s*$")
    image_matches = list(image_pattern.finditer(namespaced[index]))
    if len(image_matches) != 1:
        lab.block("Rendered operator Deployment did not contain exactly one expected tagged image")
    namespaced[index] = image_pattern.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{OPERATOR_IMAGE}{match.group(2)}",
        namespaced[index], count=1)
    if namespaced[index].count(OPERATOR_IMAGE) != 1:
        lab.block("Digest-pinned operator image was not set exactly once")
    return chart_hash, crds, namespaced


def _probe_script():
    return f'''import base64, json, os, ssl, urllib.error, urllib.request
TOKEN = open("/var/run/secrets/kubernetes.io/serviceaccount/token", encoding="utf-8").read().strip()
parts = TOKEN.split(".")
if len(parts) != 3:
    raise SystemExit("projected service-account token was not a JWT")
claims = parts[1] + "=" * (-len(parts[1]) % 4)
subject = json.loads(base64.urlsafe_b64decode(claims)).get("sub")
expected = {json.dumps(EXPECTED_SUBJECT)}
if subject != expected:
    raise SystemExit("projected token subject did not match the KubeRay operator ServiceAccount")
base = "https://" + os.environ["KUBERNETES_SERVICE_HOST"] + ":" + os.environ["KUBERNETES_SERVICE_PORT_HTTPS"]
context = ssl.create_default_context(cafile="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
token = "Bearer " + TOKEN
def get_list(name, namespace):
    url = base + "/apis/ray.io/v1/namespaces/" + namespace + "/rayclusters"
    request = urllib.request.Request(url, headers={{"Authorization": token}})
    try:
        with urllib.request.urlopen(request, context=context, timeout=8) as response:
            body = json.load(response)
            names = sorted(item.get("metadata", {{}}).get("name", "") for item in body.get("items", []))
            print(json.dumps({{"operation": name, "status": response.status,
                              "contains_case_owned_cluster": {json.dumps(RAYCLUSTER)} in names}}))
    except urllib.error.HTTPError as exc:
        print(json.dumps({{"operation": name, "status": exc.code}}))
print(json.dumps({{"operation": "identity", "subject": subject}}))
get_list("list_watched_namespace", {json.dumps(OPERATOR_NS)})
get_list("list_adjacent_namespace", {json.dumps(ADJACENT_NS)})
def get_cluster(name, namespace, cluster_name):
    url = base + "/apis/ray.io/v1/namespaces/" + namespace + "/rayclusters/" + cluster_name
    request = urllib.request.Request(url, headers={{"Authorization": token}})
    try:
        with urllib.request.urlopen(request, context=context, timeout=8) as response:
            response.read()
            print(json.dumps({{"operation": name, "status": response.status}}))
    except urllib.error.HTTPError as exc:
        print(json.dumps({{"operation": name, "status": exc.code}}))
def patch_status(name, namespace, cluster_name):
    url = base + "/apis/ray.io/v1/namespaces/" + namespace + "/rayclusters/" + cluster_name + "/status?dryRun=All"
    body = json.dumps({{"status": {{}}}}).encode("utf-8")
    request = urllib.request.Request(url, data=body,
        headers={{"Authorization": token, "Content-Type": "application/merge-patch+json"}}, method="PATCH")
    try:
        with urllib.request.urlopen(request, context=context, timeout=8) as response:
            response.read()
            print(json.dumps({{"operation": name, "status": response.status}}))
    except urllib.error.HTTPError as exc:
        print(json.dumps({{"operation": name, "status": exc.code}}))
def list_nodes():
    url = base + "/api/v1/nodes"
    request = urllib.request.Request(url, headers={{"Authorization": token}})
    try:
        with urllib.request.urlopen(request, context=context, timeout=8) as response:
            response.read()
            print(json.dumps({{"operation": "list_nodes", "status": response.status}}))
    except urllib.error.HTTPError as exc:
        print(json.dumps({{"operation": "list_nodes", "status": exc.code}}))
get_cluster("get_watched_cluster", {json.dumps(OPERATOR_NS)}, {json.dumps(RAYCLUSTER)})
get_cluster("get_adjacent_cluster", {json.dumps(ADJACENT_NS)}, {json.dumps(ADJACENT_RAYCLUSTER)})
patch_status("patch_watched_status", {json.dumps(OPERATOR_NS)}, {json.dumps(RAYCLUSTER)})
patch_status("patch_adjacent_status", {json.dumps(ADJACENT_NS)}, {json.dumps(ADJACENT_RAYCLUSTER)})
list_nodes()
'''


def _probe_pod():
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": PROBE_POD, "namespace": OPERATOR_NS,
                     "labels": {"saf-lab.example/control": CONTROL_ID,
                                "saf-lab.example/fixture": "kuberay-rbac-probe"}},
        "spec": {
            "serviceAccountName": OPERATOR_SA,
            "automountServiceAccountToken": True,
            "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "probe", "image": PROBE_IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "-c", _probe_script()],
                "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                              "limits": {"cpu": "100m", "memory": "96Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
            }],
        },
    }


def _authorization_matrix(lab):
    answers = {}
    for name, verb, namespace in (
        ("list_watched_namespace", "list", OPERATOR_NS),
        ("list_adjacent_namespace", "list", ADJACENT_NS),
        ("get_watched_cluster", "get", OPERATOR_NS),
        ("get_adjacent_cluster", "get", ADJACENT_NS),
        ("patch_watched_status", "patch", OPERATOR_NS),
        ("patch_adjacent_status", "patch", ADJACENT_NS),
        ("list_nodes", "list", None),
    ):
        resource = "nodes" if namespace is None else "rayclusters.ray.io"
        result = _kubectl(
            lab, namespace or OPERATOR_NS, "auth", "can-i", verb, resource,
            f"--as={EXPECTED_SUBJECT}",
            *(["--subresource=status"] if verb == "patch" else []),
            allow_failure=True,
        )
        answer = result.stdout.strip().lower()
        if (answer, result.returncode) not in {("yes", 0), ("no", 1)}:
            lab.block("kubectl auth can-i returned an unexpected KubeRay answer")
        answers[name] = answer == "yes"
    return answers


def _run_probe(lab):
    config = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": PROBE_CONFIG, "namespace": OPERATOR_NS,
                     "labels": {"saf-lab.example/control": CONTROL_ID,
                                "saf-lab.example/fixture": "kuberay-authz-probe-script"}},
        "data": {"probe.py": _probe_script()},
    }
    pod = _probe_pod()
    # Use a ConfigMap-mounted script to keep the probe command and collected records inert.
    pod["spec"]["containers"][0]["command"] = ["python", "-B", "/fixture/probe.py"]
    pod["spec"]["containers"][0]["volumeMounts"] = [
        {"name": "probe", "mountPath": "/fixture", "readOnly": True}]
    pod["spec"]["volumes"] = [{"name": "probe", "configMap": {"name": PROBE_CONFIG}}]
    _kubectl(lab, OPERATOR_NS, "apply", "-f", "-", payload=json.dumps(config))
    _kubectl(lab, OPERATOR_NS, "create", "-f", "-", payload=json.dumps(pod))
    _kubectl(lab, OPERATOR_NS, "wait", "--for=jsonpath={.status.phase}=Succeeded",
             f"pod/{PROBE_POD}", "--timeout=100s", timeout=110)
    lines = _kubectl(lab, OPERATOR_NS, "logs", PROBE_POD).stdout.splitlines()
    try:
        records = [json.loads(line) for line in lines if line.strip()]
    except json.JSONDecodeError:
        lab.block("KubeRay authorization probe emitted invalid JSON")
    by_name = {item.get("operation"): item for item in records}
    expected_names = {"identity", "list_watched_namespace", "list_adjacent_namespace",
                      "get_watched_cluster", "get_adjacent_cluster",
                      "patch_watched_status", "patch_adjacent_status", "list_nodes"}
    if set(by_name) != expected_names:
        lab.block("KubeRay authorization probe did not return the complete operation set")
    return by_name


def _raycluster(name, namespace):
    return {
        "apiVersion": "ray.io/v1", "kind": "RayCluster",
        "metadata": {"name": name, "namespace": namespace,
                     "labels": {"saf-lab.example/control": CONTROL_ID,
                                "saf-lab.example/fixture": "suspended-inert-raycluster"}},
        "spec": {
            "rayVersion": "2.9.0",
            "suspend": True,
            "headGroupSpec": {
                "rayStartParams": {"num-cpus": "0"},
                "template": {"spec": {"containers": [{
                    "name": "ray-head", "image": "registry.k8s.io/pause:3.10",
                }] }},
            },
            "workerGroupSpecs": [],
        },
    }


def _get_json(lab, namespace, *args):
    return json.loads(_kubectl(lab, namespace, *args, "-o", "json").stdout)


def _suspension_observed(status):
    return status.get("state") == "suspended" and any(
        condition.get("type") == "RayClusterSuspended" and condition.get("status") == "True"
        for condition in status.get("conditions", []))


def _wait_suspended(lab):
    deadline = time.monotonic() + 90
    last_state = None
    while time.monotonic() < deadline:
        cluster = _get_json(lab, OPERATOR_NS, "get", "raycluster", RAYCLUSTER)
        status = cluster.get("status", {})
        last_state = status.get("state")
        if _suspension_observed(status):
            return cluster
        time.sleep(3)
    lab.block(f"KubeRay did not report suspended state for the watched fixture; state={last_state}")


def run_kuberay_supplement(lab):
    """Run the KubeRay supplement inside an already-created reviewed lab cluster."""
    chart_hash, crds, namespaced = _render_and_partition(lab)
    lab.check(
        "kuberay_render",
        "Official KubeRay 1.8.0 chart renders only the reviewed namespace-scoped objects and one digest-pinned controller image",
        chart_hash == CHART_SHA256 and len(crds) == 4 and len(namespaced) == 7,
        {"chart_sha256": chart_hash, "operator_image": OPERATOR_IMAGE,
         "cluster_scoped_objects": ["Ray CRDs only"],
         "namespace_scoped_object_count": len(namespaced)},
    )

    # KubeRay's four CRDs are cluster-scoped chart prerequisites. Install and establish
    # those before applying any namespaced chart resources or RayCluster custom resources.
    manifest_path = lab.kubeconfig.parent / "kuberay-crds.yaml"
    manifest_path.write_text("\n---\n".join(crds) + "\n")
    _kubectl(lab, OPERATOR_NS, "apply", "--server-side", "--field-manager=saf-kuberay-fixture",
             "-f", str(manifest_path), timeout=120)
    _kubectl(lab, OPERATOR_NS, "wait", "--for=condition=Established",
             *(f"crd/{name}" for name in CRD_NAMES), "--timeout=120s", timeout=130)
    _kubectl(lab, OPERATOR_NS, "apply", "-f", "-",
             payload="\n---\n".join(namespaced), timeout=120)
    _kubectl(lab, OPERATOR_NS, "rollout", "status", "deployment/kuberay-operator",
             "--timeout=120s", timeout=130)

    deployment = _get_json(lab, OPERATOR_NS, "get", "deployment", "kuberay-operator")
    pod_spec = deployment.get("spec", {}).get("template", {}).get("spec", {})
    images = [container.get("image") for container in pod_spec.get("containers", [])]
    args = [str(arg) for arg in pod_spec.get("containers", [{}])[0].get("args", [])]
    watched_args = any(args[i] == "--watch-namespace" and
                       i + 1 < len(args) and args[i + 1] == OPERATOR_NS
                       for i in range(len(args)))
    service_account_ok = pod_spec.get("serviceAccountName") == OPERATOR_SA
    deployment_ok = images == [OPERATOR_IMAGE] and watched_args and service_account_ok
    lab.check(
        "kuberay_controller",
        "The actual KubeRay Deployment uses its dedicated ServiceAccount and watches only its operator namespace",
        deployment_ok,
        {"deployment": "kuberay-operator", "service_account": pod_spec.get("serviceAccountName"),
         "image": images, "watch_namespace_is_operator_namespace": watched_args},
    )

    # Create one suspended object in the watched namespace and a comparison object in
    # an adjacent namespace. Neither object can start a Ray pod or execute user code.
    _kubectl(lab, OPERATOR_NS, "apply", "-f", "-",
             payload=json.dumps(_raycluster(RAYCLUSTER, OPERATOR_NS)))
    _kubectl(lab, ADJACENT_NS, "apply", "-f", "-",
             payload=json.dumps(_raycluster(ADJACENT_RAYCLUSTER, ADJACENT_NS)))
    watched = _wait_suspended(lab)

    authz = _authorization_matrix(lab)
    direct = _run_probe(lab)
    direct_expected = {
        "identity": direct["identity"].get("subject") == EXPECTED_SUBJECT,
        "list_watched_namespace": direct["list_watched_namespace"].get("status") == 200
            and direct["list_watched_namespace"].get("contains_case_owned_cluster") is True,
        "list_adjacent_namespace": direct["list_adjacent_namespace"].get("status") == 403,
        "get_watched_cluster": direct["get_watched_cluster"].get("status") == 200,
        "get_adjacent_cluster": direct["get_adjacent_cluster"].get("status") == 403,
        "patch_watched_status": direct["patch_watched_status"].get("status") == 200,
        "patch_adjacent_status": direct["patch_adjacent_status"].get("status") == 403,
        "list_nodes": direct["list_nodes"].get("status") == 403,
    }
    expected_authz = {
        "list_watched_namespace": True, "list_adjacent_namespace": False,
        "get_watched_cluster": True, "get_adjacent_cluster": False,
        "patch_watched_status": True, "patch_adjacent_status": False,
        "list_nodes": False,
    }
    role = _get_json(lab, OPERATOR_NS, "get", "role", "kuberay-operator")
    binding = _get_json(lab, OPERATOR_NS, "get", "rolebinding", "kuberay-operator")
    rule_resources = sorted({resource for rule in role.get("rules", [])
                             for resource in rule.get("resources", [])})
    ray_rule = any(
        "ray.io" in rule.get("apiGroups", [])
        and "rayclusters" in rule.get("resources", [])
        and {"get", "list", "patch"}.issubset(set(rule.get("verbs", [])))
        for rule in role.get("rules", []))
    ray_status_patch = any(
        "ray.io" in rule.get("apiGroups", [])
        and "rayclusters/status" in rule.get("resources", [])
        and "patch" in rule.get("verbs", [])
        for rule in role.get("rules", []))
    binding_ok = (
        binding.get("roleRef", {}).get("kind") == "Role"
        and binding.get("roleRef", {}).get("name") == "kuberay-operator"
        and binding.get("subjects", []) == [{"kind": "ServiceAccount", "name": OPERATOR_SA,
                                             "namespace": OPERATOR_NS}]
        and ray_rule and ray_status_patch and "nodes" not in rule_resources
    )
    if not binding_ok:
        lab.block("Installed KubeRay RoleBinding or relevant permission envelope differed from the reviewed chart")
    direct_ok = all(direct_expected.values())
    rbac_ok = authz == expected_authz and direct_ok and binding_ok
    lab.check(
        "kuberay_rbac",
        "The actual KubeRay ServiceAccount can get RayClusters and patch status only within its namespace, and is denied across namespace and node boundaries",
        rbac_ok,
        {"kubectl_auth_can_i": authz,
         "projected_service_account_probe": {
             name: {key: item.get(key) for key in ("subject", "status", "contains_case_owned_cluster")}
             for name, item in direct.items()},
         "direct_operations_match_expected": direct_expected,
         "role_binding_is_dedicated_namespaced_role": binding_ok,
         "role_resource_names": rule_resources,
         "vendor_default_role_has_namespaced_secret_permissions": "secrets" in rule_resources,
         "scope_note": "The vendor default Role is broad within its namespace; this tests namespace isolation, not global least privilege.",
         "adjacent_namespace": ADJACENT_NS},
    )

    # Give an out-of-scope object a quiet window to reveal accidental broad watching.
    time.sleep(8)
    adjacent = _get_json(lab, ADJACENT_NS, "get", "raycluster", ADJACENT_RAYCLUSTER)
    adjacent_status = adjacent.get("status", {})
    adjacent_unreconciled = not adjacent_status
    watched_uid = watched["metadata"]["uid"]
    adjacent_uid = adjacent["metadata"]["uid"]
    def owned(resources, uid):
        return [item for item in resources if any(ref.get("kind") == "RayCluster" and ref.get("uid") == uid
                                                 for ref in item["metadata"].get("ownerReferences", []))]
    in_scope = _get_json(lab, OPERATOR_NS, "get", "pods,services")["items"]
    outside = _get_json(lab, ADJACENT_NS, "get", "pods,services")["items"]
    watched_resources = owned(in_scope, watched_uid)
    owned_pods = [item["metadata"]["name"] for item in watched_resources if item["kind"] == "Pod"]
    owned_services = [item for item in watched_resources if item["kind"] == "Service"]
    internal_service = (len(owned_services) == 1
                        and owned_services[0]["metadata"]["name"] == RAYCLUSTER + "-head-svc"
                        and owned_services[0]["spec"].get("type") == "ClusterIP")
    outside_resources = owned(outside, adjacent_uid)
    reconcile_ok = (_suspension_observed(watched.get("status", {})) and adjacent_unreconciled
                    and not owned_pods and internal_service and not outside_resources)
    (lab.evidence / "kuberay-namespace-observations.json").write_text(json.dumps({
        "watched_raycluster_uid": watched_uid, "adjacent_raycluster_uid": adjacent_uid,
        "watched_status": watched.get("status", {}), "adjacent_status_present": bool(adjacent_status),
        "watched_service_uid": owned_services[0]["metadata"]["uid"] if internal_service else None,
        "watched_service_is_clusterip": internal_service,
        "ray_owned_pod_count": len(owned_pods), "adjacent_owned_resource_count": len(outside_resources),
    }, indent=2) + "\n")
    lab.check(
        "kuberay_watch_scope",
        "KubeRay reconciles only the watched suspended RayCluster, creates its owned internal Service, and launches no Ray Pod",
        reconcile_ok,
        {"watched_raycluster_state": watched.get("status", {}).get("state"),
         "adjacent_raycluster_has_no_status": adjacent_unreconciled,
         "raycluster_owned_pods": owned_pods,
         "watched_raycluster_has_exact_owned_clusterip_service": internal_service,
         "adjacent_raycluster_owned_resources_absent": not outside_resources,
         "raycluster_names": [RAYCLUSTER, ADJACENT_RAYCLUSTER]},
    )
