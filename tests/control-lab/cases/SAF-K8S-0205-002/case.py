"""Check separate port admission, scoped exceptions and owned IPv4 reachability."""

from ipaddress import IPv4Address
import json
import time

SCOPE = "Kind IPv4 marker traffic and separate Pod and Service admission on self-owned resources."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
POD_RULE = "restrict-fixture-host-ports"
SERVICE_RULE = "restrict-fixture-node-ports"
HOST_DENY = "HostPort requires an exact fixture approval"
SERVICE_DENY = "NodePort or LoadBalancer node-port allocation requires fixture approval"
APPROVED = "fixture-port-exception"
GOVERNED = "saf-test"
APPROVAL_LABEL = "fixture.example/port-approval"
OWNER = "fixture-port-owner"
MEMBER = "fixture-port-member"
BACKEND = "owned-marker-backend"
HOST_POD = "approved-host-listener"
NODE_SERVICE = "approved-node-service"
INTERNAL = "owned-internal-service"
CLIENT = "owned-marker-client"
HOST_PORT = 18080
NODE_PORT = 31080
TARGET_PORT = 8080
SERVICE_PORT = 8081
MARKER = "owned-port-marker"
NO_MARKER = "no-marker"

SERVER = """
import socketserver
class Marker(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b'owned-port-marker')
socketserver.TCPServer(('0.0.0.0', 8080), Marker).serve_forever()
"""
PROBE = """
import errno, socket, sys
try:
    with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=1.2) as peer:
        print(peer.recv(128).decode())
except (ConnectionRefusedError, ConnectionResetError, TimeoutError):
    print('no-marker')
except OSError as error:
    if error.errno not in (errno.EHOSTUNREACH, errno.ENETUNREACH):
        raise
    print('no-marker')
"""


def namespaced(kind, name, namespace, api="v1", **fields):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name, "namespace": namespace}, **fields}


def marker_pod(name, node, port=0, *, namespace=APPROVED, is_client=False, init=False):
    listener = {"name": "marker", "image": IMAGE,
                "command": ["python", "-c", SERVER if not is_client else "import time; time.sleep(600)"],
                "resources": {"requests": {"cpu": "5m", "memory": "16Mi"}, "limits": {"memory": "64Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}}}
    if not is_client:
        listener["readinessProbe"] = {"tcpSocket": {"port": TARGET_PORT}, "periodSeconds": 1}
    if port:
        listener["ports"] = [{"containerPort": TARGET_PORT, "hostPort": port}]
    spec = {"nodeName": node, "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [listener]}
    if init:
        initializer = dict(listener, name="initializer", command=["python", "-c", "pass"])
        del initializer["readinessProbe"]
        spec["initContainers"] = [initializer]
        listener.pop("ports", None)
    pod = namespaced("Pod", name, namespace, spec=spec)
    if name == BACKEND:
        pod["metadata"]["labels"] = {"fixture.example/service-backend": "selected"}
    return pod


def service(name, kind, *, namespace=APPROVED, node_port=0, allocate=None):
    port = {"port": SERVICE_PORT, "targetPort": TARGET_PORT}
    if node_port:
        port["nodePort"] = node_port
    spec = {"type": kind, "selector": {"fixture.example/service-backend": "selected"}, "ports": [port]}
    if allocate is not None:
        spec["allocateLoadBalancerNodePorts"] = allocate
    return namespaced("Service", name, namespace, spec=spec)


def submit(lab, obj, *, actor=None, dry=False):
    extra = []
    if actor:
        extra.append(f"--as={actor}")
    if dry:
        extra.append("--dry-run=server")
    return lab.kubectl("create", "-f", "-", "-o", "json", "-n", obj["metadata"]["namespace"], *extra,
                       payload=json.dumps(obj), allow_failure=True)


def create(lab, obj):
    result = submit(lab, obj)
    if result.returncode != 0:
        lab.block("Fixture resource could not be created: " + result.stderr.strip())
    return json.loads(result.stdout)


def denied(result, reason):
    return result.returncode != 0 and reason in result.stderr


def install_rules(lab):
    identity = f"request.userInfo.username == '{OWNER}' && request.namespace == '{APPROVED}'"
    label = (f"has(namespaceObject.metadata.labels) && '{APPROVAL_LABEL}' in namespaceObject.metadata.labels "
             f"&& namespaceObject.metadata.labels['{APPROVAL_LABEL}'] == 'active'")
    approval = f"{identity} && {label}"
    no_host = "cs.all(c, !has(c.ports) || c.ports.all(p, !has(p.hostPort) || p.hostPort == 0))"
    exact_host = no_host.replace("p.hostPort == 0", f"(p.hostPort == 0 || (p.hostPort == {HOST_PORT} "
                                 f"&& p.containerPort == {TARGET_PORT} && p.protocol == 'TCP'))")
    regular = no_host.replace("cs.", "object.spec.containers.")
    exact = exact_host.replace("cs.", "object.spec.containers.")
    init = no_host.replace("cs.", "object.spec.initContainers.")
    pod_expression = (f"(!has(object.spec.initContainers) || {init}) && ({regular} || "
                      f"({approval} && object.metadata.name == '{HOST_POD}' && {exact}))")
    no_ports = "(object.spec.ports.all(p, !has(p.nodePort) || p.nodePort == 0))"
    service_expression = (
        "(object.spec.type != 'NodePort' && (object.spec.type != 'LoadBalancer' || "
        f"(has(object.spec.allocateLoadBalancerNodePorts) && !object.spec.allocateLoadBalancerNodePorts && {no_ports}))) "
        f"|| ({approval} && object.metadata.name == '{NODE_SERVICE}' && object.spec.type == 'NodePort' "
        f"&& object.spec.ports.size() == 1 && object.spec.ports[0].nodePort == {NODE_PORT} "
        f"&& object.spec.ports[0].port == {SERVICE_PORT} && object.spec.ports[0].protocol == 'TCP')"
    )
    api = "admissionregistration.k8s.io/v1"
    for name, resource, expression, message in (
        (POD_RULE, "pods", pod_expression, HOST_DENY),
        (SERVICE_RULE, "services", service_expression, SERVICE_DENY),
    ):
        lab.create({
            "apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": name},
            "spec": {"failurePolicy": "Fail", "matchConstraints": {"resourceRules": [{
                "apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"],
                "resources": [resource],
            }]}, "validations": [{"expression": expression, "message": message}]},
        })
        lab.create({
            "apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": name},
            "spec": {"policyName": name, "validationActions": ["Deny"], "matchResources": {
                "namespaceSelector": {"matchExpressions": [{"key": "kubernetes.io/metadata.name",
                    "operator": "In", "values": [GOVERNED, APPROVED]}]},
            }},
        })


def ready(lab, pod, namespace):
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", "pod/" + pod,
                "--timeout=80s", timeout=90)


def reachability(lab, paths, expected):
    deadline = time.monotonic() + 25
    while True:
        observed = {}
        for name, (address, port) in paths.items():
            observed[name] = lab.kubectl("exec", "pod/" + CLIENT, "--", "python", "-c", PROBE,
                                         address, str(port), timeout=9).stdout.strip()
        if observed == expected or time.monotonic() > deadline:
            return observed


def require_active_policy(lab, generic_service, generic_pod):
    deadline = time.monotonic() + 27
    while time.monotonic() < deadline:
        if (denied(submit(lab, generic_service, dry=True), SERVICE_DENY)
                and denied(submit(lab, generic_pod, dry=True), HOST_DENY)):
            return
        time.sleep(0.35)
    lab.block("The fixture admission rules did not return both expected policy denials")


def remove_exposures(lab):
    lab.kubectl("-n", APPROVED, "delete", "service/" + NODE_SERVICE, "pod/" + HOST_POD,
                "--wait=true", "--timeout=40s", timeout=50)


def run(lab):
    server = lab.cluster + "-worker"
    sender = lab.cluster + "-control-plane"
    nodes = set(lab.command("kind", "get", "nodes", "--name", lab.cluster).stdout.splitlines())
    if nodes != {server, sender}:
        lab.block("Expected an owned two-node Kind profile")
    lab.kubectl("label", "namespace", GOVERNED, "pod-security.kubernetes.io/enforce=baseline",
                "pod-security.kubernetes.io/enforce-version=v1.36")
    lab.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": APPROVED, "labels": {
        "pod-security.kubernetes.io/enforce": "privileged", APPROVAL_LABEL: "active",
    }}})
    rbac = "rbac.authorization.k8s.io/v1"
    create(lab, namespaced("Role", "fixture-port-create", APPROVED, rbac,
                          rules=[{"apiGroups": [""], "resources": ["pods", "services"], "verbs": ["create"]}]))
    create(lab, namespaced("RoleBinding", "fixture-port-creators", APPROVED, rbac,
                          subjects=[{"kind": "User", "name": user, "apiGroup": "rbac.authorization.k8s.io"}
                                    for user in (OWNER, MEMBER)],
                          roleRef={"kind": "Role", "name": "fixture-port-create",
                                   "apiGroup": "rbac.authorization.k8s.io"}))
    host = marker_pod(HOST_POD, server, HOST_PORT)
    node = service(NODE_SERVICE, "NodePort", node_port=NODE_PORT)
    sample_node = service("unapproved-node-service", "NodePort", namespace=GOVERNED)
    sample_host = marker_pod("unapproved-host-listener", server, HOST_PORT)
    explicit_lb = service("fixture-explicit-lb", "LoadBalancer", namespace=GOVERNED,
                          allocate=False, node_port=NODE_PORT)
    green_lb = service("fixture-direct-lb", "LoadBalancer", namespace=GOVERNED, allocate=False)
    before = {"baseline_ordinary": denied(submit(lab, marker_pod(
                  "regular", server, HOST_PORT, namespace=GOVERNED), dry=True), "hostPort"),
              "baseline_init": denied(submit(lab, marker_pod(
                  "init", server, HOST_PORT, init=True, namespace=GOVERNED), dry=True), "hostPort"),
              "nodeport_accepted_without_service_rule": submit(lab, sample_node, dry=True).returncode == 0,
              "explicit_load_balancer_port_accepted_before_rule": submit(lab, explicit_lb, dry=True).returncode == 0}
    lab.check("red", "Baseline PSA denies regular and init HostPort while Services still admit node port declarations",
              all(before.values()), before)

    create(lab, marker_pod(BACKEND, server))
    create(lab, marker_pod(CLIENT, sender, namespace=GOVERNED, is_client=True))
    internal = create(lab, service(INTERNAL, "ClusterIP"))
    create(lab, service("fixture-updatable", "ClusterIP", namespace=GOVERNED))
    for obj in (host, node):
        create(lab, obj)
    for name, ns in ((BACKEND, APPROVED), (HOST_POD, APPROVED), (CLIENT, GOVERNED)):
        ready(lab, name, ns)
    node_info = json.loads(lab.kubectl("get", "node", server, "-o", "json").stdout)
    node_ip, = [str(IPv4Address(a["address"])) for a in node_info["status"]["addresses"]
                if a["type"] == "InternalIP"]
    paths = {"node_port": (node_ip, NODE_PORT), "host_port": (node_ip, HOST_PORT),
             "internal": (str(IPv4Address(internal["spec"]["clusterIP"])), SERVICE_PORT)}
    permitted = dict.fromkeys(paths, MARKER)
    closed = {"node_port": NO_MARKER, "host_port": NO_MARKER, "internal": MARKER}
    red = reachability(lab, paths, permitted)
    lab.check("red", "The owned client receives the marker over both node paths and the internal Service",
              red == permitted, red)

    remove_exposures(lab)
    install_rules(lab)
    require_active_policy(lab, sample_node, sample_host)
    update = lab.kubectl("patch", "service", "fixture-updatable", "--type=merge",
                         "-p", '{"spec":{"type":"NodePort"}}', "--dry-run=server", allow_failure=True)
    service_checks = {
        "node_port_create_denied": denied(submit(lab, sample_node, dry=True), SERVICE_DENY),
        "node_port_update_denied": denied(update, SERVICE_DENY),
        "default_lb_denied": denied(submit(lab, service("fixture-default-lb", "LoadBalancer",
                                                        namespace=GOVERNED), dry=True), SERVICE_DENY),
        "explicit_load_balancer_port_denied": denied(submit(lab, explicit_lb, dry=True), SERVICE_DENY),
        "no_allocation_lb_admitted": submit(lab, green_lb, dry=True).returncode == 0,
        "cluster_ip_admitted": submit(lab, service("fixture-local-only", "ClusterIP",
                                                   namespace=GOVERNED), dry=True).returncode == 0,
    }
    lab.check("green", "The Service rule denies node port creation and updates while allowing the internal declarations",
              all(service_checks.values()), service_checks)
    boundary = {
        "member_host_denied": denied(submit(lab, host, actor=MEMBER, dry=True), HOST_DENY),
        "member_node_port_denied": denied(submit(lab, node, actor=MEMBER, dry=True), SERVICE_DENY),
        "different_host_pod_denied": denied(submit(lab, sample_host, actor=OWNER, dry=True), HOST_DENY),
        "wrong_host_port_denied": denied(submit(lab, marker_pod(HOST_POD, server, HOST_PORT + 1),
                                                actor=OWNER, dry=True), HOST_DENY),
        "wrong_node_port_denied": denied(submit(lab, service(NODE_SERVICE, "NodePort", node_port=NODE_PORT + 1),
                                                actor=OWNER, dry=True), SERVICE_DENY),
        "unapproved_init_denied": denied(submit(lab, marker_pod(HOST_POD, server, HOST_PORT, init=True),
                                                actor=OWNER, dry=True), HOST_DENY),
        "no_host_port_admitted": submit(lab, marker_pod("fixture-unexposed", server),
                                         actor=MEMBER, dry=True).returncode == 0,
    }
    rejected_paths = reachability(lab, paths, closed)
    lab.check("green", "Wrong identities, resource names and ports are denied and node markers cease after cleanup",
              all(boundary.values()) and rejected_paths == closed, {"admission": boundary, "paths": rejected_paths})

    host_created, node_created = [submit(lab, obj, actor=OWNER) for obj in (host, node)]
    accepted = {"host_effectively_created": host_created.returncode == 0,
                "node_port_effectively_created": node_created.returncode == 0}
    lab.check("positive", "The approved identity creates the exact two exceptions", all(accepted.values()), accepted)
    ready(lab, HOST_POD, APPROVED)
    live = reachability(lab, paths, permitted)
    lab.check("positive", "The approved exceptions return the marker without breaking internal connectivity",
              live == permitted, live)

    lab.kubectl("label", "namespace", APPROVED, APPROVAL_LABEL + "-")
    still_live = reachability(lab, paths, permitted)
    remove_exposures(lab)
    deadline = time.monotonic() + 24
    while True:
        revoked = {"host_recreation_denied": denied(submit(lab, host, actor=OWNER, dry=True), HOST_DENY),
                   "node_port_recreation_denied": denied(submit(lab, node, actor=OWNER, dry=True), SERVICE_DENY)}
        if all(revoked.values()) or time.monotonic() > deadline:
            break
        time.sleep(0.4)
    after = reachability(lab, paths, closed)
    lab.check("positive", "Revoking approval denies recreation after cleanup and preserves the internal Service",
              all(revoked.values()) and still_live == permitted and after == closed,
              {"admission": revoked, "before_cleanup": still_live, "after_cleanup": after})
    policies = [json.loads(lab.kubectl("get", "validatingadmissionpolicy", name, "-o", "json").stdout)["spec"]
                for name in (POD_RULE, SERVICE_RULE)]
    evidence = {"owned_source": json.loads(lab.kubectl("get", "pod", CLIENT, "-o", "json").stdout)["status"]["podIP"],
                "profile": {"ipv4": True, "node_version": node_info["status"]["nodeInfo"],
                            "approved_actor": OWNER, "comparison_actor": MEMBER, "namespace": APPROVED},
                "paths": paths, "effective_validation_policies": policies, "baseline": before,
                "service_admission": service_checks, "exception_boundary": boundary,
                "port_markers": {"without_policy": red, "unapproved_paths": rejected_paths, "active_exception": live,
                                 "after_revocation_before_cleanup": still_live, "after_cleanup": after},
                "revoked": revoked}
    (lab.evidence / "port-admission-observations.json").write_text(json.dumps(evidence, indent=2) + "\n")
