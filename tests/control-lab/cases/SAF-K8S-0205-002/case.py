"""Verify separate native admission decisions for host ports and node-address Services."""

import json
import time

from fixtures import container, pod

SCOPE = "Test real Pod Security Admission and Service ValidatingAdmissionPolicy on inert server-side dry-runs."
POLICY = "restrict-node-address-services"
SERVICE_MESSAGE = "NodePort or LoadBalancer node-port allocation is forbidden"
APPROVED = "fixture-port-exception"
GOVERNED = "saf-test"


def service(name, kind, *, allocated=None, namespace=GOVERNED):
    spec = {"type": kind, "ports": [{"port": 8080, "targetPort": 8080}]}
    if allocated is not None:
        spec["allocateLoadBalancerNodePorts"] = allocated
    return {"apiVersion": "v1", "kind": "Service",
            "metadata": {"name": name, "namespace": namespace}, "spec": spec}


def check_create(lab, obj):
    namespace = obj["metadata"]["namespace"]
    return lab.kubectl("create", "-f", "-", "-o", "json", "--dry-run=server",
                       f"--namespace={namespace}", payload=json.dumps(obj), allow_failure=True)


def pod_with_port(name, *, namespace=GOVERNED, init=False, port=18080):
    selected = container("owned-marker", ports=[{"containerPort": 8080, "hostPort": port}])
    resource = pod(name, [container("worker")] if init else [selected],
                   automountServiceAccountToken=False, **({"initContainers": [selected]} if init else {}))
    resource["metadata"]["namespace"] = namespace
    return resource


def stopped_by(result, message):
    return result.returncode != 0 and message in result.stderr


def install_service_policy(lab):
    lab.create({
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY}, "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                "operations": ["CREATE", "UPDATE"], "resources": ["services"]}]},
            "validations": [{
                "expression": "object.spec.type != 'NodePort' && (object.spec.type != 'LoadBalancer' || "
                              "(has(object.spec.allocateLoadBalancerNodePorts) && "
                              "!object.spec.allocateLoadBalancerNodePorts && "
                              "object.spec.ports.all(p, !has(p.nodePort) || p.nodePort == 0)))",
                "message": SERVICE_MESSAGE,
            }],
        }})
    lab.create({
        "apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": POLICY}, "spec": {"policyName": POLICY, "validationActions": ["Deny"],
            "matchResources": {"namespaceSelector": {"matchLabels": {
                "kubernetes.io/metadata.name": GOVERNED,
            }}}},
    })


def run(lab):
    lab.kubectl("label", "namespace", GOVERNED, "pod-security.kubernetes.io/enforce=baseline")
    lab.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": APPROVED,
                "labels": {"pod-security.kubernetes.io/enforce": "privileged"}}})
    node_port = service("fixture-node-port", "NodePort")
    before = check_create(lab, node_port)
    ordinary = check_create(lab, pod_with_port("fixture-pod-port"))
    init = check_create(lab, pod_with_port("fixture-init-port", init=True))
    scope = {"node_port_admitted": before.returncode == 0, "pod_port_denied": stopped_by(ordinary, "hostPort"),
             "init_port_denied": stopped_by(init, "hostPort")}
    lab.check("red", "Baseline Pod Security rejects regular and init HostPort while admitting a NodePort Service",
              all(scope.values()), scope)

    lab.create(service("fixture-updatable", "ClusterIP"))
    install_service_policy(lab)
    deadline = time.monotonic() + 24
    denied = check_create(lab, node_port)
    while not stopped_by(denied, SERVICE_MESSAGE) and time.monotonic() < deadline:
        time.sleep(0.5)
        denied = check_create(lab, node_port)
    default_lb = check_create(lab, service("fixture-default-lb", "LoadBalancer"))
    update = lab.kubectl("patch", "service", "fixture-updatable", "--type=merge",
                         "-p", '{"spec":{"type":"NodePort"}}', "--dry-run=server", allow_failure=True)
    denied_ports = {"node_port_create_denied": stopped_by(denied, SERVICE_MESSAGE),
                    "node_port_update_denied": stopped_by(update, SERVICE_MESSAGE),
                    "default_load_balancer_denied": stopped_by(default_lb, SERVICE_MESSAGE)}
    lab.check("green", "The scoped Service policy denies NodePort creation and update and default LoadBalancer allocation",
              all(denied_ports.values()), denied_ports)

    approved = {
        "cluster_ip_admitted": check_create(lab, service("fixture-allowed-cluster", "ClusterIP")).returncode == 0,
        "no_allocation_lb_admitted": check_create(lab, service("fixture-allowed-lb", "LoadBalancer", allocated=False)).returncode == 0,
        "no_host_port_admitted": check_create(lab, pod_with_port("fixture-allowed-pod", port=0)).returncode == 0,
        "excepted_node_port_admitted": check_create(lab, service("fixture-allowed-exception", "NodePort", namespace=APPROVED)).returncode == 0,
        "excepted_host_port_admitted": check_create(lab, pod_with_port("fixture-allowed-exception", namespace=APPROVED)).returncode == 0,
    }
    lab.check("positive", "Approved internal Services, no-allocation declarations and isolated exceptions remain admissible",
              all(approved.values()), approved)
    (lab.evidence / "port-admission-observations.json").write_text(
        json.dumps({"pod_security_only": scope, "service_policy": denied_ports, "approved": approved}, indent=2) + "\n"
    )
