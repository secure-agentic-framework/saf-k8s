"""Enforce fixture external-service approval and egress on separate boundaries."""

import json
import time

SCOPE = "Two local endpoint markers, Pod approval checks and CNI-enforced fixture egress."
IMAGE = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
STANDARD = "saf-external-standard"
RESTRICTED = "saf-external-restricted"
SERVICES = "saf-external-endpoints"
LABEL = "saf.example/service"
POLICY = "saf-external-fixture-approval"
PORT = 18080


def pod(name, access, *, marker=None):
    command = "exec sleep 240" if marker is None else f"printf '%s' '{marker}' >/tmp/index.html; exec httpd -f -p {PORT} -h /tmp"
    ready = {} if marker is None else {"readinessProbe": {"httpGet": {"path": "/", "port": PORT}, "periodSeconds": 1}}
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {LABEL: access}}, "spec": {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "fixture", "image": IMAGE, "command": ["/bin/sh", "-ec", command], **ready,
                        "resources": {"requests": {"cpu": "5m", "memory": "4Mi"}, "limits": {"cpu": "100m", "memory": "24Mi"}},
                        "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}}]}}


def create(lab, namespace, manifest, *, dry=False):
    flags = ("--dry-run=server",) if dry else ()
    return lab.kubectl("-n", namespace, "create", "-f", "-", *flags, payload=json.dumps(manifest), allow_failure=dry)


def add_pod(lab, namespace, name, access, marker=None):
    create(lab, namespace, pod(name, access, marker=marker))
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{name}", "--timeout=65s", timeout=75)
    result = lab.kubectl("-n", namespace, "get", "pod", name, "-o", "json")
    return json.loads(result.stdout)["status"]["podIP"]


def request(lab, namespace, target, marker):
    reply = lab.kubectl("-n", namespace, "exec", "fixture-client", "--", "wget", "-T", "2", "-O-", f"http://{target}:{PORT}/",
                        timeout=12, allow_failure=True)
    if reply.returncode == 0:
        if reply.stdout.strip() != marker:
            lab.block("The endpoint returned the wrong fixture marker")
        return True
    if "timed out" in reply.stderr.lower():
        return False
    lab.block("Unexpected fixture request failure")


def approval_policy(lab):
    expression = (f"has(object.metadata.labels) && '{LABEL}' in object.metadata.labels && "
                  f"((request.namespace == '{STANDARD}' && object.metadata.labels['{LABEL}'] == 'approved') || "
                  f"(request.namespace == '{RESTRICTED}' && object.metadata.labels['{LABEL}'] == 'none'))")
    namespace_selector = {"matchExpressions": [{"key": "kubernetes.io/metadata.name", "operator": "In", "values": [STANDARD, RESTRICTED]}]}
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail", "matchConstraints": {"resourceRules": [{
                    "operations": ["CREATE", "UPDATE"], "apiGroups": [""], "apiVersions": ["v1"], "resources": ["pods"], "scope": "Namespaced"}]},
                    "validations": [{"expression": expression, "message": "fixture approval does not cover this namespace and service"}]}})
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"], "matchResources": {"namespaceSelector": namespace_selector}}})


def egress(lab, namespace, name, allow):
    rules = []
    if allow:
        peer = {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": SERVICES}},
                "podSelector": {"matchLabels": {LABEL: "approved"}}}
        rules = [{"to": [peer], "ports": [{"protocol": "TCP", "port": PORT}]}]
    create(lab, namespace, {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": name},
                            "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": rules}})


def converge(lab, check, diagnostic):
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(1)
    lab.block(diagnostic)


def declined(result):
    return result.returncode != 0 and POLICY in result.stderr and "fixture approval does not cover" in result.stderr


def run(lab):
    for namespace in (STANDARD, RESTRICTED, SERVICES):
        lab.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace,
                    "labels": {"pod-security.kubernetes.io/enforce": "restricted"}}})
    selected = add_pod(lab, SERVICES, "approved-service", "approved", "approved-public-marker")
    other = add_pod(lab, SERVICES, "comparison-service", "comparison", "comparison-public-marker")
    add_pod(lab, STANDARD, "fixture-client", "approved")
    add_pod(lab, RESTRICTED, "fixture-client", "none")
    approved_path = lambda namespace: request(lab, namespace, selected, "approved-public-marker")
    other_path = lambda namespace: request(lab, namespace, other, "comparison-public-marker")
    converge(lab, lambda: all(check(namespace) for namespace in (STANDARD, RESTRICTED) for check in (approved_path, other_path)),
             "Both markers must be reachable before egress policy")
    before = create(lab, STANDARD, pod("request-comparison", "comparison"), dry=True)
    lab.check("red", "Before enforcement the owned comparison is reachable and its declaration is admitted",
              before.returncode == 0, {"comparison_reachable_and_request_admitted": before.returncode == 0})
    approval_policy(lab)
    converge(lab, lambda: declined(create(lab, STANDARD, pod("request-comparison", "comparison"), dry=True)),
             "The admission binding did not deny the unapproved service declaration")
    restricted = create(lab, RESTRICTED, pod("request-restricted", "approved"), dry=True)
    valid = create(lab, STANDARD, pod("request-approved", "approved"), dry=True)
    lab.check("green", "Admission distinguishes approved standard use from a request in the restricted fixture namespace",
              declined(restricted) and valid.returncode == 0,
              {"restricted_service_request_refused": declined(restricted), "positively_approved_request_admitted": valid.returncode == 0})
    egress(lab, STANDARD, "approved-service-only", True)
    egress(lab, RESTRICTED, "no-service-egress", False)
    converge(lab, lambda: not other_path(STANDARD) and not approved_path(RESTRICTED) and not other_path(RESTRICTED) and approved_path(STANDARD),
             "The CNI did not enforce one approved and three denied marker paths")
    lab.check("positive", "The approved marker remains reachable while separate CNI egress policy denies the other fixture paths",
              True, {"approved_marker_reached": True, "comparison_paths_denied": True})
    (lab.evidence / "external-service-observations.json").write_text(json.dumps({
        "fixture_endpoint_count": 2, "admission_approved": True, "admission_restricted_denial": True,
        "approved_marker_verified": True, "other_and_restricted_egress_denied": True,
    }, indent=2) + "\n")
