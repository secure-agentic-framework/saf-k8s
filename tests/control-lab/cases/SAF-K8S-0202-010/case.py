"""Exercise kubelet seccompDefault on one disposable Kind node."""

import json
import re
import time


SCOPE = (
    "Linux workloads on the worker node in a two-node, "
    "digest-pinned Kind Kubernetes v1.36.1 cluster; containerd RuntimeDefault. "
    "It changes the disposable worker kubelet and applies one scoped admission policy."
)

NODE_CONFIG = "/var/lib/kubelet/config.yaml"
IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)


def _set_seccomp_default(lab, value):
    """Change this Kind node's kubelet config and restart its kubelet."""
    node_container = f"{lab.cluster}-worker"
    script = "\n".join(
        (
            "set -eu",
            f"config={NODE_CONFIG}",
            'test -f "$config"',
            'if grep -q "^seccompDefault:" "$config"; then',
            f"  sed -i 's/^seccompDefault:.*/seccompDefault: {value}/' \"$config\"",
            "else",
            f"  printf '\\nseccompDefault: {value}\\n' >> \"$config\"",
            "fi",
            f"grep -q '^seccompDefault: {value}$' \"$config\"",
            "systemctl restart kubelet",
            f"grep '^seccompDefault: {value}$' \"$config\"",
        )
    )
    lab.command("docker", "exec", node_container, "sh", "-ec", script, timeout=90)
    lab.kubectl("wait", "--for=condition=Ready", f"node/{node_container}",
                 "--timeout=90s", timeout=100)


def _pod(name, *, explicit_runtime_default=False):
    container = {
        "name": "probe",
        "image": IMAGE,
        "command": ["sh", "-c", "sleep 3600"],
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
            "runAsNonRoot": True,
            "runAsUser": 65534,
        },
        "resources": {
            "requests": {"cpu": "10m", "memory": "16Mi"},
            "limits": {"cpu": "100m", "memory": "32Mi"},
        },
    }
    spec = {
        "restartPolicy": "Never",
        "automountServiceAccountToken": False,
        "activeDeadlineSeconds": 240,
        "containers": [container],
    }
    if explicit_runtime_default:
        spec["securityContext"] = {"seccompProfile": {"type": "RuntimeDefault"}}
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name},
        "spec": spec,
    }


def _wait_for_pod(lab, name, node_name):
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}",
                 "--timeout=95s", timeout=105)
    pod = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
    scheduled_here = pod.get("spec", {}).get("nodeName") == node_name
    running = pod.get("status", {}).get("phase") == "Running"
    if not scheduled_here or not running:
        lab.block(
            f"Probe pod did not run on the reviewed node: "
            f"node={pod.get('spec', {}).get('nodeName')!r}, "
            f"phase={pod.get('status', {}).get('phase')!r}"
        )
    return pod


def _seccomp_mode(lab, name):
    output = lab.kubectl(
        "exec", name, "--", "sh", "-c", "grep '^Seccomp:' /proc/self/status"
    ).stdout
    match = re.search(r"(?m)^Seccomp:\s*(\d+)\s*$", output)
    if match is None:
        lab.block("Probe process status did not contain a Seccomp mode")
    return int(match.group(1))


def explicit_unconfined(layer):
    pod = _pod("seccomp-policy-probe")
    profile = {"seccompProfile": {"type": "Unconfined"}}
    if layer == "pod":
        pod["spec"]["securityContext"] = profile
    else:
        pod["spec"]["containers"][0]["securityContext"].update(profile)
    return pod


def enforce_approved_profiles(lab):
    # All admission probes are server-side dry runs and leave no test workload.
    probes = [explicit_unconfined(layer) for layer in ("pod", "container")]
    initial = [lab.create(pod, dry_run=True, allow_failure=True).returncode == 0 for pod in probes]
    lab.check("red", "The node default alone accepts explicit Unconfined in both declaration locations",
              all(initial), {"pod_accepted": initial[0], "container_accepted": initial[1]})

    lab.kubectl("label", "namespace", "saf-test", "saf-seccomp-policy=enforce")
    policy = "saf-seccomp-profile"
    message = "SAF requires an approved seccomp profile"
    safe = "!has(x.securityContext) || !has(x.securityContext.seccompProfile) || x.securityContext.seccompProfile.type == 'RuntimeDefault'"
    expressions = [safe.replace("x.securityContext", "object.spec.securityContext")]
    for field in ("containers", "initContainers", "ephemeralContainers"):
        expressions.append(f"!has(object.spec.{field}) || object.spec.{field}.all(x, {safe})")
    lab.create({"apiVersion":"admissionregistration.k8s.io/v1","kind":"ValidatingAdmissionPolicy",
        "metadata":{"name":policy},"spec":{"failurePolicy":"Fail","matchConstraints":{"resourceRules":[
            {"apiGroups":[""],"apiVersions":["v1"],"operations":["CREATE","UPDATE"],
             "resources":["pods","pods/ephemeralcontainers"]}]},
            "validations":[{"expression":f"({expression})","message":message}
                           for expression in expressions]}})
    lab.create({"apiVersion":"admissionregistration.k8s.io/v1","kind":"ValidatingAdmissionPolicyBinding",
        "metadata":{"name":policy},"spec":{"policyName":policy,"validationActions":["Deny"],
        "matchResources":{"namespaceSelector":{"matchLabels":{"saf-seccomp-policy":"enforce"}}}}})

    deadline = time.monotonic() + 30
    rejected = []
    while time.monotonic() < deadline:
        results = [lab.create(pod, dry_run=True, allow_failure=True) for pod in probes]
        rejected = [result.returncode != 0 and policy in result.stderr and message in result.stderr
                    for result in results]
        if all(rejected):
            break
        time.sleep(1)
    lab.check("green", "Admission denies explicitly unapproved seccomp settings at both levels",
              all(rejected), {"pod_rejected_by_policy": rejected[0],
                              "container_rejected_by_policy": rejected[1]})

    # The check exercises the intended excluded namespace only through admission dry run.
    exception = "saf-seccomp-review-exception"
    lab.kubectl("create", "namespace", exception)
    excluded = explicit_unconfined("pod")
    excluded["metadata"]["namespace"] = exception
    response = lab.kubectl("create", "-n", exception, "-f", "-", "--dry-run=server",
                          payload=json.dumps(excluded), allow_failure=True)
    lab.check("positive", "The documented fixture exception namespace is outside this admission binding",
              response.returncode == 0, {"exception_dry_run_permitted": response.returncode == 0})


def run(lab):
    node_name = f"{lab.cluster}-worker"

    # Red: a newly created pod with no pod- or container-level seccomp profile
    # reaches this node while kubelet seccompDefault is explicitly disabled.
    _set_seccomp_default(lab, "false")
    red_name = "seccomp-default-off"
    red = _pod(red_name)
    if "seccompProfile" in red["spec"] or "seccompProfile" in red["spec"]["containers"][0]["securityContext"]:
        lab.block("Red fixture unexpectedly specifies seccompProfile")
    red["spec"]["nodeName"] = node_name
    lab.create(red)
    _wait_for_pod(lab, red_name, node_name)
    red_mode = _seccomp_mode(lab, red_name)
    lab.check(
        "red",
        "With seccompDefault=false, an omitted profile runs Unconfined",
        red_mode == 0,
        {"worker_confirmed": True, "seccomp_mode": red_mode},
    )

    # Green: turn on the node default, restart kubelet, then create a fresh pod.
    # Testing a new pod avoids claiming that this setting retrofits old pods.
    _set_seccomp_default(lab, "true")
    green_name = "seccomp-default-on"
    green = _pod(green_name)
    if "seccompProfile" in green["spec"] or "seccompProfile" in green["spec"]["containers"][0]["securityContext"]:
        lab.block("Green fixture unexpectedly specifies seccompProfile")
    green["spec"]["nodeName"] = node_name
    lab.create(green)
    _wait_for_pod(lab, green_name, node_name)
    green_mode = _seccomp_mode(lab, green_name)
    lab.check(
        "green",
        "With seccompDefault=true, a newly created pod with no profile uses a filter",
        green_mode == 2,
        {"worker_confirmed": True, "seccomp_mode": green_mode},
    )

    enforce_approved_profiles(lab)

    prior = _seccomp_mode(lab, red_name)
    lab.check("positive", "Changing the default leaves the already running probe unchanged",
              prior == 0, {"original_process_seccomp_mode": prior})

    # Positive/permitted case: a workload may declare RuntimeDefault itself.
    permitted_name = "seccomp-runtime-default"
    permitted = _pod(permitted_name, explicit_runtime_default=True)
    permitted["spec"]["nodeName"] = node_name
    lab.create(permitted)
    _wait_for_pod(lab, permitted_name, node_name)
    permitted_mode = _seccomp_mode(lab, permitted_name)
    lab.check(
        "positive",
        "An explicitly declared RuntimeDefault workload is permitted and filtered",
        permitted_mode == 2,
        {"worker_confirmed": True, "seccomp_mode": permitted_mode},
    )
