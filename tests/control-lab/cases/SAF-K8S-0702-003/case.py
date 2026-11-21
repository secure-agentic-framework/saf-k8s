"""Observe admission defaulting and per-container and aggregate limit enforcement."""
import json
from pathlib import Path
import time

from fixtures import container, pod, ready

SCOPE = "Namespace inventory, LimitRange defaults and maxima for CPU, memory and ephemeral storage."
APP_NAMESPACE = "app-new"
SYSTEM_NAMESPACE = "system-sample"
SYSTEM_JUSTIFICATION = (
    "The sample system namespace allows larger bounded batches for node-level maintenance; "
    "defaults remain enforced and maxima remain finite."
)
MAXIMUMS = {
    "container": {"cpu": "200m", "memory": "128Mi", "ephemeral-storage": "64Mi"},
    "pod": {"cpu": "300m", "memory": "192Mi", "ephemeral-storage": "96Mi"},
}
SYSTEM_MAXIMUMS = {
    "container": {"cpu": "500m", "memory": "256Mi", "ephemeral-storage": "128Mi"},
    "pod": {"cpu": "750m", "memory": "384Mi", "ephemeral-storage": "192Mi"},
}
DEFAULTS = {
    "requests": {"cpu": "50m", "memory": "32Mi", "ephemeral-storage": "16Mi"},
    "limits": {"cpu": "100m", "memory": "64Mi", "ephemeral-storage": "32Mi"},
}
EXCESS = {
    "cpu": ("250m", "175m"),
    "memory": ("160Mi", "112Mi"),
    "ephemeral-storage": ("80Mi", "56Mi"),
}


def excess_pods():
    for resource, (single, aggregate) in EXCESS.items():
        for count, amount, limit_type in ((1, single, "Container"), (2, aggregate, "Pod")):
            containers = [
                container(f"probe-{i}", resources={
                    "requests": {resource: amount}, "limits": {resource: amount},
                })
                for i in range(count)
            ]
            yield resource, limit_type, pod(f"oversized-{limit_type.lower()}-{resource}", containers)


def observed_resources(resource):
    return resource["spec"]["containers"][0]["resources"]


def namespaces(lab):
    data = json.loads(lab.kubectl("get", "namespaces", "-o", "json").stdout)
    return {row["metadata"]["name"] for row in data["items"]}


def coverage(lab):
    data = json.loads(lab.kubectl("get", "limitranges", "-A", "-o", "json").stdout)
    return {row["metadata"]["namespace"]: row for row in data["items"]
            if row["metadata"]["name"] == "workload-bounds"}


def install_policy(lab, namespace):
    if namespace != SYSTEM_NAMESPACE:
        lab.kubectl("-n", namespace, "apply", "-f", str(Path(__file__).with_name("limitrange.yaml")))
        return
    manifest = {
        "apiVersion": "v1", "kind": "LimitRange",
        "metadata": {"name": "workload-bounds",
                     "annotations": {"saf-lab.example/relaxation": SYSTEM_JUSTIFICATION}},
        "spec": {"limits": [
            {"type": "Container", "defaultRequest": DEFAULTS["requests"],
             "default": DEFAULTS["limits"], "max": SYSTEM_MAXIMUMS["container"]},
            {"type": "Pod", "max": SYSTEM_MAXIMUMS["pod"]},
        ]},
    }
    lab.kubectl("-n", namespace, "apply", "-f", "-", payload=json.dumps(manifest))


def dry_run(lab, namespace, resource):
    result = lab.kubectl("-n", namespace, "create", "-f", "-", "--dry-run=server", "-o", "json",
                         payload=json.dumps(resource))
    return json.loads(result.stdout)


def defaulted_resources(lab, namespace, resource):
    deadline = time.monotonic() + 15
    while True:
        observed = observed_resources(dry_run(lab, namespace, resource))
        if observed == DEFAULTS or time.monotonic() >= deadline:
            return observed
        time.sleep(0.5)


def run(lab):
    lab.kubectl("create", "namespace", SYSTEM_NAMESPACE)
    original = namespaces(lab)
    missing = sorted(original - coverage(lab).keys())
    lab.check("red", "Inventory identifies all unconfigured namespaces before provisioning",
              set(missing) == original and "saf-test" in original, missing)

    before = observed_resources(lab.create(pod("pre-policy", [container("probe")])))
    ready(lab, "pre-policy")
    lab.check("red", "A running pre-policy Pod has no resource constraints", before == {}, before)

    defaulted = pod("defaulted", [container("probe")])
    baseline = observed_resources(lab.create(defaulted, dry_run=True))
    lab.check("red", "Pod with omitted resources receives no defaults",
              baseline == {}, baseline)
    for resource, limit_type, excessive in excess_pods():
        lab.create(excessive, dry_run=True)
        lab.check("red", f"{limit_type} over {resource} max is admitted without LimitRange",
                  True, "server accepted")

    for namespace in sorted(original):
        install_policy(lab, namespace)
    lab.kubectl("create", "namespace", APP_NAMESPACE)
    missing = sorted(namespaces(lab) - coverage(lab).keys())
    lab.check("red", "Inventory detects the new namespace before its policy is installed",
              missing == [APP_NAMESPACE], missing)
    install_policy(lab, APP_NAMESPACE)
    verified = coverage(lab)
    lab.check("green", "Every lab cluster namespace has the intended LimitRange",
              verified.keys() == namespaces(lab), sorted(verified))
    for namespace, policy in sorted(verified.items()):
        items = {item["type"]: item for item in policy["spec"]["limits"]}
        expected = SYSTEM_MAXIMUMS if namespace == SYSTEM_NAMESPACE else MAXIMUMS
        condition = (
            items["Container"]["default"] == DEFAULTS["limits"]
            and items["Container"]["defaultRequest"] == DEFAULTS["requests"]
            and items["Container"]["max"] == expected["container"]
            and items["Pod"]["max"] == expected["pod"]
        )
        lab.check("green", f"{namespace} has the intended defaults and maxima", condition, items)
    justification = verified[SYSTEM_NAMESPACE]["metadata"]["annotations"]["saf-lab.example/relaxation"]
    lab.check("green", "The relaxed system limits have documented justification",
              justification == SYSTEM_JUSTIFICATION, justification)

    after = observed_resources(json.loads(lab.kubectl(
        "get", "pod", "pre-policy", "-n", "saf-test", "-o", "json").stdout))
    lab.check("green", "Installing LimitRange leaves already-running pre-policy Pod unchanged",
              after == before, {"before": before, "after": after})
    # Admission observes LimitRange changes asynchronously through its informer.
    for namespace in ("saf-test", APP_NAMESPACE, SYSTEM_NAMESPACE):
        lab.kubectl("-n", namespace, "wait", "--for=create", "serviceaccount/default", "--timeout=20s")
        observed = defaulted_resources(lab, namespace, defaulted)
        lab.check("green", f"Admission defaults all three requests and limits in {namespace}",
                  observed == DEFAULTS, observed)
    relaxed = pod("relaxed-cpu", [container("probe", resources={
        "requests": {"cpu": "250m"}, "limits": {"cpu": "250m"},
    })])
    observed = observed_resources(dry_run(lab, SYSTEM_NAMESPACE, relaxed))
    lab.check("positive", "The documented relaxation admits a CPU request above the standard maximum",
              observed["limits"]["cpu"] == "250m", observed)

    for resource, limit_type, excessive in excess_pods():
        result = lab.create(excessive, dry_run=True, allow_failure=True)
        expected = f"maximum {resource} usage per {limit_type.capitalize()}"
        lab.check("green", f"{limit_type} over {resource} max is denied by LimitRange",
                  result.returncode != 0 and "(Forbidden)" in result.stderr
                  and expected.lower() in result.stderr.lower(), result.stderr.strip())

    lab.create(defaulted)
    ready(lab, "defaulted")
    lab.check("positive", "Pod with defaults is admitted and reaches Ready", True, "Ready")
