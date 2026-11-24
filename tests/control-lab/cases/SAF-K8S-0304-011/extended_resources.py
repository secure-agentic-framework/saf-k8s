"""Exercise native admission and accounting for an inert extended resource."""

import json
import time

from fixtures import container, pod

NS = "saf-extended-quota"
RESOURCE = "saf.example/accelerator"
KEY = f"requests.{RESOURCE}"
QUOTA = "saf-extended-budget"


def create(lab, obj, *, dry_run=False, allow_failure=False):
    command = ["-n", NS, "create", "-f", "-", "-o", "json"]
    if dry_run:
        command.append("--dry-run=server")
    return lab.kubectl(*command, payload=json.dumps(obj), allow_failure=allow_failure)


def workload(name, units=None):
    resources = {} if units is None else {
        "requests": {RESOURCE: str(units)}, "limits": {RESOURCE: str(units)},
    }
    return pod(name, [container("probe", resources=resources)])


def amount(result):
    obj = json.loads(result.stdout)
    resources = obj["spec"]["containers"][0]["resources"]
    return {field: resources.get(field, {}).get(RESOURCE) for field in ("requests", "limits")}


def get(lab, *args):
    return json.loads(lab.kubectl("-n", NS, "get", *args, "-o", "json").stdout)


def wait_for(lab, label, read, wanted, timeout=35):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        row = read()
        if wanted(row):
            return row
        time.sleep(0.75)
    lab.block(f"Timed out waiting for {label}")


def run(lab):
    lab.kubectl("create", "namespace", NS)
    omitted, excessive, second = (workload("extended-default"), workload("extended-max", 3),
                                  workload("extended-second", 2))
    baseline = create(lab, omitted, dry_run=True)
    premax = create(lab, excessive, dry_run=True)
    prequota = create(lab, second, dry_run=True)
    red = {"omitted": amount(baseline), "excessive": amount(premax), "quota_candidate": amount(prequota)}
    lab.check("red", "The inert resource is absent when omitted and admitted above later bounds",
              red == {"omitted": {"requests": None, "limits": None},
                      "excessive": {"requests": "3", "limits": "3"},
                      "quota_candidate": {"requests": "2", "limits": "2"}}, red)

    def quota_status():
        return get(lab, "resourcequota", QUOTA).get("status", {})

    create(lab, {"apiVersion": "v1", "kind": "ResourceQuota", "metadata": {"name": QUOTA},
                 "spec": {"hard": {KEY: "4"}}})
    wait_for(lab, "request quota initialized", quota_status,
             lambda status: status.get("hard", {}).get(KEY) == "4")
    quota_only = amount(create(lab, omitted, dry_run=True))
    lab.check("positive", "An extended resource stays omitted under ResourceQuota alone",
              quota_only == {"requests": None, "limits": None}, quota_only)

    limit = {"type": "Container", "max": {RESOURCE: "2"}}
    stored = create(lab, {"apiVersion": "v1", "kind": "LimitRange",
                          "metadata": {"name": "saf-extended-bounds"},
                          "spec": {"limits": [limit]}})
    max_only = wait_for(lab, "defaulting from an extended-resource maximum",
                        lambda: create(lab, omitted, dry_run=True, allow_failure=True),
                        lambda row: row.returncode == 0 and amount(row) == {"requests": "2", "limits": "2"})
    effective = json.loads(stored.stdout)["spec"]["limits"][0]
    max_proof = {"policy_default": effective["default"][RESOURCE],
                 "policy_default_request": effective["defaultRequest"][RESOURCE],
                 "admitted_pair": amount(max_only)}
    lab.check("green", "A maximum alone sets an effective equal request and limit on omission",
              max_proof == {"policy_default": "2", "policy_default_request": "2",
                            "admitted_pair": {"requests": "2", "limits": "2"}}, max_proof)

    limit.update(default={RESOURCE: "1"}, defaultRequest={RESOURCE: "1"})
    lab.kubectl("-n", NS, "patch", "limitrange", "saf-extended-bounds", "--type=merge",
                "-p", json.dumps({"spec": {"limits": [limit]}}))
    applied = wait_for(lab, "equal extended-resource defaults",
                       lambda: create(lab, omitted, dry_run=True, allow_failure=True),
                       lambda row: row.returncode == 0 and amount(row) == {"requests": "1", "limits": "1"})
    annotation = json.loads(applied.stdout)["metadata"].get("annotations", {}).get("kubernetes.io/limit-ranger", "")
    lab.check("green", "One omitted extended resource receives equal request and limit defaults",
              RESOURCE in annotation and amount(applied) == {"requests": "1", "limits": "1"},
              {"amount": amount(applied), "limitranger_annotation": RESOURCE in annotation})
    max_result = create(lab, excessive, dry_run=True, allow_failure=True)
    denied_max = (max_result.returncode != 0 and "(Forbidden)" in max_result.stderr
                  and f"maximum {RESOURCE} usage per Container is 2, but limit is 3" in max_result.stderr)
    lab.check("green", "LimitRange rejects a request above the per-container extended-resource maximum",
              denied_max, {"exact_maximum_denial": denied_max})

    nodes = get(lab, "nodes")["items"]
    if len(nodes) != 1:
        lab.block("Synthetic extended-resource accounting expects one disposable Kind node")
    node = nodes[0]["metadata"]["name"]
    if node != lab.cluster + "-control-plane":
        lab.block("Synthetic extended capacity requires the lab-owned Kind node")
    capacity_key = RESOURCE.replace("~", "~0").replace("/", "~1")
    lab.kubectl("patch", "node", node, "--subresource=status", "--type=json", "-p",
                json.dumps([{"op": "add", "path": f"/status/capacity/{capacity_key}", "value": "3"}]))
    wait_for(lab, "synthetic capacity and kubelet allocatable",
             lambda: get(lab, "node", node)["status"],
             lambda status: status.get("capacity", {}).get(RESOURCE) == "3"
             and status.get("allocatable", {}).get(RESOURCE) == "3")

    lab.kubectl("-n", NS, "patch", "resourcequota", QUOTA, "--type=merge",
                "-p", json.dumps({"spec": {"hard": {KEY: "2"}}}))
    wait_for(lab, "reduced quota becomes effective", quota_status,
             lambda status: status.get("hard", {}).get(KEY) == "2")
    create(lab, omitted)
    lab.kubectl("-n", NS, "wait", "--for=condition=Ready", "pod/extended-default",
                "--timeout=70s", timeout=80)
    persisted = get(lab, "pod", "extended-default")
    used = wait_for(lab, "one declared unit charged", quota_status,
                    lambda status: status.get("used", {}).get(KEY) == "1")
    scheduled = persisted["spec"].get("nodeName") == node and persisted["status"]["phase"] == "Running"
    lab.check("positive", "A defaulted Pod schedules and charges one unit of request quota",
              scheduled, {"hard": used["hard"][KEY], "used": used["used"][KEY], "scheduled_on_fixture": scheduled})

    quota_result = create(lab, second, dry_run=True, allow_failure=True)
    denied_quota = (quota_result.returncode != 0 and "(Forbidden)" in quota_result.stderr
                    and f"exceeded quota: {QUOTA}" in quota_result.stderr and KEY in quota_result.stderr)
    lab.check("green", "Request quota rejects an aggregate overage within the container ceiling",
              denied_quota, {"exact_request_quota_denial": denied_quota})

    lab.kubectl("-n", NS, "delete", "pod", "extended-default", "--grace-period=0", "--wait=true")
    wait_for(lab, "quota released after Pod deletion", quota_status,
             lambda status: status.get("used", {}).get(KEY) == "0")
    post_delete = create(lab, second, dry_run=True)
    remaining = get(lab, "pods")["items"]
    lab.check("positive", "The identical request is admitted after existing usage is released",
              amount(post_delete) == {"requests": "2", "limits": "2"} and not remaining,
              {"amount": amount(post_delete), "persisted": len(remaining)})
    (lab.evidence / "extended-resource-observations.json").write_text(json.dumps({
        "baseline": red, "quota_only": quota_only, "max_only_default": max_proof,
        "defaulted": amount(applied), "maximum_denial": max_result.stderr.strip(),
        "used_before_overage": used["used"][KEY], "quota_denial": quota_result.stderr.strip(),
        "post_delete": amount(post_delete),
    }, indent=2) + "\n")
