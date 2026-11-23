"""Reconcile synthetic meter and billing records using actual workload identities."""

from collections import Counter
from fractions import Fraction
import json
import time

SCOPE = "Kind workload identities and scheduling; synthetic signals, billing intervals and charges."
IMAGE = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
SLOT = "saf.example/metering-slot"
NAMES = {"saf-meter-amber": "amber", "saf-meter-blue": "blue"}
POD = "meter"
CONTAINER = "fixture"


def get(lab, kind, name, *flags):
    return json.loads(lab.kubectl(*flags, "get", kind, name, "-o", "json").stdout)


def capacity(lab):
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    if len(nodes) != 1 or not nodes[0]["metadata"]["name"].startswith(lab.cluster + "-"):
        lab.block("The fixture requires one owned Kind node")
    node = nodes[0]["metadata"]["name"]
    patch = json.dumps([{"op": "add", "path": "/status/capacity/" + SLOT.replace("/", "~1"), "value": "2"}])
    lab.kubectl("patch", "node", node, "--subresource=status", "--type=json", "-p", patch)
    expires = time.monotonic() + 70
    while time.monotonic() < expires:
        if get(lab, "node", node)["status"]["allocatable"].get(SLOT) == "2":
            return node
        time.sleep(1)
    lab.block("The lab resource did not become allocatable")


def sample_workload(lab, namespace, run_id, bounds, signal, observed_at):
    payload = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": POD, "labels": {"saf.example/run": run_id}},
               "spec": {"restartPolicy": "Never", "terminationGracePeriodSeconds": 1,
                        "automountServiceAccountToken": False,
                        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                            "seccompProfile": {"type": "RuntimeDefault"}},
                        "containers": [{"name": CONTAINER, "image": IMAGE,
                                        "command": ["/bin/sh", "-c", '''printf '{"pod_uid":"%s","activity_percent":%s}\\n' "$POD_UID" "$SAMPLE"; exec sleep 160'''],
                                        "env": [{"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}},
                                                {"name": "SAMPLE", "value": str(signal)}],
                                        "resources": {"requests": {SLOT: "1", "cpu": "5m", "memory": "4Mi"},
                                                      "limits": {SLOT: "1", "cpu": "100m", "memory": "24Mi"}},
                                        "securityContext": {"allowPrivilegeEscalation": False,
                                                            "readOnlyRootFilesystem": True,
                                                            "capabilities": {"drop": ["ALL"]}}}]}}
    lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps(payload))
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{POD}", "--timeout=65s", timeout=75)
    pod = get(lab, "pod", POD, "-n", namespace)
    owner = get(lab, "namespace", namespace)["metadata"]["labels"]["saf.example/team"]
    container = pod["spec"]["containers"][0]
    request = int(container["resources"]["requests"][SLOT])
    sample = json.loads(lab.kubectl("-n", namespace, "logs", POD).stdout)
    key = {"cluster": lab.cluster, "namespace": namespace, "pod_name": POD, "container": container["name"]}
    allocation = {**key, "pod_uid": pod["metadata"]["uid"], "node": pod["spec"]["nodeName"],
                  "run": pod["metadata"]["labels"]["saf.example/run"], "team": owner,
                  "start": bounds[0], "end": bounds[1], "quantity": request}
    return allocation, {**key, **sample, "sample_time": observed_at}


def join(allocations, signal):
    fields = ("cluster", "pod_uid", "container")
    matches = [row for row in allocations if all(row[key] == signal[key] for key in fields)
               and row["start"] <= signal["sample_time"] < row["end"]]
    return matches[0]["run"] if len(matches) == 1 else None


def billing(allocations, charges):
    per_team, per_run = Counter(), Counter()
    unmatched = 0
    for line in charges:
        rows = [(entry, entry["quantity"] * max(0, min(line["end"], entry["end"]) - max(line["start"], entry["start"])))
                for entry in allocations if line["resource"] == entry["node"]]
        denominator = sum(weight for _, weight in rows)
        if not denominator:
            unmatched += line["minor_units"]
            continue
        for entry, weight in rows:
            if weight:
                cents = Fraction(line["minor_units"] * weight, denominator)
                per_team[entry["team"]] += cents
                per_run[entry["run"]] += cents
    return per_team, per_run, unmatched


def run(lab):
    node = capacity(lab)
    for namespace, owner in NAMES.items():
        lab.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace, "labels": {
            "saf.example/team": owner, "pod-security.kubernetes.io/enforce": "restricted"}}})
    old, old_metric = sample_workload(lab, "saf-meter-amber", "amber-first", (0, 10), 35, 6)
    lab.kubectl("-n", "saf-meter-amber", "delete", "pod", POD, "--wait=true", "--timeout=40s", timeout=50)
    new, new_metric = sample_workload(lab, "saf-meter-amber", "amber-next", (10, 20), 0, 12)
    blue, blue_metric = sample_workload(lab, "saf-meter-blue", "blue-first", (10, 20), 80, 12)
    allocations = [old, new, blue]
    stale = {**old_metric, "sample_time": 10}
    identity_by_name = {(record["namespace"], record["pod_name"]): record["run"] for record in allocations}
    wrongly_joined = identity_by_name[stale["namespace"], stale["pod_name"]]
    replaced = old["pod_uid"] != new["pod_uid"] and old["pod_name"] == new["pod_name"]
    lab.check("red", "Name-only attribution mislabels a delayed sample after actual Pod name reuse",
              replaced and wrongly_joined == "amber-next", {"actual_name_reuse": replaced, "naive_join_selected_replacement": True})
    linked = [join(allocations, item) for item in (old_metric, new_metric, blue_metric, stale)]
    lab.check("green", "Pod UID and half-open sample windows retain the correct workload and reject the delayed sample",
              linked == ["amber-first", "amber-next", "blue-first", None], {"joined_runs": linked})
    charges = [{"resource": node, "start": 0, "end": 30, "minor_units": 1200},
               {"resource": "unmatched-fixture-node", "start": 0, "end": 30, "minor_units": 200}]
    teams, runs, unmatched = billing(allocations, charges)
    exact = (teams == {"amber": 800, "blue": 400} and runs == {"amber-first": 400, "amber-next": 400, "blue-first": 400}
             and unmatched == 200 and sum(teams.values()) + unmatched == 1400
             and new_metric["activity_percent"] == 0 and runs["amber-next"] == 400)
    lab.check("positive", "Synthetic charge allocations reconcile while zero activity and unmatched charges remain visible",
              exact, {"team_minor_units": {key: int(value) for key, value in teams.items()}, "unallocated": unmatched,
                      "zero_activity_keeps_allocated_share": new_metric["activity_percent"] == 0 and runs["amber-next"] == 400})
    (lab.evidence / "metering-observations.json").write_text(json.dumps({
        "basis": "synthetic intervals and billing; observed Pod identities and scheduling",
        "workloads": allocations, "meter_rows": [old_metric, new_metric, blue_metric, stale], "joins": linked,
        "charge_minor_units": 1400, "unallocated_minor_units": unmatched,
        "per_run_minor_units": {key: int(value) for key, value in runs.items()},
    }, indent=2) + "\n")
