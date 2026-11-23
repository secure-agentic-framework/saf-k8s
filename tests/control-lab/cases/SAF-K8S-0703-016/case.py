"""Observe real scheduling decisions using one synthetic resource in an owned Kind node."""

import json
import time

SCOPE = "Three inert Pods compete only for one synthetic extended resource on a fresh Kind node."
IMAGE = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
SLOT = "saf.example/fixture-slot"
VICTIM = "running-nonpreempting"
WAIT = "waiting-nonpreempting"
HIGH = "higher-preempting"


def item(lab, kind, name):
    output = lab.kubectl("get", kind, name, "--ignore-not-found", "-o", "json").stdout
    return json.loads(output) if output.strip() else None


def until(lab, check, message, seconds=55):
    cutoff = time.monotonic() + seconds
    while time.monotonic() < cutoff:
        found = check()
        if found:
            return found
        time.sleep(1)
    lab.block(message)


def priority(lab, name, value, policy):
    lab.create({"apiVersion": "scheduling.k8s.io/v1", "kind": "PriorityClass", "metadata": {"name": name},
                "value": value, "preemptionPolicy": policy, "globalDefault": False})


def workload(lab, name):
    return lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name,
                       "labels": {"saf.example/fixture-workload": name}},
                "spec": {"priorityClassName": name, "terminationGracePeriodSeconds": 6,
                         "automountServiceAccountToken": False, "restartPolicy": "Never",
                         "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                             "seccompProfile": {"type": "RuntimeDefault"}},
                         "containers": [{"name": "fixture", "image": IMAGE, "command": ["/bin/sleep", "360"],
                                         "resources": {"requests": {SLOT: 1, "cpu": "5m", "memory": "4Mi"},
                                                       "limits": {SLOT: 1, "cpu": "100m", "memory": "32Mi"}},
                                         "securityContext": {"allowPrivilegeEscalation": False,
                                                             "readOnlyRootFilesystem": True,
                                                             "capabilities": {"drop": ["ALL"]}}}]}})


def ready(lab, name):
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + name, "--timeout=70s", timeout=80)
    return item(lab, "pod", name)


def unscheduled(lab):
    pod = item(lab, "pod", WAIT)
    return pod and any(row.get("type") == "PodScheduled" and row.get("status") == "False"
                       and row.get("reason") == "Unschedulable" and SLOT in row.get("message", "")
                       for row in pod["status"].get("conditions", []))


def victim_event(lab, uid):
    events = json.loads(lab.kubectl("get", "events", "--field-selector", f"involvedObject.uid={uid}", "-o", "json").stdout)
    return any(row.get("reason") == "Preempted" and row.get("involvedObject", {}).get("uid") == uid
               for row in events["items"])


def run(lab):
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    if len(nodes) != 1 or not nodes[0]["metadata"]["name"].startswith(lab.cluster + "-"):
        lab.block("The fixture requires one owned Kind node")
    node = nodes[0]["metadata"]["name"]
    patch = json.dumps([{"op": "add", "path": "/status/capacity/" + SLOT.replace("/", "~1"), "value": "1"}])
    lab.kubectl("patch", "node", node, "--subresource=status", "--type=json", "-p", patch)
    until(lab, lambda: item(lab, "node", node)["status"]["allocatable"].get(SLOT) == "1",
          "Kubelet did not advertise the disposable scheduler resource", seconds=70)
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    priority(lab, VICTIM, 10, "Never")
    priority(lab, WAIT, 20, "Never")
    priority(lab, HIGH, 30, "PreemptLowerPriority")
    workload(lab, VICTIM)
    victim = ready(lab, VICTIM)
    uid = victim["metadata"]["uid"]
    lab.create({"apiVersion": "policy/v1", "kind": "PodDisruptionBudget", "metadata": {"name": "fixture-budget"},
                "spec": {"minAvailable": 1, "selector": {"matchLabels": {"saf.example/fixture-workload": VICTIM}}}})
    def budget_observes():
        status = item(lab, "pdb", "fixture-budget").get("status", {})
        return status.get("currentHealthy") == 1 and status.get("disruptionsAllowed") == 0

    until(lab, budget_observes, "The fixture budget did not observe its healthy Pod")
    workload(lab, WAIT)
    until(lab, lambda: unscheduled(lab), "The non-preempting Pod did not report insufficient fixture capacity")
    stable = item(lab, "pod", VICTIM)
    held = stable["metadata"]["uid"] == uid and "deletionTimestamp" not in stable["metadata"]
    lab.check("green", "A greater-priority Pod with Never waits instead of evicting the fixture occupant",
              held and unscheduled(lab), {"occupied_slot_preserved": held, "candidate_waiting_for_slot": True})
    workload(lab, HIGH)
    until(lab, lambda: victim_event(lab, uid), "No scheduler preemption event was found for the original fixture Pod", seconds=70)
    observed = ready(lab, HIGH)
    def victim_stopped():
        previous = item(lab, "pod", VICTIM)
        if previous is None:
            return True
        preempted = any(row.get("type") == "DisruptionTarget" and row.get("status") == "True"
                        and row.get("reason") == "PreemptionByScheduler"
                        for row in previous["status"].get("conditions", []))
        return (previous["metadata"]["uid"] == uid and "deletionTimestamp" in previous["metadata"]
                and previous["status"]["phase"] == "Failed" and preempted)

    stopped = until(lab, victim_stopped, "The preempted workload did not reach a terminal state", seconds=35)
    lab.check("red", "The lower-priority Pod with Never can be preempted despite its disruption budget",
              stopped, {"scheduler_preemption_seen": True, "previous_workload_stopped": stopped,
                        "budget_disruptions_allowed_at_start": 0})
    expected = observed["spec"]["nodeName"] == node and observed["spec"]["priority"] == 30
    lab.check("positive", "The preempting higher-priority Pod uses the same scheduler slot",
              expected and unscheduled(lab), {"same_fixture_node": expected, "never_candidate_still_waiting": True})
    (lab.evidence / "preemption-observations.json").write_text(json.dumps({"requested_resource": SLOT,
        "fixture_allocatable": 1, "never_waited": held, "never_victim_preempted": stopped,
        "budget_disruptions_allowed_at_start": 0, "preempting_candidate_ready": expected}, indent=2) + "\n")
