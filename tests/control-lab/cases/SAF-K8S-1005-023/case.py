"""Exercise node quarantine and a PDB hold with synthetic accelerator metadata only."""
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
FIXTURES = json.loads((HERE / "fixtures" / "accelerator-node.json").read_text(encoding="utf-8"))
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
IMAGE = FIXTURES["workload"]["image"]
NAMESPACE = "saf-test"
CASE = FIXTURES["case_id"]
LABELS = FIXTURES["workload"]["labels"]
WORKLOAD = FIXTURES["workload"]["name"]
PDB = "saf-1005-023-hold-budget"
PROBE = "saf-1005-023-scheduling-probe"
BASELINE_PROBE = "saf-1005-023-baseline-probe"
EVIDENCE = "saf-1005-023-handoff-evidence"
SCOPE = (
    "One disposable Kind v1.36.1 cluster and case-owned synthetic resources in saf-test. The lab node is "
    "marked with inert accelerator inventory metadata; no GPU/device plugin is installed and no accelerator "
    "resource is requested. A digest-pinned Python container runs a sleep-only mock on the selected node. "
    "The case captures baseline API objects, cordons and taints that node, checks scheduling quarantine, "
    "and checks a PDB-protected eviction hold. It does not establish real GPU-aware drain/checkpoint behavior, "
    "hardware isolation, evidence durability/tamper resistance, or production incident readiness."
)


def _json(lab, *args, allow_failure=False, timeout=45):
    result = lab.kubectl(*args, "-o", "json", allow_failure=allow_failure, timeout=timeout)
    if result.returncode:
        return result, None
    try:
        return result, json.loads(result.stdout)
    except json.JSONDecodeError:
        return result, None


def _wait(lab, fn, description, seconds=90):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            value = fn()
            if value:
                return value
        except (KeyError, IndexError, json.JSONDecodeError):
            pass
        time.sleep(1)
    lab.block(f"Timed out waiting for {description}")


def _node_name(lab):
    _, nodes = _json(lab, "get", "nodes")
    candidates = [n for n in nodes["items"] if n.get("metadata", {}).get("name")]
    if not candidates:
        lab.block("Disposable Kind cluster returned no node")
    return sorted(candidates, key=lambda n: n["metadata"]["name"])[0]["metadata"]["name"]


def _worker(node):
    labels = {**LABELS, "app": WORKLOAD}
    return {"apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": WORKLOAD, "namespace": NAMESPACE, "labels": LABELS,
            "annotations": {"saf-k8s.example/incident": FIXTURES["incident_id"]}},
        "spec": {"replicas": 1, "selector": {"matchLabels": {"app": WORKLOAD}},
            "template": {"metadata": {"labels": labels}, "spec": {
                "nodeName": node, "automountServiceAccountToken": False,
                "terminationGracePeriodSeconds": 2,
                "containers": [{"name": "sleep-only", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                    "command": ["python", "-c", "import time; time.sleep(3600)"],
                    "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"cpu": "100m", "memory": "48Mi"}},
                    "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                        "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True, "runAsUser": 65532,
                        "seccompProfile": {"type": "RuntimeDefault"}}}]}}}}


def _probe(name, sleep=False):
    return {"apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": NAMESPACE,
            "labels": {"saf-k8s.example/case": CASE, "saf-k8s.example/role": "scheduling-probe"}},
        "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
            "nodeSelector": {FIXTURES["node_label"]["key"]: FIXTURES["node_label"]["value"]},
            "terminationGracePeriodSeconds": 1,
            "containers": [{"name": "inert-probe", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-c", "import time; time.sleep(3600)" if sleep else "pass"],
                "resources": {"requests": {"cpu": "5m", "memory": "8Mi"}, "limits": {"cpu": "20m", "memory": "16Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True, "runAsUser": 65532,
                    "seccompProfile": {"type": "RuntimeDefault"}}}]}}


def run(lab):
    node = _node_name(lab)
    lab.kubectl("label", "node", node, f"{FIXTURES['node_label']['key']}={FIXTURES['node_label']['value']}", "--overwrite")
    lab.kubectl("annotate", "node", node, f"{FIXTURES['node_annotation']['key']}={FIXTURES['node_annotation']['value']}", "--overwrite")
    lab.create(_probe(BASELINE_PROBE, sleep=True))
    baseline_probe = _wait(lab, lambda: (lambda x: x if x and x.get("spec", {}).get("nodeName") == node
        and x.get("status", {}).get("phase") == "Running" else None)(_json(lab, "get", "pod", BASELINE_PROBE)[1]),
        "baseline scheduling probe Running on target node")
    lab.check("red", "Before quarantine, a synthetic accelerator-selected Pod can schedule to the target node",
        baseline_probe.get("spec", {}).get("nodeName") == node,
        {"pod": baseline_probe.get("metadata", {}).get("name"), "same_selected_node": baseline_probe.get("spec", {}).get("nodeName") == node,
         "phase": baseline_probe.get("status", {}).get("phase")})
    lab.kubectl("delete", "pod", BASELINE_PROBE, "--wait=true")
    lab.create(_worker(node))
    lab.create({"apiVersion": "policy/v1", "kind": "PodDisruptionBudget",
        "metadata": {"name": PDB, "namespace": NAMESPACE, "labels": {"saf-k8s.example/case": CASE}},
        "spec": {"minAvailable": 1, "selector": {"matchLabels": {"app": WORKLOAD}}}})

    def pods(): return _json(lab, "get", "pods", "-l", f"app={WORKLOAD}")[1]
    pod_list = _wait(lab, lambda: (lambda x: x if x and len(x["items"]) == 1
        and x["items"][0].get("status", {}).get("phase") == "Running"
        and any(c.get("type") == "Ready" and c.get("status") == "True"
                for c in x["items"][0].get("status", {}).get("conditions", [])) else None)(pods()),
        "mock workload Ready on selected node")
    node_before = _json(lab, "get", "node", node)[1]
    pdb_before = _wait(lab, lambda: (lambda x: x if x and x.get("status", {}).get("observedGeneration")
        == x.get("metadata", {}).get("generation") and x.get("status", {}).get("disruptionsAllowed") == 0
        and x.get("status", {}).get("currentHealthy") == 1 else None)(
        _json(lab, "get", "pdb", PDB)[1]), "PDB reports zero allowed disruptions")
    lab.check("red", "Baseline node is schedulable and the synthetic workload is Ready",
        node_before.get("spec", {}).get("unschedulable") is not True
        and pod_list["items"][0].get("spec", {}).get("nodeName") == node,
        {"node_unschedulable": node_before.get("spec", {}).get("unschedulable", False),
         "fixture_pod_bound_to_node": pod_list["items"][0]["spec"]["nodeName"] == node,
         "pdb_allows_disruptions": pdb_before["status"]["disruptionsAllowed"]})

    pre = {"case_id": CASE, "node": node, "node_object": node_before, "pods": pod_list,
           "pdb": pdb_before, "incident_id": FIXTURES["incident_id"],
           "fixture_marker": FIXTURES["evidence_fixture"]}
    (lab.evidence / "pre-quarantine.raw.json").write_text(json.dumps(pre, indent=2, sort_keys=True)+"\n", encoding="utf-8")

    lab.kubectl("cordon", node)
    lab.kubectl("taint", "node", node,
        f"{FIXTURES['quarantine']['taint_key']}={FIXTURES['quarantine']['taint_value']}:{FIXTURES['quarantine']['taint_effect']}",
        "--overwrite")
    quarantined = _json(lab, "get", "node", node)[1]
    lab.create(_probe(PROBE))
    probe = _wait(lab, lambda: (lambda x: x if x and x.get("status", {}).get("phase") == "Pending"
        and any(c.get("type") == "PodScheduled" and c.get("status") == "False"
                and c.get("reason") == "Unschedulable" for c in x["status"].get("conditions", []))
        else None)(
        _json(lab, "get", "pod", PROBE)[1]), "non-tolerating scheduling probe Pending")
    pod_after_quarantine = pods()
    pdb_quarantine = _json(lab, "get", "pdb", PDB)[1]
    record = {"case_id": CASE, "incident_id": FIXTURES["incident_id"],
        "phase": "PRE-SIMULATED-HANDOFF", "decision": FIXTURES["decision"],
        "node_before": node_before, "node_quarantined": quarantined,
        "workload_before": pod_list, "workload_after_quarantine": pod_after_quarantine,
        "pdb_before": pdb_before, "pdb_after_quarantine": pdb_quarantine,
        "scheduling_probe": probe, "fixture_marker": FIXTURES["evidence_fixture"],
        "secrets_included": False}
    cm = {"apiVersion": "v1", "kind": "ConfigMap", "immutable": True,
        "metadata": {"name": EVIDENCE, "namespace": NAMESPACE,
            "labels": {"saf-k8s.example/case": CASE, "saf-k8s.example/role": "handoff-evidence"}},
        "data": {"record.json": json.dumps(record, sort_keys=True)}}
    lab.create(cm)
    persisted = _json(lab, "get", "configmap", EVIDENCE)[1]
    (lab.evidence / "pre-handoff-evidence.raw.json").write_text(json.dumps(persisted, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    persisted_record = json.loads(persisted.get("data", {}).get("record.json", "{}"))

    pod_name = pod_list["items"][0]["metadata"]["name"]
    eviction = {"apiVersion": "policy/v1", "kind": "Eviction",
        "metadata": {"name": pod_name, "namespace": NAMESPACE},
        "deleteOptions": {"gracePeriodSeconds": 1}}
    ev = lab.kubectl("create", "--raw", f"/api/v1/namespaces/{NAMESPACE}/pods/{pod_name}/eviction",
                     "-f", "-", payload=json.dumps(eviction), allow_failure=True)
    ev_text = ev.stdout + ev.stderr
    eviction_blocked = ev.returncode != 0 and ("429" in ev_text or "TooManyRequests" in ev_text) and "disruption budget" in ev_text.lower()
    (lab.evidence / "eviction-hold.raw.txt").write_text(ev_text + f"\n[exit {ev.returncode}]\n", encoding="utf-8")
    pod_after_eviction = pods()
    pdb_after = _json(lab, "get", "pdb", PDB)[1]
    retained_same_pod = (len(pod_after_eviction.get("items", [])) == 1
                         and pod_after_eviction["items"][0]["metadata"]["uid"]
                         == pod_list["items"][0]["metadata"]["uid"])
    lab.check("green", "Quarantine blocks new scheduling and PDB keeps eviction on hold",
        quarantined.get("spec", {}).get("unschedulable") is True
        and any(t.get("key") == FIXTURES["quarantine"]["taint_key"] and t.get("effect") == "NoSchedule"
                for t in quarantined.get("spec", {}).get("taints", []))
        and probe.get("spec", {}).get("nodeName") in (None, "")
        and probe.get("status", {}).get("phase") == "Pending"
        and len(pod_after_quarantine.get("items", [])) == 1
        and retained_same_pod
        and pdb_after.get("status", {}).get("disruptionsAllowed") == 0
        and persisted_record == record and eviction_blocked,
        {"node_unschedulable": quarantined.get("spec", {}).get("unschedulable"),
         "probe_phase": probe.get("status", {}).get("phase"),
         "same_workload_pod_retained": retained_same_pod,
         "disruptions_allowed": pdb_after["status"]["disruptionsAllowed"], "eviction_exit": ev.returncode,
         "eviction_blocked_by_api": eviction_blocked, "evidence_readback_matches": persisted_record == record})

    final_node = _json(lab, "get", "node", node)[1]
    final_cm = _json(lab, "get", "configmap", EVIDENCE)[1]
    final_record = json.loads(final_cm.get("data", {}).get("record.json", "{}"))
    (lab.evidence / "post-handoff-observations.raw.json").write_text(json.dumps({
        "node_after": final_node, "pods_after": pod_after_eviction, "pdb_after": pdb_after,
        "evidence_record_after": final_record, "eviction_response": ev_text,
        "disposition": "hold; no direct delete or force-drain fallback"}, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    lab.check("positive", "Evidence and decision survive the simulated handoff boundary",
        final_record == record and len(pod_after_eviction.get("items", [])) == 1
        and final_node.get("spec", {}).get("unschedulable") is True,
        {"evidence_unchanged": final_record == record, "pod_retained": len(pod_after_eviction.get("items", [])) == 1,
         "node_remains_quarantined": final_node.get("spec", {}).get("unschedulable") is True})
