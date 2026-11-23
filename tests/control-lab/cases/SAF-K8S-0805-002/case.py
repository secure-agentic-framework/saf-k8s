"""Verify live Pod lifecycle audit evidence and explicitly modeled allocation correlation."""

import json
import time

SCOPE = "Live Kubernetes scheduler and Pod creation audit events correlated with inert synthetic allocation records."
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
NS = "saf-test"
POD = "fixture-allocation"
ACCOUNT = "fixture-accelerator-workload"
RESOURCE = "fixture.example/accelerator"
CONTAINER = "unit"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
LOG = "/var/log/kubernetes/saf-allocation-audit.log"
KEYS = ("cluster", "namespace", "node", "uid", "container", "resource")


def prepare_kind(_lab, temporary):
    policy = temporary / "allocation-audit.json"
    policy.write_text(json.dumps({
        "apiVersion": "audit.k8s.io/v1", "kind": "Policy", "omitStages": ["RequestReceived"],
        "rules": [{"level": "RequestResponse", "verbs": ["create"], "namespaces": [NS],
                   "resources": [{"group": "", "resources": ["pods"]}]}, {"level": "None"}],
    }))
    config = temporary / "kind-allocation-audit.yaml"
    config.write_text(f"""kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: {json.dumps(str(policy))}
        containerPath: /etc/kubernetes/saf-allocation-audit.json
        readOnly: true
kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta4
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        - name: audit-policy-file
          value: /etc/kubernetes/saf-allocation-audit.json
        - name: audit-log-path
          value: {LOG}
      extraVolumes:
        - name: saf-allocation-audit-policy
          hostPath: /etc/kubernetes/saf-allocation-audit.json
          mountPath: /etc/kubernetes/saf-allocation-audit.json
          readOnly: true
          pathType: File
        - name: saf-allocation-audit-log
          hostPath: /var/log/kubernetes
          mountPath: /var/log/kubernetes
          pathType: DirectoryOrCreate
""")
    return config


def node_resource(lab):
    node, = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    name = node["metadata"]["name"]
    field = RESOURCE.replace("/", "~1")
    lab.kubectl("patch", "node", name, "--subresource=status", "--type=json", "-p",
                json.dumps([{"op": "add", "path": f"/status/capacity/{field}", "value": "1"}]))
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status = json.loads(lab.kubectl("get", "node", name, "-o", "json").stdout)["status"]
        if status.get("allocatable", {}).get(RESOURCE) == "1":
            return name
        time.sleep(0.5)
    lab.block("The disposable node did not advertise the synthetic resource")


def scheduled(lab, node):
    created = lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": POD}, "spec": {
        "serviceAccountName": ACCOUNT, "automountServiceAccountToken": False, "restartPolicy": "Never",
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": CONTAINER, "image": IMAGE, "command": ["python", "-c", "import time; time.sleep(100)"],
                        "resources": {"requests": {RESOURCE: "1", "cpu": "5m", "memory": "12Mi"},
                                      "limits": {RESOURCE: "1", "cpu": "100m", "memory": "64Mi"}},
                        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]}}}],
    }})
    lab.kubectl("wait", "--for=condition=PodScheduled", f"pod/{POD}", "--timeout=55s", timeout=64)
    item = json.loads(lab.kubectl("get", "pod", POD, "-o", "json").stdout)
    spec = item["spec"]
    container, = spec["containers"]
    if (item["metadata"]["uid"] != created["metadata"]["uid"] or spec["nodeName"] != node
            or container["resources"]["requests"].get(RESOURCE) != "1"):
        lab.block("The scheduled fixture did not preserve the admitted workload and resource identity")
    return {"cluster": lab.cluster, "namespace": item["metadata"]["namespace"], "name": item["metadata"]["name"],
            "node": spec["nodeName"], "uid": item["metadata"]["uid"], "container": container["name"],
            "resource": RESOURCE, "service_account": spec["serviceAccountName"]}


def get_audit(lab, uids):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        result = lab.command("docker", "exec", f"{lab.cluster}-control-plane", "cat", LOG, allow_failure=True)
        events = {}
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                event = json.loads(line)
                obj = event.get("responseObject") or {}
                meta = obj.get("metadata") or {}
                ref = event.get("objectRef") or {}
                uid = meta.get("uid")
                if (uid in uids and meta.get("name") == POD and ref.get("namespace") == NS
                        and ref.get("resource") == "pods" and event.get("stage") == "ResponseComplete"
                        and event.get("verb") == "create" and event.get("responseStatus", {}).get("code") == 201
                        and obj.get("spec", {}).get("serviceAccountName") == ACCOUNT):
                    events[uid] = {"audit_id": event["auditID"], "recorded_at": event["stageTimestamp"],
                                   "service_account": ACCOUNT}
        if events.keys() == uids:
            return events
        time.sleep(0.5)
    lab.block("Both successful scoped API audit events were not available")


def correlate(workload, snapshots):
    matching = {row["device"] for row in snapshots if all(row[key] == workload[key] for key in KEYS)}
    if len(matching) != 1:
        return {"status": "ambiguous" if matching else "missing", "exact_duration": None}
    return {"status": "synthetic-snapshot", "device": next(iter(matching)), "exact_duration": None}


def run(lab):
    lab.kubectl("label", "namespace", NS, "pod-security.kubernetes.io/enforce=restricted")
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": ACCOUNT},
                "automountServiceAccountToken": False})
    node = node_resource(lab)
    first = scheduled(lab, node)
    lab.kubectl("delete", "pod", POD, "--grace-period=0", "--force", "--wait=true")
    second = scheduled(lab, node)
    modeled = {**first, "device": "fixture-device-a"}
    name_collision = first["namespace"] == second["namespace"] and first["name"] == second["name"]
    lab.check("red", "A namespace-and-name join would confuse the old allocation with the recreated Pod",
              name_collision and first["uid"] != second["uid"], {"same_name": name_collision, "distinct_uids": first["uid"] != second["uid"]})

    audit = get_audit(lab, {first["uid"], second["uid"]})
    first_match = correlate(first, [modeled])
    second_match = correlate(second, [modeled])
    lab.check("green", "Distinct live creation audit events back the UID join and exclude the replacement Pod",
              len({row["audit_id"] for row in audit.values()}) == 2
              and first_match.get("device") == "fixture-device-a" and second_match["status"] == "missing",
              {"distinct_creation_audit_events": len(audit), "first": first_match["status"], "replacement": second_match["status"]})

    wrong_node = correlate(first, [{**modeled, "node": "fixture-other-node"}])
    conflict = correlate(first, [modeled, {**modeled, "device": "fixture-device-b"}])
    lab.check("positive", "Wrong-node and conflicting records stay unresolved and snapshots yield no exact interval",
              wrong_node["status"] == "missing" and conflict["status"] == "ambiguous" and first_match["exact_duration"] is None,
              {"wrong_node": wrong_node["status"], "conflict": conflict["status"], "exact_duration": first_match["exact_duration"]})
    (lab.evidence / "accelerator-audit-observations.json").write_text(json.dumps({
        "workloads": [first, second], "creation_audit": audit, "first_relation": first_match,
        "replacement_relation": second_match, "conflicting_relation": conflict,
        "allocation_source": "synthetic", "hardware_or_plugin_observed": False,
    }, indent=2) + "\n")
