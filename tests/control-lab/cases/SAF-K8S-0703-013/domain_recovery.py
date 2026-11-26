"""Observe Ready replica replacement as a case-owned scheduling domain is withdrawn and restored."""
import json
import time

from fixtures import BUSYBOX_IMAGE

POOL = "saf.example/node-pool"
DOMAIN = "saf.example/failure-domain"
APP_LABEL = "saf-lab.example/0703-013-failure-recovery"
APP_VALUE = "owned-fixture"
WITHDRAWN_TAINT = "saf.example/fixture-withdrawn"
DEPLOYMENT = "saf-0703-013-domain-recovery"


def get_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def pod_domain(lab, pod):
    node_name = pod.get("spec", {}).get("nodeName")
    if not node_name:
        return None
    return get_json(lab, "get", "node", node_name).get("metadata", {}).get("labels", {}).get(DOMAIN)


def ready_owned_pods(lab, replica_set_uid=None):
    pods = get_json(lab, "get", "pods", "-l", f"{APP_LABEL}={APP_VALUE}")["items"]
    owned = []
    for pod in pods:
        refs = pod.get("metadata", {}).get("ownerReferences", [])
        is_rs_owned = any(ref.get("controller") is True and ref.get("kind") == "ReplicaSet"
                         and (replica_set_uid is None or ref.get("uid") == replica_set_uid)
                          for ref in refs)
        ready = any(c.get("type") == "Ready" and c.get("status") == "True"
                    for c in pod.get("status", {}).get("conditions", []))
        if is_rs_owned and ready and not pod.get("metadata", {}).get("deletionTimestamp"):
            owned.append(pod)
    return owned


def wait_ready_domains(lab, expected_domains, replica_set_uid=None, timeout=90):
    deadline = time.monotonic() + timeout
    last = []
    while time.monotonic() < deadline:
        dep = get_json(lab, "get", "deployment", DEPLOYMENT)
        pods = ready_owned_pods(lab, replica_set_uid)
        domains = [pod_domain(lab, pod) for pod in pods]
        if dep.get("status", {}).get("readyReplicas") == 2 and len(pods) == 2:
            if sorted(domains) == sorted(expected_domains):
                return dep, pods, domains
        last = domains
        time.sleep(0.5)
    return dep, pods, last


def run(lab):
    nodes = get_json(lab, "get", "nodes")["items"]
    workers = [n for n in nodes if n.get("metadata", {}).get("labels", {}).get(POOL) == "compute"]
    by_domain = {n.get("metadata", {}).get("labels", {}).get(DOMAIN): n["metadata"]["name"]
                 for n in workers}
    if (set(by_domain) != {"fd-a", "fd-b"} or len(workers) != 2
            or set(by_domain.values()) != {lab.cluster + "-worker", lab.cluster + "-worker2"}):
        lab.block("Expected exactly the two fixture-owned synthetic compute domains fd-a and fd-b")

    deployment = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": DEPLOYMENT, "namespace": "saf-test"},
        "spec": {
            "replicas": 2,
            "selector": {"matchLabels": {APP_LABEL: APP_VALUE}},
            "template": {
                "metadata": {"labels": {APP_LABEL: APP_VALUE}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "terminationGracePeriodSeconds": 1,
                    "containers": [{"name": "probe", "image": BUSYBOX_IMAGE,
                                    "command": ["sh", "-c", "printf ready >/tmp/saf-ready; sleep 900"],
                                    "readinessProbe": {"exec": {"command": ["test", "-s", "/tmp/saf-ready"]},
                                                       "periodSeconds": 1}}],
                    "nodeSelector": {POOL: "compute"},
                    "topologySpreadConstraints": [{
                        "maxSkew": 1, "topologyKey": DOMAIN,
                        "whenUnsatisfiable": "DoNotSchedule",
                        "nodeAffinityPolicy": "Honor", "nodeTaintsPolicy": "Honor",
                        "labelSelector": {"matchLabels": {APP_LABEL: APP_VALUE}},
                    }],
                },
            },
        },
    }

    node_a = by_domain["fd-a"]
    taint_added = False
    cordoned = False
    applied = False
    try:
        lab.kubectl("apply", "-f", "-", payload=json.dumps(deployment))
        applied = True
        dep = get_json(lab, "get", "deployment", DEPLOYMENT)
        deployment_uid = dep["metadata"]["uid"]
        dep, pods, domains = wait_ready_domains(lab, ["fd-a", "fd-b"])
        rs = get_json(lab, "get", "replicasets", "-l", f"{APP_LABEL}={APP_VALUE}")["items"]
        if len(rs) != 1 or not any(ref.get("uid") == deployment_uid and ref.get("controller") is True
                                   for ref in rs[0].get("metadata", {}).get("ownerReferences", [])):
            lab.block("The selected ReplicaSet is not owned by this fixture Deployment")
        rs_uid = rs[0]["metadata"]["uid"]
        def owned_ready():
            return ready_owned_pods(lab, rs_uid)

        lab.check("positive", "Two fixture-owned replicas are Ready, one in each synthetic domain",
                  dep.get("status", {}).get("readyReplicas") == 2 and len(owned_ready()) == 2
                  and sorted(domains) == ["fd-a", "fd-b"],
                  {"ready_replicas": dep.get("status", {}).get("readyReplicas"), "domains": sorted(domains)})

        # Withdraw only the case-owned fd-a worker from new scheduling. The node
        # remains in the isolated cluster; the custom NoSchedule taint is explicit.
        lab.kubectl("taint", "node", node_a, f"{WITHDRAWN_TAINT}=true:NoSchedule", "--overwrite")
        taint_added = True
        lab.kubectl("cordon", node_a)
        cordoned = True
        fd_a_pods = [p for p in owned_ready() if pod_domain(lab, p) == "fd-a"]
        if len(fd_a_pods) != 1:
            lab.block("Expected exactly one Ready fixture-owned Pod on fd-a before controlled loss")
        removed_name = fd_a_pods[0]["metadata"]["name"]
        removed_uid = fd_a_pods[0]["metadata"]["uid"]
        lab.kubectl("delete", "pod", removed_name, "--wait=true", "--timeout=25s")

        dep, recovered, domains = wait_ready_domains(lab, ["fd-b", "fd-b"], rs_uid)
        recovered_uids = {p["metadata"]["uid"] for p in recovered}
        withdrawn_replaced = removed_uid not in recovered_uids and len(recovered_uids) == 2
        lab.check("green", "After fd-a withdrawal and one owned Pod loss, two Ready replicas recover on fd-b",
                  dep.get("status", {}).get("readyReplicas") == 2 and len(owned_ready()) == 2
                  and domains == ["fd-b", "fd-b"] and withdrawn_replaced,
                  {"ready_replicas": dep.get("status", {}).get("readyReplicas"),
                   "domains": domains, "withdrawn_domain": "fd-a",
                   "withdrawn_pod_replaced": withdrawn_replaced})

        # Return the synthetic domain and replace exactly one remaining owned Pod.
        # This tests placement on a fresh scheduling decision, not autonomous
        # rebalancing of already-running Pods.
        lab.kubectl("taint", "node", node_a, f"{WITHDRAWN_TAINT}-")
        taint_added = False
        lab.kubectl("uncordon", node_a)
        cordoned = False
        fd_b_pods = [p for p in owned_ready() if pod_domain(lab, p) == "fd-b"]
        if len(fd_b_pods) != 2:
            lab.block("Expected both recovered fixture Pods on fd-b before replacement comparison")
        replaced_name = fd_b_pods[0]["metadata"]["name"]
        replaced_uid = fd_b_pods[0]["metadata"]["uid"]
        lab.kubectl("delete", "pod", replaced_name, "--wait=true", "--timeout=25s")
        dep, recovered, domains = wait_ready_domains(lab, ["fd-a", "fd-b"], rs_uid)
        restored_uids = {p["metadata"]["uid"] for p in recovered}
        restored_new_pod = replaced_uid not in restored_uids and len(restored_uids) == 2
        (lab.evidence / "domain-recovery-observations.json").write_text(json.dumps({
            "deployment_uid": deployment_uid, "replica_set_uid": rs_uid,
            "withdrawn_node": node_a, "initial_pod_uids": sorted(p["metadata"]["uid"] for p in pods),
            "withdrawn_pod_uid": removed_uid, "recovered_pod_uids": sorted(recovered_uids),
            "replaced_after_return_uid": replaced_uid, "restored_pod_uids": sorted(restored_uids),
            "restored_domain_distribution": sorted(domains),
        }, indent=2) + "\n")
        lab.check("positive", "After fd-a returns, a bounded owned-Pod replacement restores 1/1 spread",
                  dep.get("status", {}).get("readyReplicas") == 2 and len(owned_ready()) == 2
                  and sorted(domains) == ["fd-a", "fd-b"] and restored_new_pod,
                  {"ready_replicas": dep.get("status", {}).get("readyReplicas"),
                   "domains": sorted(domains), "returned_domain_targeted_by_new_replica": restored_new_pod,
                   "automatic_rebalancing_claimed": False})
    finally:
        if taint_added:
            lab.kubectl("taint", "node", node_a, f"{WITHDRAWN_TAINT}-", allow_failure=True)
        if cordoned:
            lab.kubectl("uncordon", node_a, allow_failure=True)
        if applied:
            lab.kubectl("delete", "deployment", DEPLOYMENT, "--wait=true", "--timeout=25s",
                        allow_failure=True)
