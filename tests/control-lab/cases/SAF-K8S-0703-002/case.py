"""Exercise PDB status and the policy/v1 Pod Eviction subresource."""
import json
from pathlib import Path
import socket
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

SCOPE = (
    "One owned three-replica Deployment in the runner-created saf-test namespace: "
    "policy/v1 Eviction requests with no matching PDB, zero disruption allowance, "
    "and one allowed disruption. A distinct two-replica StatefulSet tests maxUnavailable "
    "with a zero-allowance refusal and an approved replacement of one ordinal. "
    "Operational coverage and other disruption mechanisms require separate evidence."
)

NAMESPACE = "saf-test"
NAME = "pdb-availability-probe"
LABEL = "saf-lab.example/control"
VALUE = "SAF-K8S-0703-002"
REPLICAS = 3
STATEFUL = "pdb-stateful-probe"
STATEFUL_VALUE = VALUE + "-stateful"


def get_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def apply_pdb(lab, limit, *, name=NAME, value=VALUE, key="minAvailable"):
    pdb = {
        "apiVersion": "policy/v1",
        "kind": "PodDisruptionBudget",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {
            key: limit,
            "selector": {"matchLabels": {LABEL: value}},
        },
    }
    lab.kubectl("apply", "-f", "-", payload=json.dumps(pdb))


def ready_pods(lab):
    pods = get_json(lab, "get", "pods", "-l", f"{LABEL}={VALUE}")["items"]
    return [
        pod for pod in pods
        if not pod["metadata"].get("deletionTimestamp")
        and any(
            condition["type"] == "Ready" and condition["status"] == "True"
            for condition in pod.get("status", {}).get("conditions", [])
        )
    ]


def wait_for_replicas(lab, *, evicted=None, timeout=90):
    deadline = time.monotonic() + timeout
    while True:
        deployment = get_json(lab, "get", "deployment", NAME)
        pods = ready_pods(lab)
        names = {pod["metadata"]["name"] for pod in pods}
        if (deployment.get("status", {}).get("readyReplicas", 0) == REPLICAS
                and len(pods) == REPLICAS and evicted not in names):
            return deployment, pods
        if time.monotonic() >= deadline:
            return deployment, pods
        time.sleep(0.5)


def wait_for_budget(lab, minimum, timeout=30, *, name=NAME, replicas=REPLICAS):
    deadline = time.monotonic() + timeout
    while True:
        pdb = get_json(lab, "get", "poddisruptionbudget", name)
        status = pdb.get("status", {})
        condition = next(
            (item for item in status.get("conditions", [])
             if item.get("type") == "DisruptionAllowed"),
            {},
        )
        desired_reason = "InsufficientPods" if minimum == replicas else "SufficientPods"
        desired_status = "False" if minimum == replicas else "True"
        ready = (
            pdb.get("metadata", {}).get("generation") == status.get("observedGeneration")
            and status.get("expectedPods") == replicas
            and status.get("currentHealthy") == replicas
            and status.get("desiredHealthy") == minimum
            and status.get("disruptionsAllowed") == replicas - minimum
            and condition.get("reason") == desired_reason
            and condition.get("status") == desired_status
        )
        if ready or time.monotonic() >= deadline:
            return pdb, ready
        time.sleep(0.5)


def eviction_payload(pod_name):
    request = {
        "apiVersion": "policy/v1",
        "kind": "Eviction",
        "metadata": {"name": pod_name, "namespace": NAMESPACE},
        "deleteOptions": {"gracePeriodSeconds": 1},
    }
    return request


def start_proxy(lab):
    """Start a loopback-only authenticated kubectl proxy for exact Eviction POSTs."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    process = subprocess.Popen(
        ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
         f"kind-{lab.cluster}", "proxy", "--address=127.0.0.1", f"--port={port}",
         f"--accept-paths=^/api/v1/namespaces/{NAMESPACE}/pods(/[^/]+/eviction)?$"],
        env=lab.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 10
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("kubectl proxy exited before becoming ready")
            try:
                with urlopen(base + f"/api/v1/namespaces/{NAMESPACE}/pods?limit=1", timeout=1) as response:
                    if response.status == 200:
                        return process, base
            except URLError:
                time.sleep(0.1)
        raise RuntimeError("kubectl proxy did not become ready")
    except Exception:
        process.terminate()
        process.wait(timeout=5)
        raise


def stop_proxy(process):
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def eviction(lab, base, pod_name):
    path = f"{base}/api/v1/namespaces/{NAMESPACE}/pods/{pod_name}/eviction"
    payload = eviction_payload(pod_name)
    body = json.dumps(payload)
    request = Request(path, data=body.encode(),
                      headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=10) as response:
            status, response_body = response.status, response.read().decode()
    except HTTPError as error:
        status, response_body = error.code, error.read().decode()
    try:
        decoded = json.loads(response_body)
    except json.JSONDecodeError:
        decoded = {"raw": response_body}
    with (lab.evidence / "commands.log").open("a") as transcript:
        transcript.write(
            f"$ POST {path}\n{body}\n[HTTP {status}]\n"
            f"{json.dumps(decoded, sort_keys=True)}\n\n"
        )
    return {"status": status, "body": decoded}


def budget_observation(pdb):
    status = pdb.get("status", {})
    condition = next((item for item in status.get("conditions", []) if item.get("type") == "DisruptionAllowed"), {})
    return {"generation": pdb["metadata"].get("generation"),
            "observedGeneration": status.get("observedGeneration"),
            "expectedPods": status.get("expectedPods"), "currentHealthy": status.get("currentHealthy"),
            "desiredHealthy": status.get("desiredHealthy"), "disruptionsAllowed": status.get("disruptionsAllowed"),
            "conditionStatus": condition.get("status"), "conditionReason": condition.get("reason")}


def recovered(deployment, pods, target):
    return {"readyReplicas": deployment.get("status", {}).get("readyReplicas"), "readyPods": len(pods),
            "evictedPodReplaced": all(pod["metadata"]["name"] != target for pod in pods)}


def stateful_budget(lab, proxy_url):
    lab.apply(Path(__file__).with_name("statefulset.yaml"))
    lab.kubectl("rollout", "status", f"statefulset/{STATEFUL}", "--timeout=90s", timeout=100)
    stateful = get_json(lab, "get", "statefulset", STATEFUL)
    target = STATEFUL + "-0"
    original = get_json(lab, "get", "pod", target)
    owner_uid = stateful["metadata"]["uid"]

    def ready_owned(pod):
        return (pod.get("metadata", {}).get("labels", {}).get(LABEL) == STATEFUL_VALUE
                and not pod["metadata"].get("deletionTimestamp")
                and any(owner.get("uid") == owner_uid and owner.get("controller") is True
                        for owner in pod["metadata"].get("ownerReferences", []))
                and any(condition.get("type") == "Ready" and condition.get("status") == "True"
                        for condition in pod.get("status", {}).get("conditions", [])))

    if not ready_owned(original):
        lab.block("The exact selected StatefulSet ordinal was unavailable")
    old_uid = original["metadata"]["uid"]
    limits = {"name": STATEFUL, "value": STATEFUL_VALUE, "key": "maxUnavailable"}
    apply_pdb(lab, 0, **limits)
    _, zero_ready = wait_for_budget(lab, 2, name=STATEFUL, replicas=2)
    denial = eviction(lab, proxy_url, target)
    retained = get_json(lab, "get", "pod", target)
    same_ready = retained["metadata"]["uid"] == old_uid and ready_owned(retained)
    lab.check("green", "A matching StatefulSet maxUnavailable zero budget preserves the exact Ready ordinal",
              zero_ready and denial["status"] == 429 and same_ready,
              {"zero_allowed": zero_ready, "eviction_http": denial["status"],
               "original_ready_ordinal_preserved": same_ready})

    apply_pdb(lab, 1, **limits)
    _, one_ready = wait_for_budget(lab, 1, name=STATEFUL, replicas=2)
    result = eviction(lab, proxy_url, target)
    deadline = time.monotonic() + 100
    recovered = False
    while time.monotonic() < deadline:
        observed = lab.kubectl("get", "pod", target, "-o", "json", allow_failure=True, timeout=10)
        if observed.returncode == 0:
            replacement = json.loads(observed.stdout)
            if replacement["metadata"]["uid"] != old_uid and ready_owned(replacement):
                current = get_json(lab, "get", "statefulset", STATEFUL)
                if current.get("status", {}).get("readyReplicas", 0) == 2:
                    recovered = True
                    break
        time.sleep(1)
    lab.check("positive", "One permitted StatefulSet eviction replaces its ordinal and restores both Ready replicas",
              one_ready and result["status"] in (200, 201) and recovered,
              {"one_allowed": one_ready, "eviction_http": result["status"],
               "new_ready_ordinal_and_replicas": recovered})


def run(lab):
    # The lab runner creates this namespace on a fresh, case-owned cluster. Refuse
    # ambiguous pre-existing policies instead of accidentally testing another PDB.
    existing = get_json(lab, "get", "poddisruptionbudgets")
    if existing["items"]:
        lab.block("saf-test is not empty of PDBs; refusing ambiguous selector coverage")

    lab.apply(Path(__file__).with_name("deployment.yaml"))
    deployment, pods = wait_for_replicas(lab)
    lab.check(
        "positive", "Owned benign Deployment reaches three Ready replicas",
        deployment.get("status", {}).get("readyReplicas") == REPLICAS and len(pods) == REPLICAS,
        {"namespace": NAMESPACE, "deployment": NAME,
         "readyReplicas": deployment.get("status", {}).get("readyReplicas"),
         "readyPods": len(pods)},
    )

    proxy, proxy_url = start_proxy(lab)
    try:
        target = sorted(pod["metadata"]["name"] for pod in pods)[0]
        no_policy = eviction(lab, proxy_url, target)
        lab.check(
            "red", "Eviction API accepts a voluntary eviction when no PDB selects the workload",
            no_policy["status"] in (200, 201),
            {"pdbCountBefore": len(existing["items"]), "httpStatus": no_policy["status"]},
        )
        deployment, pods = wait_for_replicas(lab, evicted=target)
        restored = recovered(deployment, pods, target)
        lab.check(
            "green", "Deployment controller restores its three Ready replicas after the unbudgeted eviction",
            restored == {"readyReplicas": REPLICAS, "readyPods": REPLICAS, "evictedPodReplaced": True},
            restored,
        )

        apply_pdb(lab, REPLICAS)
        blocked_status, blocked_ready = wait_for_budget(lab, REPLICAS)
        lab.check(
            "green", "PDB status reports a current, zero-allowance DisruptionAllowed condition",
            blocked_ready,
            budget_observation(blocked_status),
        )
        target = sorted(pod["metadata"]["name"] for pod in pods)[0]
        denied = eviction(lab, proxy_url, target)
        denied_body = denied["body"]
        still_ready = any(pod["metadata"]["name"] == target for pod in ready_pods(lab))
        lab.check(
            "green", "Eviction API rejects a healthy Pod while the matching PDB allows zero disruptions",
            denied["status"] == 429 and denied_body.get("reason") == "TooManyRequests"
            and "disruption budget" in denied_body.get("message", "").lower() and still_ready,
            {"httpStatus": denied["status"], "reason": denied_body.get("reason"),
             "targetStillReady": still_ready},
        )

        apply_pdb(lab, REPLICAS - 1)
        allowed_status, allowed_ready = wait_for_budget(lab, REPLICAS - 1)
        lab.check(
            "green", "PDB status reports one allowed disruption and a current positive condition",
            allowed_ready,
            budget_observation(allowed_status),
        )
        target = sorted(pod["metadata"]["name"] for pod in pods)[0]
        permitted = eviction(lab, proxy_url, target)
        deployment, pods = wait_for_replicas(lab, evicted=target)
        restored = recovered(deployment, pods, target)
        lab.check(
            "positive", "Eviction API permits one voluntary eviction with one disruption allowed",
            permitted["status"] in (200, 201)
            and restored == {"readyReplicas": REPLICAS, "readyPods": REPLICAS, "evictedPodReplaced": True},
            {"httpStatus": permitted["status"], **restored},
        )
        stateful_budget(lab, proxy_url)
    finally:
        stop_proxy(proxy)
