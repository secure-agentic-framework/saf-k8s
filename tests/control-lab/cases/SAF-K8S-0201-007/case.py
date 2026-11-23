"""Exercise one worker hard-eviction threshold without creating real exhaustion."""
import json
import re
import time

IMAGE = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
CONFIG = "/var/lib/kubelet/config.yaml"
VICTIM = "saf-hard-threshold"
SCOPE = (
    "A disposable Kind v1.36.1 worker on containerd. A deliberately raised "
    "memory.available threshold creates a kubelet pressure signal without allocating "
    "large memory. Checks the real eviction, a blocking PDB, configured workload grace, "
    "control-plane readiness, and worker recovery. This is not production threshold tuning."
)


def read(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def condition(node, kind):
    return next((item["status"] for item in node["status"]["conditions"] if item["type"] == kind), None)


def wait(lab, read_condition, description, seconds=60):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        value = read_condition()
        if value:
            return value
        time.sleep(1)
    lab.block(f"Timed out waiting for {description}")


def workload(name, worker):
    return {"apiVersion":"v1","kind":"Pod","metadata":{"name":name,"labels":{"case":VICTIM}},
            "spec":{"nodeName":worker,"restartPolicy":"Never","automountServiceAccountToken":False,
                    "terminationGracePeriodSeconds":120,
                    "containers":[{"name":"marker","image":IMAGE,"command":["sh","-c","dd if=/dev/zero of=/dev/shm/saf-measurement bs=1048576 count=16 2>/dev/null; exec sleep 600"],
                        "resources":{"requests":{"cpu":"5m","memory":"1Mi"},
                                     "limits":{"cpu":"20m","memory":"48Mi"}},
                        "securityContext":{"allowPrivilegeEscalation":False,"runAsNonRoot":True,
                            "runAsUser":65534,"capabilities":{"drop":["ALL"]},
                            "seccompProfile":{"type":"RuntimeDefault"}},
                        "lifecycle":{"preStop":{"exec":{"command":["sleep","100"]}}}}]}}


def config_with_threshold(text, value):
    lines = text.splitlines()
    start = lines.index("evictionHard:") + 1
    end = next((i for i in range(start, len(lines)) if not lines[i].startswith(" ")), len(lines))
    thresholds = [line for line in lines[start:end] if not line.startswith("  memory.available:")]
    lines[start:end] = [f"  memory.available: {value}Mi", *thresholds]
    lines = ["evictionPressureTransitionPeriod: 30s" if line.startswith("evictionPressureTransitionPeriod:") else line
             for line in lines]
    return "\n".join(lines) + "\n"


def write_config(lab, worker, contents):
    lab.command("docker", "exec", "-i", worker, "sh", "-ceu",
                'test -f "$1"; umask 077; stage="$1.saf-pressure"; test ! -e "$stage"; '
                'cat > "$stage"; chmod --reference="$1" "$stage"; mv "$stage" "$1"; '
                'systemctl restart kubelet', "sh", CONFIG, payload=contents, timeout=45)


def configz(lab, worker):
    result = lab.kubectl("get", f"--raw=/api/v1/nodes/{worker}/proxy/configz",
                         timeout=12, allow_failure=True)
    if result.returncode:
        return None
    return json.loads(result.stdout)["kubeletconfig"]


def run(lab):
    worker = f"{lab.cluster}-worker"
    rows = read(lab, "get", "nodes")["items"]
    names = set(node["metadata"]["name"] for node in rows)
    if names != {worker, f"{lab.cluster}-control-plane"}:
        lab.block("Expected exactly the disposable worker and its control plane")
    before = read(lab, "get", "node", worker)
    source = lab.command("docker", "exec", worker, "cat", CONFIG).stdout
    initial_config = wait(lab, lambda: configz(lab, worker), "original effective kubelet config")
    initial_hard = initial_config["evictionHard"]

    lab.create(workload(VICTIM, worker))
    lab.kubectl("wait","--for=condition=Ready",f"pod/{VICTIM}","--timeout=75s",timeout=86)
    lab.create({"apiVersion":"policy/v1","kind":"PodDisruptionBudget",
                "metadata":{"name":VICTIM},"spec":{"minAvailable":1,
                "selector":{"matchLabels":{"case":VICTIM}}}})
    def budget_observed():
        status = read(lab, "get", "pdb", VICTIM)["status"]
        return status if status.get("currentHealthy") == 1 and status.get("disruptionsAllowed") == 0 else None
    budget = wait(lab, budget_observed, "PDB to protect the only healthy fixture Pod")
    active = read(lab, "get", "pod", VICTIM)
    lab.check("red", "Nominal threshold leaves the only PDB-protected Pod Running and the worker unpressured",
              condition(before,"MemoryPressure") == "False" and active["status"]["phase"] == "Running",
              {"initial_pressure_clear": condition(before,"MemoryPressure") == "False",
               "pod_running": active["status"]["phase"] == "Running",
               "voluntary_disruptions_allowed": budget["disruptionsAllowed"]})

    capacity = re.fullmatch(r"(\d+)Ki", before["status"]["capacity"]["memory"])
    if capacity is None:
        lab.block("Worker memory capacity is not in the expected Ki unit")
    stats_path = f"--raw=/api/v1/nodes/{worker}/proxy/stats/summary"
    memory = json.loads(lab.kubectl("get", stats_path).stdout)["node"]["memory"]
    available = memory.get("availableBytes")
    if not isinstance(available, int) or available <= 0:
        lab.block("Kubelet stats summary did not report memory.available")
    # Leave a small positive allocatable margin so kubelet accepts the case
    # configuration. No host memory pressure is needed.
    threshold_mib = int(capacity.group(1)) // 1024 - 8
    if threshold_mib * (1024 * 1024) <= available:
        lab.block("Pinned worker has no usable interval between observed free memory and capacity")
    configured = f"{threshold_mib}Mi"
    replacement = config_with_threshold(source, threshold_mib)
    started = time.monotonic()
    elapsed = None
    try:
        write_config(lab, worker, replacement)
        def applied_config():
            effective = configz(lab, worker)
            return effective if effective and effective["evictionHard"].get("memory.available") == configured else None
        effective = wait(lab, applied_config, "configured hard threshold in active kubelet")
        lab.check("green", "The active kubelet reports the deliberately raised memory threshold",
                  bool(effective), {"configured_threshold_loaded": True, "low_memory_workload_only": True})

        def actual_eviction():
            pod = read(lab, "get", "pod", VICTIM)
            node = read(lab, "get", "node", worker)
            return (pod,node) if pod["status"].get("reason") == "Evicted" and condition(node,"MemoryPressure") == "True" else None
        evicted, pressured = wait(lab, actual_eviction, "native MemoryPressure and Evicted status", 75)
        stopped = json.loads(lab.command("docker","exec",worker,"crictl","ps",
                     "--label",f"io.kubernetes.pod.name={VICTIM}","-o","json").stdout)
        elapsed = time.monotonic() - started
        action = evicted["status"]
        real = action["phase"] == "Failed" and "low on resource: memory" in action.get("message","")
        same = evicted["metadata"]["uid"] == active["metadata"]["uid"]
        grace = active["spec"]["terminationGracePeriodSeconds"]
        api_ready = lab.kubectl("get","--raw=/readyz").stdout.strip() == "ok"
        quick = not stopped.get("containers") and elapsed < grace
        lab.check("green", "Hard memory eviction stops the same Pod before its configured grace despite the blocking PDB",
                  real and same and quick and api_ready,
                  {"memory_pressure": condition(pressured,"MemoryPressure") == "True",
                   "native_eviction_reason": real,"same_pod": same,"terminated_before_grace": quick,
                   "pod_grace_seconds":grace,"api_ready":api_ready})
    except Exception:
        lab.kubectl("get", stats_path, allow_failure=True)
        lab.command("docker", "exec", worker, "journalctl", "-u", "kubelet", "-n", "100",
                    "--no-pager", allow_failure=True)
        raise
    finally:
        write_config(lab, worker, source)

    def restored_state():
        effective = configz(lab, worker)
        ready = read(lab, "get", "node", worker)
        if effective and effective["evictionHard"] == initial_hard and condition(ready,"Ready") == "True" and condition(ready,"MemoryPressure") == "False":
            return True
        return False
    restored = wait(lab, restored_state, "restored kubelet thresholds and worker condition", 90)
    replacement_name = "saf-after-pressure"
    lab.create(workload(replacement_name, worker))
    lab.kubectl("wait","--for=condition=Ready",f"pod/{replacement_name}","--timeout=60s",timeout=75)
    accepted = read(lab,"get","pod",replacement_name)
    lab.check("positive", "The restored worker runs a permitted workload without MemoryPressure",
              restored and accepted["status"]["phase"] == "Running",
              {"original_thresholds_restored": restored,"ordinary_pod_running": accepted["status"]["phase"] == "Running"})
    (lab.evidence/"hard-eviction.raw.json").write_text(json.dumps({
        "threshold":configured,"available_before_bytes":available,"baseline":initial_hard,"eviction_message":action["message"],
        "elapsed_seconds":round(elapsed,3),"pod_grace_seconds":grace,
        "pdb_disruptions_allowed_before":budget["disruptionsAllowed"],"restored":restored,
    },indent=2)+"\n")
