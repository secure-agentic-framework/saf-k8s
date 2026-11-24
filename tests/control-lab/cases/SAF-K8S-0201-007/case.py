"""Exercise native kubelet eviction signals without exhausting resources."""
import json
import re
import time

from fixtures import container, pod, ready

IMAGE = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
CONFIG = "/var/lib/kubelet/config.yaml"
VICTIM = "saf-hard-threshold"
SCOPE = (
    "A disposable Kind v1.36.1 worker on containerd. A deliberately raised "
    "memory.available threshold creates a kubelet pressure signal without allocating "
    "large memory. Checks the real eviction, a blocking PDB, configured workload grace, "
    "control-plane readiness, and worker recovery. Also compares effective settings for an omitted "
    "filesystem-inode signal under each default-merge mode. Separately exercise native nodefs space, "
    "nodefs inodes and PID pressure, kubelet admission, and recovery. All thresholds are synthetic and local."
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


def hard_map_bounds(lines):
    begin = lines.index("evictionHard:") + 1
    end = next((i for i in range(begin, len(lines)) if not lines[i].startswith(" ")), len(lines))
    return begin, end


def config_with_threshold(text, value):
    lines = text.splitlines()
    start, end = hard_map_bounds(lines)
    thresholds = [line for line in lines[start:end] if not line.startswith("  memory.available:")]
    lines[start:end] = [f"  memory.available: {value}Mi", *thresholds]
    lines = ["evictionPressureTransitionPeriod: 30s" if line.startswith("evictionPressureTransitionPeriod:") else line
             for line in lines]
    return "\n".join(lines) + "\n"


def with_merge_fixture(text, explicit, merge):
    lines = [line for line in text.splitlines() if not line.startswith("mergeDefaultEvictionSettings:")]
    start, end = hard_map_bounds(lines)
    lines[start:end] = [f"  {signal}: {json.dumps(value)}" for signal, value in explicit.items()]
    lines.append(f"mergeDefaultEvictionSettings: {str(merge).lower()}")
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


def verify_default_merge(lab, worker, source, initial):
    omitted = "nodefs.inodesFree"
    explicit = {
        "memory.available": "128Mi",
        "nodefs.available": "0%",
        "imagefs.available": "0%",
        "imagefs.inodesFree": "0%",
    }
    stats_path = f"--raw=/api/v1/nodes/{worker}/proxy/stats/summary"
    overview = json.loads(lab.kubectl("get", stats_path).stdout)["node"]
    fs = overview["fs"]
    if (fs.get("inodes", 0) <= 0 or fs.get("inodesFree", 0) * 100 < fs["inodes"] * 10
            or overview["memory"].get("availableBytes", 0) < 512 * 1024 * 1024):
        lab.block("The owned worker needs headroom before enabling the version's test inode threshold")

    def effective_with(merge):
        config = configz(lab, worker)
        if config and config.get("mergeDefaultEvictionSettings", False) is merge:
            hard = config["evictionHard"]
            if all(hard.get(signal) == value for signal, value in explicit.items()):
                return hard
        return None

    try:
        write_config(lab, worker, with_merge_fixture(source, explicit, False))
        without = wait(lab, lambda: effective_with(False), "custom map with default merging disabled")
        mode = without.get(omitted)
        lab.check("red", "Without merging, an omitted inode signal has no active threshold",
                  mode in (None, "0", "0%"), {"omitted_inode_threshold_passive": mode in (None, "0", "0%")})
        write_config(lab, worker, with_merge_fixture(source, explicit, True))
        merged = wait(lab, lambda: effective_with(True), "custom map with default merging enabled")
        lab.check("green", "Merging brings back the version's inode default while explicit thresholds prevail",
                  merged == {**explicit, omitted: "5%"},
                  {"inherited_inode_threshold": merged.get(omitted), "explicit_thresholds_preserved": True})
    finally:
        write_config(lab, worker, source)

    def restored():
        config = configz(lab, worker)
        return config and config["evictionHard"] == initial["evictionHard"] and (
            config.get("mergeDefaultEvictionSettings", False) == initial.get("mergeDefaultEvictionSettings", False)
        )

    wait(lab, restored, "exact restored threshold map and merge flag")
    lab.check("positive", "The worker again reports the original effective map and merge policy",
              True, {"original_map_and_merge_policy_restored": True})
    return {"signal": omitted, "explicit": explicit, "merge_disabled": without, "merge_enabled": merged,
            "original_map": initial["evictionHard"],
            "original_merge_enabled": initial.get("mergeDefaultEvictionSettings", False), "restored": True}


SIGNALS = (
    ("nodefs.available", "disk-space", "DiskPressure"),
    ("nodefs.inodesFree", "disk-inodes", "DiskPressure"),
    ("pid.available", "pids", "PIDPressure"),
)
PRESSURE_CONDITIONS = ("DiskPressure", "PIDPressure", "MemoryPressure")


def headroom(signal, sample):
    if signal == "pid.available":
        limits = sample["rlimit"]
        maximum = limits["maxpid"]
        return maximum - limits["curproc"], maximum
    data = sample["fs"]
    if signal == "nodefs.available":
        return data["availableBytes"], data["capacityBytes"]
    return data["inodesFree"], data["inodes"]


def exercise_pressure_signals(lab, worker, source, initial, baseline):
    raw_path = f"--raw=/api/v1/nodes/{worker}/proxy/stats/summary"
    worker_uid = baseline["metadata"]["uid"]
    original_hard = initial["evictionHard"]
    original_merge = initial.get("mergeDefaultEvictionSettings", False)

    def current():
        return read(lab, "get", "node", worker)

    def normal():
        worker_state = current()
        effective = configz(lab, worker)
        return (effective and effective["evictionHard"] == original_hard
                and effective.get("mergeDefaultEvictionSettings", False) == original_merge
                and worker_state["metadata"]["uid"] == worker_uid
                and condition(worker_state, "Ready") == "True"
                and all(condition(worker_state, key) == "False" for key in PRESSURE_CONDITIONS))

    receipts = {}
    for signal, label, pressure in SIGNALS:
        name = f"saf-pressure-{label}"
        wait(lab, normal, f"ready worker and restored original map before {signal}", 90)
        fixture = lab.create(pod(name, [container("marker", resources={
            "requests": {"cpu": "5m", "memory": "2Mi", "ephemeral-storage": "1Mi"},
            "limits": {"cpu": "20m", "memory": "24Mi", "ephemeral-storage": "8Mi"},
        })], nodeName=worker, terminationGracePeriodSeconds=1,
                                   automountServiceAccountToken=False))
        ready(lab, name)
        observed = json.loads(lab.kubectl("get", raw_path).stdout)["node"]
        available, capacity = headroom(signal, observed)
        if not 0 < available < capacity - 2 or available * 10 < capacity:
            lab.block(f"Expected ample real headroom and a measurable used margin for {signal}")
        # Move only the node's synthetic comparison threshold. The fixture
        # never fills the filesystem or spawns a PID or inode load.
        threshold = capacity - min((capacity - available) // 4, 1024 * 1024 * 1024)
        expected = {**original_hard, signal: str(threshold)}
        if original_merge:
            lab.block("The isolated one-signal replay needs the pinned non-merging baseline")
        lab.check("red", f"{signal} baseline has a Ready fixture with pressure clear",
                  condition(current(), pressure) == "False" and threshold > available,
                  {"baseline_condition_clear": True, "threshold_crossable_without_load": threshold > available})
        try:
            write_config(lab, worker, with_merge_fixture(source, expected, False))

            def active():
                effective = configz(lab, worker)
                return effective and effective["evictionHard"] == expected

            wait(lab, active, f"the expected full threshold map for {signal}")

            def pressured():
                state = current()
                if condition(state, pressure) == "True":
                    return state
                return None

            state = wait(lab, pressured, f"native {pressure} from {signal}", 75)
            # Direct node placement lets the probe reach kubelet admission even
            # though the default scheduler also excludes the pressured node.
            new_name = f"{name}-while-pressured"
            challenger = lab.create(pod(new_name, [container("marker")], nodeName=worker,
                                        terminationGracePeriodSeconds=1, automountServiceAccountToken=False))

            def rejected():
                result = read(lab, "get", "pod", new_name)
                return result if result["status"].get("reason") == "Evicted" else None

            denied = wait(lab, rejected, f"kubelet admission denial for {signal}", 45)
            message = denied["status"].get("message", "")
            specific_denial = f"The node had condition: [{pressure}]." in message
            same_pod = denied["metadata"]["uid"] == challenger["metadata"]["uid"]
            only_selected = all(condition(state, key) == "False" for key in PRESSURE_CONDITIONS if key != pressure)
            api_ready = lab.kubectl("get", "--raw=/readyz").stdout.strip() == "ok"
            lab.check("green", f"{signal} raises the native condition and blocks admission of a bound Pod",
                      same_pod and specific_denial and only_selected and api_ready,
                      {"pressure_condition": pressure, "same_challenge_uid": same_pod,
                       "specific_kubelet_admission_denial": specific_denial,
                       "selected_condition_only": only_selected, "api_ready": api_ready})
        except Exception:
            lab.command("docker", "exec", worker, "journalctl", "-u", "kubelet", "-n", "65",
                        "--no-pager", allow_failure=True)
            raise
        finally:
            write_config(lab, worker, source)

        wait(lab, normal, f"original thresholds and healthy condition after {signal}", 90)
        recovery_name = f"{name}-recovery"
        recovery = lab.create(pod(recovery_name, [container("marker")], nodeName=worker,
                                  terminationGracePeriodSeconds=1, automountServiceAccountToken=False))
        ready(lab, recovery_name)
        actual = read(lab, "get", "pod", recovery_name)
        healthy = actual["metadata"]["uid"] == recovery["metadata"]["uid"] and actual["status"]["phase"] == "Running"
        lab.check("positive", f"Restoring the baseline after {signal} clears pressure and permits a fresh Pod",
                  healthy and normal(), {"original_thresholds_restored": True, "fresh_pod_ready": healthy})
        lab.kubectl("delete", "pod", recovery_name, name, "--wait=true")
        receipts[signal] = {"available_before": available, "capacity": capacity, "threshold": threshold,
                            "ready_baseline_uid": fixture["metadata"]["uid"],
                            "challenger_uid": challenger["metadata"]["uid"], "rejected_uid": denied["metadata"]["uid"],
                            "node_uid": worker_uid, "pressure_condition": pressure, "message": message,
                            "recovery_uid": recovery["metadata"]["uid"], "recovered": healthy}
    return receipts


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
    merge_evidence = verify_default_merge(lab, worker, source, initial_config)

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
    lab.create(pod(replacement_name, [container("marker")], nodeName=worker,
                   terminationGracePeriodSeconds=1, automountServiceAccountToken=False))
    lab.kubectl("wait","--for=condition=Ready",f"pod/{replacement_name}","--timeout=60s",timeout=75)
    accepted = read(lab,"get","pod",replacement_name)
    lab.check("positive", "The restored worker runs a permitted workload without MemoryPressure",
              restored and accepted["status"]["phase"] == "Running",
              {"original_thresholds_restored": restored,"ordinary_pod_running": accepted["status"]["phase"] == "Running"})
    lab.kubectl("delete", "pod", replacement_name, "--wait=true")
    other_signals = exercise_pressure_signals(lab, worker, source, initial_config, before)
    (lab.evidence/"hard-eviction.raw.json").write_text(json.dumps({
        "threshold":configured,"available_before_bytes":available,"baseline":initial_hard,"eviction_message":action["message"],
        "elapsed_seconds":round(elapsed,3),"pod_grace_seconds":grace,
        "pdb_disruptions_allowed_before":budget["disruptionsAllowed"],"restored":restored,
        "effective_merge_check": merge_evidence,
        "additional_native_signals": other_signals,
    },indent=2)+"\n")
