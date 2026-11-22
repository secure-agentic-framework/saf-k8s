"""Compare PVC Unused-condition telemetry in two disposable clusters."""

import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time
import uuid


VERSIONS = (
    {
        "version": "v1.36.1",
        "image": "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5",
        "expect_condition": False,
    },
    {
        "version": "v1.37.0",
        "image": "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5",
        "expect_condition": True,
    },
)
WORKLOAD_IMAGE = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
NAMESPACE = "saf-release-review-15"
PVC = "retained-data"
PV = "saf-release-review-15-retained"
MARKER = "saf-k8s-release-review-15-marker-v1"
CONDITION = "Unused"
CONDITION_GATE = "PersistentVolumeClaimUnusedSinceTime"


class RunnerError(RuntimeError):
    pass


class Cluster:
    def __init__(self, context, kubeconfig, evidence, version):
        self.context = context
        self.kubeconfig = kubeconfig
        self.evidence = evidence
        self.name = f"saf-rv15-{version['version'].replace('.', '-')}-{uuid.uuid4().hex[:8]}"
        self.env = dict(os.environ)
        for key in ("DOCKER_HOST", "KIND_CLUSTER_NAME", "KUBECONFIG", "KUBERNETES_MASTER"):
            self.env.pop(key, None)
        self.env.update(DOCKER_CONTEXT=context, KIND_EXPERIMENTAL_PROVIDER="docker")

    def command(self, *args, payload=None, timeout=60, allow_failure=False):
        with (self.evidence / "commands.log").open("a", encoding="utf-8") as log:
            log.write(f"$ {shlex.join([str(arg) for arg in args])}\n")
            if payload is not None:
                log.write(payload + "\n")
            try:
                proc = subprocess.run(args, input=payload, text=True, capture_output=True,
                                      env=self.env, timeout=timeout)
            except (OSError, subprocess.TimeoutExpired) as error:
                log.write(f"{error}\n")
                raise RunnerError(str(error)) from error
            log.write(proc.stdout + proc.stderr + f"\n[exit {proc.returncode}]\n\n")
        if proc.returncode and not allow_failure:
            raise RunnerError(f"{args[0]} failed: {proc.stderr.strip() or proc.stdout.strip()}")
        return proc

    def kubectl(self, *args, timeout=60, **kwargs):
        return self.command("kubectl", "--kubeconfig", str(self.kubeconfig), "--context",
                            f"kind-{self.name}", "--namespace", NAMESPACE,
                            f"--request-timeout={timeout - 5}s", *args, timeout=timeout, **kwargs)

    def get_json(self, *args):
        return json.loads(self.kubectl("get", *args, "-o", "json").stdout)


def condition(pvc):
    return next((row for row in pvc.get("status", {}).get("conditions", [])
                 if row.get("type") == CONDITION), None)


def references(cluster):
    pods = cluster.get_json("pods").get("items", [])
    return sorted({pod["metadata"]["name"] for pod in pods
                   if pod.get("status", {}).get("phase") not in ("Succeeded", "Failed")
                   and any(volume.get("persistentVolumeClaim", {}).get("claimName") == PVC
                           for volume in pod.get("spec", {}).get("volumes", []))})


def snapshot(cluster, label, expect_condition, expected_state=None, expected_reason=None,
             expected_refs=None, marker_readback=None, previous_time=None):
    deadline = time.monotonic() + 90
    while True:
        pvc = cluster.get_json("pvc", PVC)
        pod_refs = references(cluster)
        observed = condition(pvc)
        ok = True
        if expect_condition:
            ok = (observed is not None and observed.get("status") == expected_state
                  and observed.get("reason") == expected_reason
                  and bool(observed.get("lastTransitionTime")))
        else:
            ok = observed is None
        if expected_refs is not None:
            ok = ok and pod_refs == expected_refs
        if ok:
            break
        if time.monotonic() >= deadline:
            raise RunnerError(f"Timed out waiting for {label}: condition={observed}, refs={pod_refs}")
        time.sleep(0.5)

    pv = cluster.get_json("pv", PV)
    if pvc["status"].get("phase") != "Bound" or pvc["spec"].get("volumeName") != PV:
        raise RunnerError(f"PVC lost its bound PV at {label}")
    if pv["spec"].get("persistentVolumeReclaimPolicy") != "Retain":
        raise RunnerError(f"Fixture PV is not Retain at {label}")
    if marker_readback is not None and marker_readback != MARKER:
        raise RunnerError(f"Marker changed or was unreadable at {label}: {marker_readback!r}")
    if expected_refs is not None and pod_refs != expected_refs:
        raise RunnerError(f"Unexpected non-terminal references at {label}: {pod_refs}")
    phases = {item["metadata"]["name"]: item.get("status", {}).get("phase")
              for item in cluster.get_json("pods").get("items", [])}
    if expected_refs and any(phases.get(name) != "Running" for name in expected_refs):
        raise RunnerError(f"Referencing Pod is not Running at {label}: {phases}")
    now = observed.get("lastTransitionTime") if observed else None
    if previous_time and (not now or now <= previous_time):
        raise RunnerError(f"lastTransitionTime did not advance at {label}: {previous_time} -> {now}")
    return {
        "label": label,
        "pvc_uid": pvc["metadata"]["uid"],
        "pv_name": pv["metadata"]["name"],
        "pv_uid": pv["metadata"]["uid"],
        "reclaim_policy": pv["spec"]["persistentVolumeReclaimPolicy"],
        "phase": pvc["status"].get("phase"),
        "pod_references": pod_refs,
        "pod_phases": phases,
        "marker_readback": marker_readback,
        "unused_condition": observed,
        "last_transition_time_advanced": bool(previous_time and now and now > previous_time),
    }


def pod_doc(name, command, *, root=False):
    security = {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                "seccompProfile": {"type": "RuntimeDefault"}}
    if not root:
        security.update(runAsNonRoot=True, runAsUser=65534)
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "labels": {"saf-k8s-case": "release-review-15"}},
        "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False, "containers": [{
            "name": "probe", "image": WORKLOAD_IMAGE, "command": ["sh", "-c", command],
            "securityContext": security,
            "volumeMounts": [{"name": "data", "mountPath": "/data", "readOnly": not root}],
        }], "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": PVC}}]},
    }


def create_fixture(cluster):
    cluster.kubectl("create", "namespace", NAMESPACE)
    pv = {"apiVersion": "v1", "kind": "PersistentVolume", "metadata": {"name": PV,
          "labels": {"saf-k8s-case": "release-review-15"}},
          "spec": {"capacity": {"storage": "1Mi"}, "volumeMode": "Filesystem",
                   "accessModes": ["ReadWriteOnce"], "persistentVolumeReclaimPolicy": "Retain",
                   "storageClassName": "", "hostPath": {"path": "/tmp/saf-release-review-15",
                   "type": "DirectoryOrCreate"}}}
    pvc = {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
           "metadata": {"name": PVC, "labels": {"saf-k8s-case": "release-review-15"}},
           "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": "", "volumeName": PV,
                    "resources": {"requests": {"storage": "1Mi"}}}}
    for item in (pv, pvc):
        cluster.kubectl("create", "-f", "-", payload=json.dumps(item))
    cluster.kubectl("wait", "--for=jsonpath={.status.phase}=Bound", f"pvc/{PVC}",
                     "--timeout=90s", timeout=100)

    seed_command = f"printf '%s' '{MARKER}' > /data/marker"
    cluster.kubectl("create", "-f", "-", payload=json.dumps(pod_doc("seed-marker", seed_command, root=True)))
    cluster.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", "pod/seed-marker",
                     "--timeout=90s", timeout=100)
    cluster.kubectl("delete", "pod", "seed-marker", "--wait=true", "--timeout=45s")


def read_marker(cluster, pod_name):
    command = "test \"$(cat /data/marker)\" = \"" + MARKER + "\" && sleep 3600"
    cluster.kubectl("create", "-f", "-", payload=json.dumps(pod_doc(pod_name, command)))
    cluster.kubectl("wait", "--for=condition=Ready", f"pod/{pod_name}", "--timeout=90s", timeout=100)
    value = cluster.kubectl("exec", pod_name, "--", "cat", "/data/marker").stdout.strip()
    return value


def run_version(context, output_root, version):
    evidence = output_root / version["version"]
    evidence.mkdir(parents=True, exist_ok=False)
    record = {"version": version["version"], "node_image": version["image"],
              "workload_image": WORKLOAD_IMAGE,
              "scope": "Disposable kind; native PVC Unused condition and retained fixture marker only.",
              "feature_gate_override": None, "checkpoints": []}
    with tempfile.TemporaryDirectory(prefix="saf-rv15-") as temporary:
        cluster = Cluster(context, Path(temporary) / "kubeconfig", evidence, version)
        record["cluster"] = cluster.name
        created = False
        try:
            endpoint = cluster.command("docker", "context", "inspect", context,
                                       "--format", "{{.Endpoints.docker.Host}}").stdout.strip()
            if not endpoint.startswith("unix://"):
                raise RunnerError(f"Choose a local Docker Unix socket context; found {endpoint!r}")
            cluster.command("kind", "version")
            existing = cluster.command("kind", "get", "clusters").stdout.splitlines()
            if cluster.name in existing:
                raise RunnerError(f"Random cluster name collision: {cluster.name}")
            created = True
            cluster.command("kind", "create", "cluster", "--name", cluster.name,
                            "--image", version["image"], "--kubeconfig", str(cluster.kubeconfig),
                            "--wait", "90s", timeout=480)
            server = json.loads(cluster.kubectl("version", "-o", "json").stdout)
            record["server_version"] = server
            if server.get("serverVersion", {}).get("gitVersion") != version["version"]:
                raise RunnerError("API server version differs from the pinned comparison version")
            nodes = cluster.get_json("nodes")
            record["node_versions"] = [item["status"]["nodeInfo"]["kubeletVersion"]
                                       for item in nodes.get("items", [])]
            if record["node_versions"] != [version["version"]]:
                raise RunnerError(f"Unexpected kubelet versions: {record['node_versions']}")
            record["controller_gate_args"] = {}
            for component in ("kube-apiserver", "kube-controller-manager"):
                pods = json.loads(cluster.kubectl("-n", "kube-system", "get", "pods",
                                                   "-l", f"component={component}", "-o", "json").stdout)
                if len(pods.get("items", [])) != 1:
                    raise RunnerError(f"Expected one {component} static Pod")
                args = pods["items"][0]["spec"]["containers"][0].get("args", [])
                record["controller_gate_args"][component] = args
                if any(CONDITION_GATE in arg for arg in args):
                    raise RunnerError(f"An explicit {CONDITION_GATE} override was found in {component} args")
            create_fixture(cluster)

            idle = snapshot(cluster, "initial_idle_after_seed_removal", version["expect_condition"],
                            "True", "NoPodsUsingPVC", [])
            idle["marker_seeded_by"] = "seed-marker Pod; command exited successfully"
            record["checkpoints"].append(idle)

            time.sleep(1.1)
            first_marker = read_marker(cluster, "first-reference")
            first = snapshot(cluster, "first_running_reference", version["expect_condition"],
                             "False", "PodUsingPVC", ["first-reference"], first_marker,
                             (idle["unused_condition"] or {}).get("lastTransitionTime"))
            record["checkpoints"].append(first)

            time.sleep(1.1)
            cluster.kubectl("delete", "pod", "first-reference", "--wait=true", "--timeout=45s")
            no_ref = snapshot(cluster, "only_reference_pod_removed", version["expect_condition"],
                              "True", "NoPodsUsingPVC", [],
                              None, (first["unused_condition"] or {}).get("lastTransitionTime"))
            record["checkpoints"].append(no_ref)

            time.sleep(1.1)
            second_marker = read_marker(cluster, "second-reference")
            second = snapshot(cluster, "second_running_reference", version["expect_condition"],
                              "False", "PodUsingPVC", ["second-reference"], second_marker,
                              (no_ref["unused_condition"] or {}).get("lastTransitionTime"))
            record["checkpoints"].append(second)
            ids = {(row["pvc_uid"], row["pv_uid"], row["pv_name"], row["reclaim_policy"])
                   for row in record["checkpoints"]}
            marker_reads = [row["marker_readback"] for row in record["checkpoints"]
                            if row["marker_readback"] is not None]
            if len(ids) != 1 or marker_reads != [MARKER, MARKER]:
                raise RunnerError("PVC/PV identity, Retain policy, or mounted marker observations changed")
            record["status"] = "passed"
        except Exception as error:
            record.update(status="blocked" if isinstance(error, RunnerError) else "error", error=str(error))
            raise
        finally:
            if created:
                try:
                    cluster.command("kind", "delete", "cluster", "--name", cluster.name,
                                    "--kubeconfig", str(cluster.kubeconfig), timeout=120)
                    record["cluster_cleanup"] = "deleted"
                except Exception as error:
                    record["cluster_cleanup"] = f"failed: {error}"
            (evidence / "result.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker-context", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    results = []
    for version in VERSIONS:
        results.append(run_version(args.docker_context, output, version))
    summary = {"comparison": "v1.36.1 default-off vs v1.37.0 default-on",
               "results": [{"version": row["version"], "status": row["status"],
                            "cluster": row["cluster"], "cluster_cleanup": row.get("cluster_cleanup")}
                           for row in results]}
    (output / "comparison.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0 if all(row.get("cluster_cleanup") == "deleted" for row in results) else 3


if __name__ == "__main__":
    raise SystemExit(main())
