"""Verify inert etcd and PVC backup fixtures in a disposable Kind cluster."""
import base64
import hashlib
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
FIXTURE = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
IMAGE = FIXTURE["image"]
NS = FIXTURE["namespace"]
ETCD_SNAPSHOT = "/tmp/saf-1005-029-snapshot.db"
ETCD_RESTORE_DIR = "/tmp/saf-1005-029-restored"
RESTORE_CLIENT = "http://127.0.0.1:12379"
RESTORE_PEER = "http://127.0.0.1:12380"
SCOPE = (
    "One disposable Kind Kubernetes v1.36.1 cluster. The case writes one reserved-placeholder "
    "key to the cluster's own etcd, creates and inspects an etcd snapshot, checks a missing "
    "incomplete snapshot fails, restores the snapshot into an isolated loopback-only etcd "
    "member, and reads back the exact synthetic key. A digest-pinned Python Job writes an "
    "inert marker to a PVC, archives and verifies it, rejects corrupted/incomplete archives, "
    "and a separate Pod independently reads the restored exact bytes. Snapshot contents and "
    "Kubernetes object dumps are never written to evidence. No production data or secrets "
    "are inputs. This does not validate production backup infrastructure or recovery outcomes."
)


def get_json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def create(lab, resource, namespace=None):
    args = ("-n", namespace) if namespace else ()
    return lab.kubectl(*args, "create", "-f", "-", payload=json.dumps(resource))


def etcd_container(lab):
    pods = get_json(lab, "-n", "kube-system", "get", "pods", "-l", "component=etcd")
    matches = [p for p in pods["items"] if p["metadata"]["name"].startswith("etcd-")]
    if len(matches) != 1:
        lab.block(f"Expected one disposable control-plane etcd Pod; saw {len(matches)}")
    node = matches[0]["spec"]["nodeName"]
    if node != f"{lab.cluster}-control-plane" or matches[0]["metadata"]["name"] != f"etcd-{node}":
        lab.block("Backup target does not match the disposable control-plane fixture")
    ids = lab.command("docker", "exec", node, "crictl", "ps", "-q", "--name", "etcd").stdout.split()
    if len(ids) != 1:
        lab.block(f"Expected one running etcd container on owned Kind node; saw {len(ids)}")
    return node, ids[0]


def in_etcd(lab, node, container_id, executable, *args, allow_failure=False):
    return lab.command("docker", "exec", node, "crictl", "exec", container_id,
                       executable, *args, allow_failure=allow_failure)


def etcdctl_args(endpoint, key=None, operation=None):
    certs = ("--endpoints=" + endpoint,)
    if endpoint.startswith("https:"):
        certs += ("--cacert=/etc/kubernetes/pki/etcd/ca.crt",
                  "--cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt",
                  "--key=/etc/kubernetes/pki/etcd/healthcheck-client.key")
    if operation == "put":
        return certs + ("put", key)
    if operation == "get":
        return certs + ("get", key, "--print-value-only")
    if operation == "snapshot":
        return certs + ("snapshot", "save", ETCD_SNAPSHOT)
    raise ValueError("unknown etcdctl operation")


def verify_etcd(lab):
    node, cid = etcd_container(lab)
    key = FIXTURE["etcd_key"]
    marker = FIXTURE["marker_utf8"]
    live = "https://127.0.0.1:2379"
    # etcdctl put's value is positional and intentionally public fixture text.
    in_etcd(lab, node, cid, "etcdctl", *etcdctl_args(live, key, "put"), marker)
    in_etcd(lab, node, cid, "etcdctl", *etcdctl_args(live, operation="snapshot"))
    status = in_etcd(lab, node, cid, "etcdutl", "--write-out=json", "snapshot", "status", ETCD_SNAPSHOT)
    try:
        status_json = json.loads(status.stdout)
    except json.JSONDecodeError:
        lab.block("etcdutl did not return JSON snapshot status")

    missing_path = "/tmp/saf-1005-029-absent.db"
    missing = in_etcd(lab, node, cid, "etcdutl", "--write-out=json", "snapshot", "status", missing_path,
                      allow_failure=True)
    incomplete_rejected = (missing.returncode != 0 and missing_path in missing.stderr
                           and "no such file" in missing.stderr)
    lab.check("red", "An absent etcd backup fails offline status verification",
              incomplete_rejected, {"returncode": missing.returncode, "input": "absent snapshot"})

    restored = in_etcd(lab, node, cid, "etcdutl", "snapshot", "restore", ETCD_SNAPSHOT,
                       "--name=" + FIXTURE["etcd_restore_name"],
                       "--initial-cluster=" + FIXTURE["etcd_restore_name"] + "=" + RESTORE_PEER,
                       "--initial-advertise-peer-urls=" + RESTORE_PEER,
                       "--data-dir=" + ETCD_RESTORE_DIR)
    # The detached restored process stays inside this disposable cluster's etcd
    # container and is removed with the cluster. It binds only to loopback.
    lab.command("docker", "exec", "-d", node, "crictl", "exec", cid, "etcd",
                           "--name=" + FIXTURE["etcd_restore_name"],
                           "--data-dir=" + ETCD_RESTORE_DIR,
                           "--listen-client-urls=" + RESTORE_CLIENT,
                           "--advertise-client-urls=" + RESTORE_CLIENT,
                           "--listen-peer-urls=" + RESTORE_PEER,
                           "--initial-advertise-peer-urls=" + RESTORE_PEER,
                           "--initial-cluster=" + FIXTURE["etcd_restore_name"] + "=" + RESTORE_PEER,
                           "--initial-cluster-state=new")
    value = None
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        health = in_etcd(lab, node, cid, "etcdctl", "--endpoints=" + RESTORE_CLIENT,
                         "--dial-timeout=2s", "--command-timeout=3s",
                         "endpoint", "health", allow_failure=True)
        if health.returncode == 0:
            readback = in_etcd(lab, node, cid, "etcdctl", "--endpoints=" + RESTORE_CLIENT,
                               "--dial-timeout=2s", "--command-timeout=3s",
                               "get", key, "--print-value-only", allow_failure=True)
            if readback.returncode == 0:
                value = readback.stdout.removesuffix("\n")
                break
        time.sleep(0.5)
    exact = value == marker
    lab.check("green", "A digest-statused etcd snapshot restores into a separate local data directory",
              isinstance(status_json, dict) and status_json.get("revision", 0) > 0
              and restored.returncode == 0,
              {"snapshot_revision_present": status_json.get("revision", 0) > 0,
               "restored_to_separate_data_directory": restored.returncode == 0})
    lab.check("positive", "The isolated restored etcd member returns the exact synthetic marker bytes",
              exact, {"key": key, "expected_bytes": len(marker.encode()),
                      "observed_bytes": len(value.encode()) if value is not None else None,
                      "sha256": hashlib.sha256(value.encode()).hexdigest() if value is not None else None,
                      "marker_sha256": hashlib.sha256(marker.encode()).hexdigest(),
                      "marker_utf8": marker})
    (lab.evidence / "etcd-backup-observation.raw.json").write_text(
        json.dumps({"fixture": FIXTURE["control_id"], "snapshot_status": status_json,
                    "incomplete_snapshot_rejected": incomplete_rejected,
                    "incomplete_snapshot_error": missing.stderr.strip()[:300],
                    "restore_exit": restored.returncode,
                    "restored_marker": {"key": key, "exact": exact,
                                        "bytes": len(value.encode()) if value is not None else None,
                                        "sha256": hashlib.sha256(value.encode()).hexdigest()
                                        if value is not None else None},
                    "expected_marker": {"bytes": len(marker.encode()),
                                        "sha256": hashlib.sha256(marker.encode()).hexdigest()}},
                   sort_keys=True, indent=2) + "\n", encoding="utf-8")


def verify_workload(lab):
    ns = NS
    lab.kubectl("create", "namespace", ns)
    pvc = {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
           "metadata": {"name": FIXTURE["pvc_name"], "namespace": ns},
           "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "128Mi"}}}}
    create(lab, pvc, ns)
    script_cm = {"apiVersion": "v1", "kind": "ConfigMap",
                 "metadata": {"name": "saf-1005-029-backup-script", "namespace": ns},
                 "data": {"workload_backup.py": (HERE / "workload_backup.py").read_text(encoding="utf-8")}}
    create(lab, script_cm, ns)
    marker = FIXTURE["marker_utf8"].encode()
    job_name = "saf-1005-029-backup-job"
    job = {"apiVersion": "batch/v1", "kind": "Job",
           "metadata": {"name": job_name, "namespace": ns,
                        "labels": {"saf.example/control-id": FIXTURE["control_id"],
                                   "saf.example/fixture": "synthetic-only"}},
           "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90,
                    "ttlSecondsAfterFinished": 300,
                    "template": {"metadata": {"labels": {"app": job_name}},
                                 "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                                          "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                                              "runAsGroup": 10001, "fsGroup": 10001,
                                                              "seccompProfile": {"type": "RuntimeDefault"}},
                                          "containers": [{"name": "backup", "image": IMAGE,
                                                          "imagePullPolicy": "IfNotPresent",
                                                          "command": ["python", "/case/workload_backup.py"],
                                                          "env": [{"name": "MARKER_NAME", "value": FIXTURE["marker_name"]},
                                                                  {"name": "MARKER_B64", "value": base64.b64encode(marker).decode("ascii")}],
                                                          "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                                                        "limits": {"cpu": "100m", "memory": "96Mi"}},
                                                          "securityContext": {"allowPrivilegeEscalation": False,
                                                                              "readOnlyRootFilesystem": True,
                                                                              "capabilities": {"drop": ["ALL"]}},
                                                          "volumeMounts": [{"name": "data", "mountPath": "/data"},
                                                                           {"name": "script", "mountPath": "/case", "readOnly": True}]}],
                                          "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": FIXTURE["pvc_name"]}},
                                                      {"name": "script", "configMap": {"name": script_cm["metadata"]["name"], "defaultMode": 292}}]}}}}
    create(lab, job, ns)
    lab.kubectl("-n", ns, "wait", "--for=condition=Complete", "job/" + job_name,
                "--timeout=120s", timeout=130)
    pods = get_json(lab, "-n", ns, "get", "pods", "-l", "batch.kubernetes.io/job-name=" + job_name)["items"]
    if len(pods) != 1:
        lab.block(f"Expected one completed backup Job Pod; saw {len(pods)}")
    output = lab.kubectl("-n", ns, "logs", pods[0]["metadata"]["name"]).stdout.strip()
    result = json.loads(output)
    expected_sha = hashlib.sha256(marker).hexdigest()
    red_ok = (result["corrupt_backup"]["valid"] is False
              and result["corrupt_backup"]["reason"] == "marker-mismatch"
              and result["incomplete_backup"]["valid"] is False
              and result["incomplete_backup"]["reason"] == "incomplete-or-unexpected-members")
    lab.check("red", "Corrupted and incomplete workload archives both fail verification",
              red_ok, {"corrupt": result["corrupt_backup"], "incomplete": result["incomplete_backup"]})
    green_ok = (result["valid_backup"]["valid"] is True
                and result["valid_backup"]["sha256"] == expected_sha
                and result["source_sha256"] == expected_sha)
    lab.check("green", "The complete workload backup validates against the exact synthetic marker digest",
              green_ok, {"valid_backup": result["valid_backup"],
                         "source_sha256": result["source_sha256"], "expected_sha256": expected_sha})

    reader_code = ("import hashlib,pathlib; "
                   f"p=pathlib.Path('/data/restore')/{FIXTURE['marker_name']!r}; "
                   "b=p.read_bytes(); print(hashlib.sha256(b).hexdigest(),len(b),flush=True)")
    reader = {"apiVersion": "v1", "kind": "Pod",
              "metadata": {"name": "saf-1005-029-independent-reader", "namespace": ns},
              "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                       "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                                           "seccompProfile": {"type": "RuntimeDefault"}},
                       "containers": [{"name": "reader", "image": IMAGE,
                                       "imagePullPolicy": "IfNotPresent",
                                       "command": ["python", "-c", reader_code],
                                       "securityContext": {"allowPrivilegeEscalation": False,
                                                           "readOnlyRootFilesystem": True,
                                                           "capabilities": {"drop": ["ALL"]}},
                                       "volumeMounts": [{"name": "data", "mountPath": "/data", "readOnly": True}],
                                       "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                                     "limits": {"cpu": "100m", "memory": "64Mi"}}}],
                       "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": FIXTURE["pvc_name"]}}]}}
    create(lab, reader, ns)
    lab.kubectl("-n", ns, "wait", "--for=jsonpath={.status.phase}=Succeeded", "pod/" + reader["metadata"]["name"],
                "--timeout=90s", timeout=100)
    raw = lab.kubectl("-n", ns, "logs", reader["metadata"]["name"]).stdout.strip()
    fields = raw.split()
    if len(fields) != 2 or not fields[1].isdecimal():
        lab.block("Independent reader did not emit one hash and byte count")
    seen_sha, seen_bytes = fields
    restored_ok = (result["restored_exact"] is True and result["restored_sha256"] == expected_sha
                   and seen_sha == expected_sha and int(seen_bytes) == len(marker))
    lab.check("positive", "A separate Pod independently observes the exact restored marker bytes on the PVC",
              restored_ok, {"sha256": seen_sha, "bytes": int(seen_bytes),
                            "expected_sha256": expected_sha, "expected_bytes": len(marker),
                            "reader_pod": reader["metadata"]["name"],
                            "backup_verifier_restored_exact": result["restored_exact"]})
    (lab.evidence / "workload-backup-observation.raw.json").write_text(
        json.dumps({"fixture": FIXTURE["control_id"], "job_output": result,
                    "independent_reader": {"sha256": seen_sha, "bytes": int(seen_bytes)},
                    "expected_marker_sha256": expected_sha, "expected_marker_bytes": len(marker)},
                   sort_keys=True, indent=2) + "\n", encoding="utf-8")


def run(lab):
    version = json.loads(lab.kubectl("get", "--raw=/version").stdout)
    git_version = version.get("gitVersion")
    lab.check("positive", "The disposable API server is Kubernetes v1.36.1",
              git_version == "v1.36.1", {"gitVersion": git_version})
    verify_etcd(lab)
    verify_workload(lab)
