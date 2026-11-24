"""Observe etcd history compaction and scheduled per-member defragmentation."""
import json
import time
from datetime import datetime, timezone
from pathlib import Path

ETCD_IMAGE = "gcr.io/etcd-development/etcd:v3.6.8@sha256:397189418d1a00e500c0605ad18d1baf3b541a1004d768448c367e48071622e5"
PYTHON_IMAGE = "python:3.9.25-slim-bookworm@sha256:a02e9c5406c416c504d6c9a1a306ff4080c3173f1008d192f953bd20382a2d5c"
NAMESPACE = "saf-etcd-fixture"
CRONJOB = "etcd-sequential-defrag"
CRONJOB_SCHEDULE = "* * * * *"
CRONJOB_WINDOW_SECONDS = 180
RAW_EVIDENCE_FILE = "etcd-cluster-maintenance.raw.json"
SCHEDULED_TIMESTAMP_ANNOTATION = "batch.kubernetes.io/cronjob-scheduled-timestamp"
SCOPE = (
    "Three disposable etcd 3.6.8 members in one dedicated namespace in the fresh Kind lab cluster, "
    "with emptyDir data only and synthetic keys. Periodic auto-compaction and a controller-scheduled, "
    "bounded every-minute CronJob are exercised. The scheduled job compacts and defragments only these "
    "members, sequentially, after endpoint health, same-cluster membership and leader checks; it checks "
    "a separate member for marker reads after each local defrag. A forced endpoint-health failure runs "
    "the same maintenance function and must issue zero defrag commands. The fixture does not access the "
    "Kind control-plane etcd, real workloads or provider-managed settings. Deployed/provider obligations "
    "remain separate evidence."
)


def kubectl(lab, *args, payload=None, timeout=45, allow_failure=False):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", "kind-" + lab.cluster,
        "--namespace", NAMESPACE, *args, payload=payload, timeout=timeout,
        allow_failure=allow_failure,
    )


def record_raw_evidence(lab, name, value):
    path = lab.evidence / RAW_EVIDENCE_FILE
    data = json.loads(path.read_text()) if path.exists() else {}
    data[name] = value
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def resource_version(resource):
    return json.dumps(resource, sort_keys=True, separators=(",", ":"))


def create_resource(lab, resource):
    kubectl(lab, "create", "-f", "-", "-o", "json", payload=resource_version(resource))


def wait_pods_ready(lab):
    kubectl(lab, "rollout", "status", "statefulset/etcd", "--timeout=180s", timeout=190)
    result = kubectl(lab, "get", "pods", "-l", "app=etcd", "-o", "json")
    pods = json.loads(result.stdout).get("items", [])
    ready = [p for p in pods if p.get("status", {}).get("phase") == "Running"
             and any(c.get("type") == "Ready" and c.get("status") == "True"
                     for c in p.get("status", {}).get("conditions", []))]
    lab.check("positive", "The dedicated synthetic etcd StatefulSet has three ready members",
              len(pods) == 3 and len(ready) == 3,
              {"three_members_ready": len(pods) == 3 and len(ready) == 3})


def etcd_statefulset():
    names = ["etcd-0", "etcd-1", "etcd-2"]
    peer_urls = ["http://%s.etcd.%s.svc.cluster.local:2380" % (n, NAMESPACE) for n in names]
    client_url = "http://$(POD_NAME).etcd.%s.svc.cluster.local:2379" % NAMESPACE
    args = [
        "--name=$(POD_NAME)", "--data-dir=/etcd-data",
        "--listen-client-urls=http://0.0.0.0:2379", "--advertise-client-urls=" + client_url,
        "--listen-peer-urls=http://0.0.0.0:2380", "--initial-advertise-peer-urls=http://$(POD_NAME).etcd.%s.svc.cluster.local:2380" % NAMESPACE,
        "--initial-cluster=" + ",".join("%s=%s" % (n, url) for n, url in zip(names, peer_urls)),
        "--initial-cluster-state=new", "--initial-cluster-token=saf-k8s-0102-013-disposable",
        "--auto-compaction-mode=periodic", "--auto-compaction-retention=10s",
    ]
    return {
        "apiVersion": "apps/v1", "kind": "StatefulSet",
        "metadata": {"name": "etcd", "namespace": NAMESPACE},
        "spec": {
            "serviceName": "etcd", "replicas": 3, "podManagementPolicy": "Parallel",
            "selector": {"matchLabels": {"app": "etcd"}},
            "template": {
                "metadata": {"labels": {"app": "etcd"}},
                "spec": {
                    "terminationGracePeriodSeconds": 20,
                    "containers": [{
                        "name": "etcd", "image": ETCD_IMAGE, "imagePullPolicy": "IfNotPresent",
                        "command": ["/usr/local/bin/etcd"], "args": args,
                        "env": [{"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}}],
                        "ports": [{"name": "client", "containerPort": 2379}, {"name": "peer", "containerPort": 2380}],
                        "readinessProbe": {"exec": {"command": ["/usr/local/bin/etcdctl", "--endpoints=http://127.0.0.1:2379", "endpoint", "health"]},
                                           "initialDelaySeconds": 2, "periodSeconds": 2, "timeoutSeconds": 2, "failureThreshold": 15},
                        "resources": {"requests": {"cpu": "50m", "memory": "64Mi"},
                                      "limits": {"cpu": "500m", "memory": "256Mi"}},
                        "volumeMounts": [{"name": "data", "mountPath": "/etcd-data"}],
                    }],
                    "volumes": [{"name": "data", "emptyDir": {"sizeLimit": "512Mi"}}],
                },
            },
        },
    }


def service():
    return {
        "apiVersion": "v1", "kind": "Service", "metadata": {"name": "etcd", "namespace": NAMESPACE},
        "spec": {"clusterIP": "None", "publishNotReadyAddresses": True,
                 "selector": {"app": "etcd"},
                 "ports": [{"name": "client", "port": 2379, "targetPort": 2379},
                           {"name": "peer", "port": 2380, "targetPort": 2380}]},
    }


def runner_pod_spec(script_name, args):
    return {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000},
        "initContainers": [{
            "name": "copy-pinned-etcdctl", "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
            "command": ["python3", "-c", "import os,shutil; shutil.copyfile('/etcd-image/usr/local/bin/etcdctl','/tools/etcdctl'); os.chmod('/tools/etcdctl',0o555)"],
            "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "runAsGroup": 1000},
            "volumeMounts": [{"name": "etcd-image", "mountPath": "/etcd-image", "readOnly": True},
                             {"name": "etcdctl", "mountPath": "/tools"}],
            "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                          "limits": {"cpu": "100m", "memory": "64Mi"}},
        }],
        "containers": [{
            "name": "fixture", "image": PYTHON_IMAGE, "imagePullPolicy": "IfNotPresent",
            "command": ["python3", "/opt/fixture/maintenance.py", "--mode", script_name] + args,
            "env": [{"name": "ETCDCTL", "value": "/tools/etcdctl"},
                    {"name": "ETCDCTL_API", "value": "3"},
                    {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
                    {"name": "SCHEDULED_TIMESTAMP", "valueFrom": {"fieldRef": {"fieldPath": "metadata.annotations['%s']" % SCHEDULED_TIMESTAMP_ANNOTATION}}}],
            "volumeMounts": [{"name": "etcdctl", "mountPath": "/tools", "readOnly": True},
                             {"name": "fixture-script", "mountPath": "/opt/fixture", "readOnly": True}],
            "resources": {"requests": {"cpu": "25m", "memory": "48Mi"},
                          "limits": {"cpu": "250m", "memory": "128Mi"}},
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
        }],
        "volumes": [{"name": "etcdctl", "emptyDir": {"sizeLimit": "64Mi"}},
                    {"name": "fixture-script", "configMap": {"name": "fixture-script", "defaultMode": 292}},
                    {"name": "etcd-image", "image": {"reference": ETCD_IMAGE, "pullPolicy": "IfNotPresent"}}],
    }


def probe_job(name, mode, args=None):
    return {
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 120,
                 "ttlSecondsAfterFinished": 3600,
                 "template": {"metadata": {"labels": {"app": "saf-etcd-fixture", "fixture-job": name}},
                              "spec": runner_pod_spec(mode, args or [])}},
    }


def scheduled_cronjob():
    pod = runner_pod_spec("scheduled", [])
    pod["containers"][0]["env"].append({"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}})
    return {
        "apiVersion": "batch/v1", "kind": "CronJob",
        "metadata": {"name": CRONJOB, "namespace": NAMESPACE},
        "spec": {
            "schedule": CRONJOB_SCHEDULE, "timeZone": "Etc/UTC", "suspend": False,
            "concurrencyPolicy": "Forbid", "startingDeadlineSeconds": 120,
            "successfulJobsHistoryLimit": 1, "failedJobsHistoryLimit": 1,
            "jobTemplate": {"spec": {
                "backoffLimit": 0, "activeDeadlineSeconds": CRONJOB_WINDOW_SECONDS,
                "ttlSecondsAfterFinished": 3600, "completions": 1, "parallelism": 1,
                "template": {"metadata": {"labels": {"app": "saf-etcd-fixture", "fixture-job": "scheduled"}},
                             "spec": pod},
            }},
        },
    }


def wait_job_logs(lab, name, timeout):
    deadline = time.monotonic() + timeout
    status = {}
    while time.monotonic() < deadline:
        state = json.loads(kubectl(lab, "get", "job", name, "-o", "json", timeout=15).stdout)
        status = state.get("status") or {}
        conditions = {item["type"] for item in status.get("conditions") or [] if item.get("status") == "True"}
        if "Complete" in conditions:
            return kubectl(lab, "logs", "job/" + name, timeout=30).stdout
        if "Failed" in conditions:
            break
        time.sleep(2)
    logs = kubectl(lab, "logs", "job/" + name, "--all-containers=true", allow_failure=True, timeout=20)
    kubectl(lab, "get", "pods", "-l", "job-name=" + name, "-o", "json", allow_failure=True, timeout=15)
    lab.block(f"etcd fixture Job {name} did not complete: {status}. {logs.stdout[-1800:]} {logs.stderr[-500:]}")


def run_job(lab, name, mode, args=None, timeout=150):
    create_resource(lab, probe_job(name, mode, args))
    logs = wait_job_logs(lab, name, timeout)
    record = parse_run_evidence(logs)
    record_raw_evidence(lab, name, {"logs": logs, "result": record})
    return record, logs


def parse_run_evidence(logs):
    for line in reversed(logs.splitlines()):
        if line.startswith("RUN_EVIDENCE "):
            return json.loads(line[len("RUN_EVIDENCE "):])
    raise RuntimeError("fixture Job did not emit structured RUN_EVIDENCE")


def cronjob_owned_jobs(lab, cronjob_uid):
    result = kubectl(lab, "get", "jobs", "-o", "json")
    jobs = json.loads(result.stdout).get("items", [])
    return [j for j in jobs if any(o.get("kind") == "CronJob" and o.get("uid") == cronjob_uid
                                    and o.get("controller") is True
                                    for o in j.get("metadata", {}).get("ownerReferences", []))]


def suspend_after_first_owned_job(lab, cronjob):
    uid = cronjob["metadata"]["uid"]
    deadline = time.monotonic() + CRONJOB_WINDOW_SECONDS
    found = None
    while time.monotonic() < deadline:
        owned = cronjob_owned_jobs(lab, uid)
        if owned:
            found = sorted(owned, key=lambda j: j.get("metadata", {}).get("creationTimestamp", ""))[0]
            kubectl(lab, "patch", "cronjob/" + CRONJOB, "--type=merge", "-p", '{"spec":{"suspend":true}}')
            break
        time.sleep(2)
    if found is None:
        lab.block("The Kubernetes CronJob controller did not create an owned scheduled Job within the bounded wait")
    return found


def cluster_signature(snapshot):
    members = snapshot.get("members_seen", [])
    return (tuple(sorted(m.get("member_id", "") for m in members if m.get("healthy"))),
            tuple(sorted(m.get("cluster_id", "") for m in members if m.get("healthy"))),
            tuple(sorted(set(m.get("leader", "") for m in members if m.get("healthy")))))


def stable_cluster_observation(snapshot):
    return {
        "three_members_healthy": snapshot.get("healthy_endpoints") == 3,
        "quorum_healthy": snapshot.get("quorum") is True,
        "same_cluster_membership": snapshot.get("members") == 3 and snapshot.get("cluster_count") == 1,
        "single_known_leader": snapshot.get("leader_count") == 1,
        "expected_etcd_version": all(m.get("server_version") == "3.6.8"
                                       for m in snapshot.get("members_seen", []) if m.get("healthy")),
    }


def validate_member_actions(record):
    actions = record.get("actions", [])
    expected = ["etcd-0", "etcd-1", "etcd-2"]
    members = [a.get("member") for a in actions if a.get("action") == "defrag" and a.get("issued") is True]
    reads = [a.get("benign_marker_read_from") for a in actions]
    read_ok = all(a.get("benign_marker_preserved") is True and a.get("member") != a.get("benign_marker_read_from")
                  for a in actions)
    snapshots = [s for a in actions for s in (a.get("pre_interlock"), a.get("post_interlock")) if s]
    signatures = [cluster_signature(s) for s in snapshots]
    health_ok = (len(snapshots) == 6 and all(all(stable_cluster_observation(s).values()) for s in snapshots)
                 and len(set(signatures)) == 1)
    return (members == expected and len(reads) == 3 and read_ok and health_ok
            and record.get("attempted_maintenance_commands") == 3)


def validate_cronjob_spec(cronjob):
    spec = cronjob.get("spec", {})
    job = spec.get("jobTemplate", {}).get("spec", {})
    podspec = job.get("template", {}).get("spec", {})
    container = podspec.get("containers", [{}])[0]
    resources = container.get("resources", {})
    return (
        spec.get("schedule") == CRONJOB_SCHEDULE and spec.get("timeZone") == "Etc/UTC"
        and spec.get("concurrencyPolicy") == "Forbid" and spec.get("suspend") is False
        and spec.get("startingDeadlineSeconds") == 120
        and job.get("activeDeadlineSeconds") == CRONJOB_WINDOW_SECONDS
        and job.get("backoffLimit") == 0 and job.get("completions") == 1 and job.get("parallelism") == 1
        and podspec.get("restartPolicy") == "Never" and podspec.get("automountServiceAccountToken") is False
        and bool(resources.get("requests")) and bool(resources.get("limits"))
    )


def validate_scheduled_job(job, cronjob):
    meta = job.get("metadata", {})
    owners = meta.get("ownerReferences", [])
    owner_ok = any(o.get("kind") == "CronJob" and o.get("uid") == cronjob["metadata"]["uid"]
                   and o.get("controller") is True for o in owners)
    annotations = meta.get("annotations", {})
    timestamp = annotations.get(SCHEDULED_TIMESTAMP_ANNOTATION)
    manual = meta.get("annotations", {}).get("cronjob.kubernetes.io/instantiate") == "manual"
    try:
        scheduled = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        created = datetime.fromisoformat(meta["creationTimestamp"].replace("Z", "+00:00"))
        timestamp_ok = scheduled.tzinfo is not None and scheduled.utcoffset().total_seconds() == 0
        timestamp_ok = timestamp_ok and scheduled.second == 0 and scheduled.microsecond == 0
        timestamp_ok = timestamp_ok and scheduled <= created and (created - scheduled).total_seconds() <= 120
    except (AttributeError, KeyError, TypeError, ValueError):
        timestamp_ok = False
    return owner_ok and timestamp_ok and not manual, {"controller_owned": owner_ok,
                                                      "controller_scheduled_timestamp_present_and_utc": timestamp_ok,
                                                      "manual_job_marker_absent": not manual}


def run(lab):
    # A fresh Lab cluster is created by lab.py; this case creates only its own namespace and workloads.
    create_namespace = lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", "kind-" + lab.cluster,
        "create", "namespace", NAMESPACE, "-o", "json", timeout=30,
    )
    record_raw_evidence(lab, "namespace", json.loads(create_namespace.stdout))
    create_resource(lab, service())
    create_resource(lab, etcd_statefulset())
    script = Path(__file__).with_name("maintenance.py").read_text()
    create_resource(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                          "metadata": {"name": "fixture-script", "namespace": NAMESPACE},
                          "data": {"maintenance.py": script}})
    wait_pods_ready(lab)

    auto, _ = run_job(lab, "auto-compaction-probe", "auto-compaction")
    lab.check("red", "An old exact marker revision is readable before periodic compaction",
              auto.get("old_revision_readable_before_expiry") is True,
              {"old_revision_readable_before_expiry": auto.get("old_revision_readable_before_expiry") is True})
    lab.check("green", "Periodic compaction expires only the old revision while the latest marker remains readable",
              auto.get("old_revision_compacted") is True and auto.get("latest_value_preserved") is True,
              {"old_revision_compacted": auto.get("old_revision_compacted") is True,
               "latest_exact_key_read_available": auto.get("latest_value_preserved") is True})

    negative, negative_logs = run_job(lab, "maintenance-negative", "negative")
    negative_ok = (negative.get("interlock_passed") is False
                   and negative.get("forced_bad_endpoint_health") is True
                   and negative.get("attempted_maintenance_commands") == 0
                   and negative.get("marker_read_from_other_member") is True)
    independent_zero = "MAINTENANCE_COMMAND_ATTEMPT " not in negative_logs
    record_raw_evidence(lab, "negative_command_audit", {
        "job_logs_contain_no_maintenance_command_attempt_event": independent_zero,
        "runner_reported_attempts": negative.get("attempted_maintenance_commands"),
    })
    lab.check("red", "The shared maintenance function withholds defrag on forced endpoint-health failure",
              negative_ok and independent_zero,
              {"forced_bad_endpoint_health_result": negative.get("forced_bad_endpoint_health") is True,
               "interlock_failed_closed": negative.get("interlock_passed") is False,
               "zero_maintenance_commands_attempted": negative_ok and independent_zero,
               "benign_marker_remains_readable": negative.get("marker_read_from_other_member") is True})

    cronjob = scheduled_cronjob()
    create_resource(lab, cronjob)
    observed_cronjob = json.loads(kubectl(lab, "get", "cronjob", CRONJOB, "-o", "json").stdout)
    spec_ok = validate_cronjob_spec(observed_cronjob)
    lab.check("positive", "The bounded UTC CronJob declares Forbid concurrency and one constrained Job",
              spec_ok, {"every_minute_schedule": observed_cronjob.get("spec", {}).get("schedule") == CRONJOB_SCHEDULE,
                        "utc": observed_cronjob.get("spec", {}).get("timeZone") == "Etc/UTC",
                        "forbid": observed_cronjob.get("spec", {}).get("concurrencyPolicy") == "Forbid",
                        "bounded_job_and_resources": spec_ok})

    job = suspend_after_first_owned_job(lab, observed_cronjob)
    owned_ok, owner_observation = validate_scheduled_job(job, observed_cronjob)
    logs = wait_job_logs(lab, job["metadata"]["name"], 190)
    scheduled = parse_run_evidence(logs)
    record_raw_evidence(lab, "scheduled-maintenance", {
        "job": job, "cronjob": observed_cronjob, "logs": logs, "result": scheduled,
    })
    # Verify suspension after first observation, after waiting for the already-owned job to finish.
    suspended = json.loads(kubectl(lab, "get", "cronjob", CRONJOB, "-o", "json").stdout)["spec"].get("suspend") is True
    lab.check("positive", "The first controller-owned Job carries its CronJob UID and scheduled UTC timestamp",
              owned_ok, owner_observation)
    lab.check("positive", "Scheduling is suspended after the first owned Job is observed",
              suspended, {"further_scheduling_suspended": suspended})
    lab.check("positive", "Scheduled maintenance defragments members sequentially with healthy cluster and remote marker checks",
              scheduled.get("result") == "passed" and validate_member_actions(scheduled),
              {"three_member_actions_in_order": [a.get("member") for a in scheduled.get("actions", [])
                                                  if a.get("action") == "defrag" and a.get("issued") is True]
               == ["etcd-0", "etcd-1", "etcd-2"],
               "healthy_membership_and_leader_before_after_each_action": validate_member_actions(scheduled),
               "marker_read_from_different_member_after_each_action": all(
                   a.get("benign_marker_preserved") is True and a.get("member") != a.get("benign_marker_read_from")
                   for a in scheduled.get("actions", []))})
    reclaimed = scheduled.get("allocated_bytes_reclaimed") is True
    lab.check("positive", "A scheduled member defrag reclaims backend bytes while all current synthetic markers remain readable",
              reclaimed and scheduled.get("all_latest_markers_readable") is True,
              {"allocated_size_decreased_after_defrag": reclaimed,
               "all_latest_exact_key_reads_available": scheduled.get("all_latest_markers_readable") is True})
    if scheduled.get("result") != "passed":
        lab.block("Scheduled maintenance Job did not report a passed bounded run")
