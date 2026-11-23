"""Recover an owned application checkpoint into a distinct PVC and verify its service."""

import hashlib
import json
import time

SCOPE = "A controlled application outage and checkpoint restore within an owned Kind cluster."
IMAGE = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
PRIMARY = "saf-contingency-primary"
RECOVERY = "saf-contingency-recovery"
PORT = 18080


def payload(revision):
    return json.dumps({"schema": "fixture-v1", "sequence": revision, "marker": "public-checkpoint"}, sort_keys=True)


def hash_bytes(raw):
    return hashlib.sha256(raw.encode()).hexdigest()


def verified_checkpoint(raw, expected):
    if hash_bytes(raw) != expected:
        return False
    parsed = json.loads(raw)
    return parsed.get("schema") == "fixture-v1" and isinstance(parsed.get("sequence"), int)


def create(lab, namespace, manifest):
    lab.kubectl("-n", namespace, "create", "-f", "-", payload=json.dumps(manifest))


def container(name, command, *, mounts):
    return {"name": name, "image": IMAGE, "command": command, "volumeMounts": mounts,
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "5m", "memory": "4Mi"}, "limits": {"cpu": "100m", "memory": "24Mi"}}}


def start(lab, namespace, raw, expected):
    if not verified_checkpoint(raw, expected):
        lab.block("The fixture checkpoint failed its portable integrity check")
    create(lab, namespace, {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": {"name": "checkpoint-data"},
                            "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "8Mi"}}}})
    create(lab, namespace, {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "checkpoint-transfer"},
                            "immutable": True, "data": {"snapshot.json": raw, "sha256": expected}})
    create(lab, namespace, {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "fixture-app"},
                            "spec": {"selector": {"app": "fixture-app"}, "ports": [{"name": "web", "port": PORT, "targetPort": PORT}]}})
    data = {"name": "storage", "mountPath": "/data"}
    init = container("initialize", ["/bin/sh", "-ec", '''
        test "$(sha256sum /backup/snapshot.json | cut -d ' ' -f 1)" = "$(cat /backup/sha256)"
        cat /backup/snapshot.json > /data/index.html
        '''], mounts=[data, {"name": "transfer", "mountPath": "/backup", "readOnly": True}])
    app = container("http", ["/bin/httpd", "-f", "-p", str(PORT), "-h", "/data"], mounts=[data])
    app["readinessProbe"] = {"httpGet": {"path": "/", "port": PORT}, "periodSeconds": 1}
    labels = {"app": "fixture-app"}
    create(lab, namespace, {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "fixture-app"},
                            "spec": {"replicas": 1, "selector": {"matchLabels": labels}, "template": {
                                "metadata": {"labels": labels}, "spec": {"automountServiceAccountToken": False,
                                    "terminationGracePeriodSeconds": 1,
                                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                        "fsGroup": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                                    "initContainers": [init], "containers": [app], "volumes": [
                                        {"name": "storage", "persistentVolumeClaim": {"claimName": "checkpoint-data"}},
                                        {"name": "transfer", "configMap": {"name": "checkpoint-transfer"}}],
                                }}}})
    lab.kubectl("-n", namespace, "rollout", "status", "deployment/fixture-app", "--timeout=75s", timeout=85)


def get_claim(lab, namespace):
    return json.loads(lab.kubectl("-n", namespace, "get", "pvc", "checkpoint-data", "-o", "json").stdout)


def service_read(lab, namespace):
    url = f"http://fixture-app.{namespace}.svc:{PORT}/"
    result = lab.kubectl("exec", "recovery-probe", "--", "wget", "-T", "2", "-O-", url, timeout=14, allow_failure=True)
    if result.returncode == 0:
        return result.stdout
    text = result.stderr.lower()
    if "timed out" in text or "connection refused" in text:
        return None
    lab.block("A fixture service probe failed for an unexpected reason")


def wait_for(lab, check, explanation):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(1)
    lab.block(explanation)


def run(lab):
    for name in (PRIMARY, RECOVERY):
        lab.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name,
                    "labels": {"pod-security.kubernetes.io/enforce": "restricted"}}})
    probe = container("probe", ["/bin/sleep", "240"], mounts=[])
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "recovery-probe"}, "spec": {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [probe]}})
    lab.kubectl("wait", "--for=condition=Ready", "pod/recovery-probe", "--timeout=65s", timeout=75)
    checkpoint = payload(7)
    start(lab, PRIMARY, checkpoint, hash_bytes(checkpoint))
    wait_for(lab, lambda: service_read(lab, PRIMARY) == checkpoint, "No healthy primary checkpoint response")
    backup = lab.kubectl("-n", PRIMARY, "exec", "deployment/fixture-app", "--", "cat", "/data/index.html").stdout
    backup_hash = hash_bytes(backup)
    if backup != checkpoint:
        lab.block("The primary volume did not contain the approved public checkpoint")
    approved_backup = verified_checkpoint(backup, backup_hash)
    invalid_rejected = not verified_checkpoint(backup.replace("public-checkpoint", "changed-fixture"), backup_hash)
    claim = get_claim(lab, PRIMARY)
    latest = payload(8)
    lab.kubectl("-n", PRIMARY, "exec", "deployment/fixture-app", "--", "/bin/sh", "-ec",
                '''printf '%s' "$1" > /data/index.html''', "fixture", latest)
    wait_for(lab, lambda: service_read(lab, PRIMARY) == latest, "The last primary write was not observed")
    began = time.monotonic()
    lab.kubectl("-n", PRIMARY, "scale", "deployment/fixture-app", "--replicas=0")
    wait_for(lab, lambda: service_read(lab, PRIMARY) is None, "The controlled primary outage was not observed")
    lab.check("red", "The primary serves a newer write before the controlled outage and then becomes unavailable",
              True, {"last_primary_sequence": 8, "observed_primary_outage": True})
    lab.check("green", "The backup is bound to its exact digest and rejects changed data",
              approved_backup and invalid_rejected, {"export_integrity_verified": approved_backup, "changed_export_denied": invalid_rejected})
    start(lab, RECOVERY, backup, backup_hash)
    wait_for(lab, lambda: service_read(lab, RECOVERY) == backup, "The restored service did not return the checkpoint")
    recovery = get_claim(lab, RECOVERY)
    marker = service_read(lab, RECOVERY)
    elapsed = time.monotonic() - began
    separate = claim["metadata"]["uid"] != recovery["metadata"]["uid"] and claim["spec"]["volumeName"] != recovery["spec"]["volumeName"]
    sequence_lag = json.loads(latest)["sequence"] - json.loads(marker)["sequence"]
    lab.check("positive", "The standby service returns the approved checkpoint from a separate PVC within the fixture objective",
              marker == backup and separate and elapsed <= 130 and sequence_lag == 1 and service_read(lab, PRIMARY) is None,
              {"separate_pvcs": separate, "recovery_bound_met": elapsed <= 130, "checkpoint_sequence_lag": sequence_lag})
    (lab.evidence / "continuity-observations.json").write_text(json.dumps({
        "local_kind_rehearsal": True, "backup_sha256": backup_hash, "latest_sequence_before_loss": 8,
        "recovered_sequence": 7, "checkpoint_sequence_lag": sequence_lag,
        "observed_recovery_seconds": round(elapsed, 2), "fixture_recovery_bound_seconds": 130,
        "source_pvc_uid": claim["metadata"]["uid"], "recovery_pvc_uid": recovery["metadata"]["uid"],
    }, indent=2) + "\n")
