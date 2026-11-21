"""Exercise kube-apiserver file audit rotation with synthetic backup metadata."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import tempfile
import time


CASE_DIR = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
AUDIT_PATH = "/var/log/kubernetes/audit/audit.log"
AUDIT_DIR_IN_NODE = "/var/log/kubernetes/audit"
MAX_AGE_DAYS = 2
MAX_BACKUPS = 2
MAX_SIZE_MB = 1
PADDING_BYTES = MAX_SIZE_MB * 1024 * 1024
SCOPE = (
    "Kubernetes v1.36.1 kube-apiserver file audit backend on one disposable kind control-plane; "
    "synthetic rotated-file names test age and count cleanup when a harmless ConfigMap patch "
    "causes a size rotation. Read only the new synthetic API audit event and retain only outcome booleans."
)


def backup_path(directory, when):
    # lumberjack v2 backup names encode the rotation time in UTC, to milliseconds.
    stamp = when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S.%f")[:-3]
    return directory / f"audit-{stamp}.log"


def create_age_fixtures(directory, backend_now):
    expired = backup_path(directory, backend_now - timedelta(days=MAX_AGE_DAYS, seconds=30))
    inside = backup_path(directory, backend_now - timedelta(days=MAX_AGE_DAYS, seconds=-30))
    expired.write_text("synthetic audit metadata fixture\n")
    inside.write_text("synthetic audit metadata fixture\n")
    # A max-sized synthetic current file makes the next selected audit event rotate it.
    (directory / "audit.log").write_bytes(b"x" * PADDING_BYTES)
    return {"expired_fixture": expired.name, "inside_fixture": inside.name}


def create_count_fixtures(directory):
    now = datetime.now(timezone.utc)
    paths = [
        backup_path(directory, now - timedelta(hours=hours))
        for hours in (3, 2, 1)
    ]
    for path in paths:
        path.write_text("synthetic audit metadata fixture\n")
    (directory / "audit.log").write_bytes(b"x" * PADDING_BYTES)
    return {"old_fixture": paths[0].name, "middle_fixture": paths[1].name,
            "new_fixture": paths[2].name}


def client_args(cluster, kubeconfig):
    return ["kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
            "--namespace", NAMESPACE, "--request-timeout=40s"]


def marker_resource(name):
    return {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": name, "namespace": NAMESPACE}}


def backup_names(directory):
    return {path.name for path in directory.iterdir()
            if path.is_file() and re.fullmatch(r"audit-\d{4}-\d\d-\d\dT\d\d-\d\d-\d\d\.\d{3}\.log", path.name)}


@contextmanager
def audited_cluster(lab, suffix, directory, max_age, max_backups):
    cluster = f"{lab.cluster}-{suffix}"
    existing = lab.command("kind", "get", "clusters").stdout.splitlines()
    if cluster in existing:
        lab.block(f"Analysis cluster already exists: {cluster}")

    with tempfile.TemporaryDirectory(prefix=f"{suffix}-") as temp:
        temp_path = Path(temp)
        kubeconfig = temp_path / "kubeconfig"
        policy = (CASE_DIR / "audit-policy.yaml").resolve()
        audit_dir = directory.resolve()
        config = temp_path / "kind-config.yaml"
        config.write_text(
            "kind: Cluster\n"
            "apiVersion: kind.x-k8s.io/v1alpha4\n"
            "nodes:\n"
            "  - role: control-plane\n"
            "    extraMounts:\n"
            f"      - hostPath: {json.dumps(str(policy))}\n"
            "        containerPath: /etc/kubernetes/audit-policy.yaml\n"
            "        readOnly: true\n"
            f"      - hostPath: {json.dumps(str(audit_dir))}\n"
            f"        containerPath: {AUDIT_DIR_IN_NODE}\n"
            "        readOnly: false\n"
            "kubeadmConfigPatches:\n"
            "  - |\n"
            "    apiVersion: kubeadm.k8s.io/v1beta4\n"
            "    kind: ClusterConfiguration\n"
            "    apiServer:\n"
            "      extraArgs:\n"
            "        - name: audit-policy-file\n"
            "          value: /etc/kubernetes/audit-policy.yaml\n"
            f"        - name: audit-log-path\n          value: {AUDIT_PATH}\n"
            f"        - name: audit-log-maxage\n          value: \"{max_age}\"\n"
            f"        - name: audit-log-maxbackup\n          value: \"{max_backups}\"\n"
            f"        - name: audit-log-maxsize\n          value: \"{MAX_SIZE_MB}\"\n"
            "      extraVolumes:\n"
            "        - name: audit-policy\n"
            "          hostPath: /etc/kubernetes/audit-policy.yaml\n"
            "          mountPath: /etc/kubernetes/audit-policy.yaml\n"
            "          readOnly: true\n"
            "          pathType: File\n"
            "        - name: audit-log\n"
            f"          hostPath: {AUDIT_DIR_IN_NODE}\n"
            f"          mountPath: {AUDIT_DIR_IN_NODE}\n"
            "          readOnly: false\n"
            "          pathType: DirectoryOrCreate\n"
        )
        try:
            lab.command("kind", "create", "cluster", "--name", cluster,
                        "--image", NODE_IMAGE, "--config", str(config),
                        "--kubeconfig", str(kubeconfig), "--wait", "90s", timeout=480)
            lab.command(*client_args(cluster, kubeconfig), "create", "namespace", NAMESPACE)
            yield cluster, kubeconfig
        finally:
            lab.command("kind", "delete", "cluster", "--name", cluster,
                        "--kubeconfig", str(kubeconfig), timeout=90)



def wait_for_pruning(directory, keep, remove, total):
    deadline = time.monotonic() + 10
    while True:
        names = backup_names(directory)
        result = {"kept": set(keep) <= names,
                  "removed": not set(remove) & names,
                  "backup_count": len(names),
                  "rotation_observed": bool(names - set(keep) - set(remove))}
        if (result["kept"] and result["removed"] and len(names) == total
                and result["rotation_observed"]) or time.monotonic() >= deadline:
            return result
        time.sleep(0.2)


def submit_marker(lab, cluster, kubeconfig, directory, name):
    lab.command(*client_args(cluster, kubeconfig), "patch", f"configmap/{name}",
                "--type=merge", "-p", '{"data":{"probe":"synthetic"}}')
    # The policy records only Metadata for our own ConfigMap PATCH. Determine
    # whether the new active file contains the matching response without logging it.
    deadline = time.monotonic() + 8
    observed = {}
    while True:
        active = directory / "audit.log"
        if active.is_file() and 0 < active.stat().st_size < PADDING_BYTES:
            for line in active.read_text().splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                observed = {"stage": event.get("stage"), "verb": event.get("verb"),
                            "named_route": event.get("requestURI", "").split("?")[0].endswith(f"/configmaps/{name}"),
                            "response_code": event.get("responseStatus", {}).get("code")}
                if observed == {"stage": "ResponseComplete", "verb": "patch",
                                "named_route": True, "response_code": 200}:
                    return True, observed
        if time.monotonic() >= deadline:
            return False, {**observed, "active_log_bytes": active.stat().st_size if active.is_file() else 0}
        time.sleep(0.2)


def run_age_check(lab):
    with tempfile.TemporaryDirectory(prefix="saf-audit-age-") as temp:
        directory = Path(temp)
        with audited_cluster(lab, "audit-age", directory, MAX_AGE_DAYS, 100) as (cluster, kubeconfig):
            clock = lab.command("docker", "exec", f"{cluster}-control-plane",
                                "date", "-u", "+%Y-%m-%dT%H:%M:%S").stdout.strip()
            backend_now = datetime.strptime(clock, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
            marker = "saf-audit-age-probe"
            lab.command(*client_args(cluster, kubeconfig), "create", "-f", "-",
                        payload=json.dumps(marker_resource(marker)))
            fixtures = create_age_fixtures(directory, backend_now)
            pre_rotation = (backup_names(directory) == set(fixtures.values())
                            and (directory / "audit.log").stat().st_size == PADDING_BYTES)
            lab.check("red", "Both age fixtures and a full active file exist before an audit write",
                      pre_rotation, pre_rotation)
            written, observed = submit_marker(lab, cluster, kubeconfig, directory, marker)
            lab.check("positive", "The harmless synthetic ConfigMap patch is recorded after age rotation",
                      written, observed)
            result = wait_for_pruning(directory, [fixtures["inside_fixture"]],
                                      [fixtures["expired_fixture"]], 2)
            lab.check("green", "Age pruning removes only the expired backup and keeps the new rotation",
                      result == {"kept": True, "removed": True, "backup_count": 2,
                                 "rotation_observed": True}, result)


def run_count_check(lab):
    with tempfile.TemporaryDirectory(prefix="saf-audit-count-") as temp:
        directory = Path(temp)
        with audited_cluster(lab, "audit-count", directory, 0, MAX_BACKUPS) as (cluster, kubeconfig):
            marker = "saf-audit-count-probe"
            lab.command(*client_args(cluster, kubeconfig), "create", "-f", "-",
                        payload=json.dumps(marker_resource(marker)))
            fixtures = create_count_fixtures(directory)
            pre_rotation = (backup_names(directory) == set(fixtures.values())
                            and (directory / "audit.log").stat().st_size == PADDING_BYTES)
            lab.check("red", "Three backups exist before a write triggers the two-backup cap",
                      pre_rotation, pre_rotation)
            written, observed = submit_marker(lab, cluster, kubeconfig, directory, marker)
            lab.check("positive", "The harmless synthetic ConfigMap patch is recorded after count rotation",
                      written, observed)
            result = wait_for_pruning(directory, [fixtures["new_fixture"]],
                                      [fixtures["middle_fixture"], fixtures["old_fixture"]], MAX_BACKUPS)
            lab.check("green", "The cap removes two backups under four hours old even with age pruning disabled",
                      result == {"kept": True, "removed": True, "backup_count": MAX_BACKUPS,
                                 "rotation_observed": True}, result)


def run(lab):
    run_age_check(lab)
    run_count_check(lab)
