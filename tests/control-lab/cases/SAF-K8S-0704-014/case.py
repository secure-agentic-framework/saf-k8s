"""Verify the local Kubernetes audit backend's finite backup coverage."""

import json
import time

SCOPE = "Actual Kubernetes API-server audit log rotation and retrieval for one owned fixture resource."
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
MARKER = "audit-retention-marker"
LOG = "/var/log/kubernetes/saf-retention-audit.log"


def prepare_kind(_lab, temporary):
    policy = temporary / "retention-policy.json"
    policy.write_text(json.dumps({"apiVersion": "audit.k8s.io/v1", "kind": "Policy", "omitStages": ["RequestReceived"],
        "rules": [{"level": "RequestResponse", "verbs": ["patch"], "namespaces": ["saf-test"],
                   "resources": [{"group": "", "resources": ["configmaps"], "resourceNames": [MARKER]}]}, {"level": "None"}]}))
    config = temporary / "kind-retention.yaml"
    config.write_text(f'''kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: {json.dumps(str(policy))}
        containerPath: /etc/kubernetes/saf-retention-policy.json
        readOnly: true
kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta4
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        - name: audit-policy-file
          value: /etc/kubernetes/saf-retention-policy.json
        - name: audit-log-path
          value: {LOG}
        - name: audit-log-maxsize
          value: "1"
        - name: audit-log-maxbackup
          value: "1"
      extraVolumes:
        - name: saf-fixture-policy
          hostPath: /etc/kubernetes/saf-retention-policy.json
          mountPath: /etc/kubernetes/saf-retention-policy.json
          readOnly: true
          pathType: File
        - name: saf-fixture-audit
          hostPath: /var/log/kubernetes
          mountPath: /var/log/kubernetes
          pathType: DirectoryOrCreate
''')
    return config
def produce(lab, marker):
    patch = lab.evidence / "retention-fixture-patch.json"
    patch.write_text(json.dumps({"data": {"marker": marker, "public-padding": "x" * (128 * 1024)}}))
    try:
        lab.kubectl("patch", "configmap", MARKER, "--type=merge", "--patch-file", str(patch), "-o", "name")
    finally:
        patch.unlink(missing_ok=True)


def find_marker(lab, marker, *, include_backups):
    script = ('for file in "$1" "${1%.log}"-*.log; do '
              'test -f "$file" || continue; grep -qF -- "$2" "$file" && printf "%s\n" "$file"; '
              'done; exit 0') if include_backups else 'grep -qF -- "$2" "$1" && printf "%s\n" "$1"; exit 0'
    response = lab.command("docker", "exec", f"{lab.cluster}-control-plane", "sh", "-c", script, "sh",
                           LOG, marker)
    return response.stdout.splitlines()


def backup_count(lab):
    prefix = LOG.removesuffix(".log")
    response = lab.command("docker", "exec", f"{lab.cluster}-control-plane", "sh", "-c",
                           'for file in "$1"-*.log; do test ! -f "$file" || printf "%s\n" "$file"; done',
                           "sh", prefix)
    return len(response.stdout.splitlines())


def run(lab):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": MARKER},
                "data": {"marker": "unrecorded-initial-fixture"}})
    oldest = "public-audit-oldest-014"
    produce(lab, oldest)
    initially_visible = bool(find_marker(lab, oldest, include_backups=False))
    lab.check("red", "The initial public fixture event can be retrieved from the active log before rotation",
              initially_visible, {"oldest_initially_visible": initially_visible})
    for sequence in range(12):
        produce(lab, f"public-audit-record-014-{sequence:02d}")
    current = "public-audit-current-014"
    produce(lab, current)

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        count = backup_count(lab)
        oldest_visible = bool(find_marker(lab, oldest, include_backups=True))
        if count == 1 and not oldest_visible:
            break
        time.sleep(0.5)
    else:
        lab.block("The actual API audit backend did not reach the expected one-backup retention condition")
    lab.check("green", "The actual audit backend retains one rotated backup and the oldest event is no longer retrievable",
              count == 1 and not oldest_visible, {"retained_backups": count, "oldest_after_rotation_visible": oldest_visible})

    current_found = bool(find_marker(lab, current, include_backups=False))
    lab.check("positive", "The newest event is still retrievable from the active producer log",
              current_found, {"newest_active_log_visible": current_found})
    (lab.evidence / "retention-observations.json").write_text(json.dumps({
        "scope": "local audit file rotation",
        "configured_backup_limit": 1, "rotation_mib": 1, "retained_backups": count,
        "oldest_initially_visible": initially_visible, "oldest_after_rotation_visible": oldest_visible,
        "newest_active_log_visible": current_found}, indent=2) + "\n")
