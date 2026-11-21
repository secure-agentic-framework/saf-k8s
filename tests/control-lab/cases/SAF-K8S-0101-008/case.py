"""Compare one harmless ConfigMap request with audit disabled and enabled."""

from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import time


NAMESPACE = "saf-test"
MARKER = "saf-audit-metadata-marker"
LOG_PATH = "/var/log/kubernetes/audit.log"
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
SCOPE = (
    "One harmless ConfigMap create in the runner-owned default kind cluster, where the "
    "static API server manifest has no audit flags and the known audit file is absent, "
    "compared with the same create in a disposable v1.36.1 kind cluster using a catch-all "
    "Metadata policy; the audited ResponseComplete event must omit both body fields."
)


def marker_resource():
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": MARKER, "namespace": NAMESPACE},
    }


def client_args(cluster, kubeconfig):
    return [
        "kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
        "--namespace", NAMESPACE, "--request-timeout=40s",
    ]


def create_marker(lab, cluster, kubeconfig=None):
    if kubeconfig is None:
        result = lab.kubectl("create", "-f", "-", "-o", "json",
                             payload=json.dumps(marker_resource()))
    else:
        result = lab.command(*client_args(cluster, kubeconfig), "create", "-f", "-", "-o", "json",
                             payload=json.dumps(marker_resource()))
    created = json.loads(result.stdout)
    metadata = created.get("metadata", {})
    return (created.get("kind") == "ConfigMap"
            and metadata.get("name") == MARKER
            and metadata.get("namespace") == NAMESPACE)


def baseline_backend_state(lab):
    # Inspect the static-pod manifest and audit-file existence inside the
    # runner-owned node. The shell emits only fixed presence/absence values.
    script = r'''set -eu
manifest=/etc/kubernetes/manifests/kube-apiserver.yaml
test -r "$manifest"
if grep -q -- '--audit-' "$manifest"; then flags=present; else flags=absent; fi
if test -e /var/log/kubernetes/audit.log; then logfile=present; else logfile=absent; fi
printf 'audit_flags=%s audit_log=%s\n' "$flags" "$logfile"
'''
    node = f"{lab.cluster}-control-plane"
    result = lab.command("docker", "exec", node, "sh", "-c", script, timeout=30)
    return result.stdout.strip()


def marker_event_summaries(lab, cluster):
    # All event parsing stays in the kind node. Only fixed fields and body-field
    # presence leave docker exec; raw audit records and bodies are never emitted.
    script = r'''set -eu
log="$1"
name="$2"
namespace="$3"
test -f "$log" || exit 0
grep -F '"name":"'"$name"'"' "$log" |
  grep -F '"resource":"configmaps"' |
  grep -F '"namespace":"'"$namespace"'"' |
  while IFS= read -r line; do
    case "$line" in *'"stage":"ResponseComplete"'*) ;; *) continue ;; esac
    field() {
      printf '%s\n' "$line" | sed -n 's/.*"'"$1"'":"\([A-Za-z]*\)".*/\1/p'
    }
    verb=$(field verb)
    level=$(field level)
    stage=$(field stage)
    event_namespace=$(printf '%s\n' "$line" | sed -n 's/.*"namespace":"\([A-Za-z0-9-]*\)".*/\1/p')
    test -n "$verb" && test -n "$level" && test -n "$stage" && test -n "$event_namespace"
    if printf '%s\n' "$line" | grep -q '"requestObject":'; then
      request_body=present
    else
      request_body=absent
    fi
    if printf '%s\n' "$line" | grep -q '"responseObject":'; then
      response_body=present
    else
      response_body=absent
    fi
    printf 'verb=%s level=%s namespace=%s stage=%s requestObject=%s responseObject=%s\n' \
      "$verb" "$level" "$event_namespace" "$stage" "$request_body" "$response_body"
  done
'''
    node = f"{cluster}-control-plane"
    result = lab.command("docker", "exec", node, "sh", "-c", script,
                         "audit-marker-summary", LOG_PATH, MARKER, NAMESPACE,
                         timeout=30, allow_failure=True)
    if result.returncode not in (0, 1):
        lab.block(result.stderr.strip() or "Could not summarize the marker audit event")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


@contextmanager
def audited_cluster(lab):
    cluster = lab.cluster + "-audit"
    kubeconfig = None
    owned = False
    with tempfile.TemporaryDirectory(prefix="saf-audit-metadata-") as temp:
        temp_path = Path(temp)
        kubeconfig = temp_path / "kubeconfig"
        config = temp_path / "audited-kind-config.yaml"
        policy = Path(__file__).with_name("audit-policy.yaml").resolve()
        config.write_text(
            "kind: Cluster\n"
            "apiVersion: kind.x-k8s.io/v1alpha4\n"
            "nodes:\n"
            "  - role: control-plane\n"
            "    extraMounts:\n"
            "      - hostPath: " + json.dumps(str(policy)) + "\n"
            "        containerPath: /etc/kubernetes/audit-policy.yaml\n"
            "        readOnly: true\n"
            "kubeadmConfigPatches:\n"
            "  - |\n"
            "    apiVersion: kubeadm.k8s.io/v1beta4\n"
            "    kind: ClusterConfiguration\n"
            "    apiServer:\n"
            "      extraArgs:\n"
            "        - name: audit-policy-file\n"
            "          value: /etc/kubernetes/audit-policy.yaml\n"
            f"        - name: audit-log-path\n          value: {LOG_PATH}\n"
            "      extraVolumes:\n"
            "        - name: audit-policy\n"
            "          hostPath: /etc/kubernetes/audit-policy.yaml\n"
            "          mountPath: /etc/kubernetes/audit-policy.yaml\n"
            "          readOnly: true\n"
            "          pathType: File\n"
            "        - name: audit-log\n"
            "          hostPath: /var/log/kubernetes\n"
            "          mountPath: /var/log/kubernetes\n"
            "          readOnly: false\n"
            "          pathType: DirectoryOrCreate\n"
        )

        if cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
            lab.block(f"Additional analysis cluster already exists: {cluster}")
        # From here on, cleanup owns this unique cluster name, including partial
        # failures during kind create.
        owned = True
        try:
            lab.command("kind", "create", "cluster", "--name", cluster,
                        "--image", NODE_IMAGE, "--config", str(config),
                        "--kubeconfig", str(kubeconfig), "--wait", "90s", timeout=480)
            lab.command(*client_args(cluster, kubeconfig), "create", "namespace", NAMESPACE)
            yield cluster, kubeconfig
        finally:
            if owned:
                lab.command("kind", "delete", "cluster", "--name", cluster,
                            "--kubeconfig", str(kubeconfig), timeout=90)


def run(lab):
    baseline_created = create_marker(lab, lab.cluster)
    lab.check(
        "positive",
        "The harmless ConfigMap create succeeds against the unaudited baseline API",
        baseline_created,
        f"created {NAMESPACE}/{MARKER}" if baseline_created else "API response did not identify the marker",
    )
    baseline_state = baseline_backend_state(lab)
    baseline_inactive = "audit_flags=absent" in baseline_state and "audit_log=absent" in baseline_state
    lab.check(
        "red",
        "The runner-owned default API server has no configured audit backend",
        baseline_inactive,
        baseline_state,
    )

    with audited_cluster(lab) as (cluster, kubeconfig):
        # The audited create uses the same namespace, resource and marker name.
        created = create_marker(lab, cluster, kubeconfig)
        lab.check(
            "positive",
            "The same harmless ConfigMap create succeeds against the audited API",
            created,
            f"created {NAMESPACE}/{MARKER}" if created else "API response did not identify the marker",
        )

        summaries = []
        deadline = time.monotonic() + 10
        while not summaries and time.monotonic() < deadline:
            summaries = marker_event_summaries(lab, cluster)
            if not summaries:
                time.sleep(0.25)
        fields = (dict(item.split("=", 1) for item in summaries[0].split())
                  if len(summaries) == 1 else {})
        valid = fields == {
            "verb": "create",
            "level": "Metadata",
            "namespace": NAMESPACE,
            "stage": "ResponseComplete",
            "requestObject": "absent",
            "responseObject": "absent",
        }
        lab.check(
            "green",
            "The matching API create has a Metadata completion event without either body",
            valid,
            "; ".join(summaries) if summaries else "no filtered marker event found",
        )
