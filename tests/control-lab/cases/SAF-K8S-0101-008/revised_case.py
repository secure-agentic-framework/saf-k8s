"""Compare metadata-safe audit decisions with a narrow synthetic canary rule."""
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import time

from fixtures import container, pod


CASE_DIR = Path(__file__).resolve().parent
FIXTURE = json.loads((CASE_DIR / "revised-fixtures.json").read_text())
NAMESPACE = FIXTURE["namespace"]
IDENTITY = FIXTURE["identity"]
LOG_PATH = "/var/log/kubernetes/audit.log"
FIXTURE_SERVICE_ACCOUNT = "saf-audit-projected-fixture"
TOKEN_REVIEW_URI = "/apis/authentication.k8s.io/v1/tokenreviews"
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
SCOPE = (
    "The same synthetic ConfigMap and Secret creates, allowed and denied reads, inert "
    "TokenReview, and ordinary Pod token projection use default and audited kind profiles. "
    "Audit events are filtered in-node to fixed metadata and "
    "body-presence booleans. Only the noncredential ConfigMap canary may record a request "
    "body; Secret, TokenReview, and service-account token policies are metadata-only."
)


def client_args(cluster, kubeconfig):
    return [
        "kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
        "--namespace", NAMESPACE, "--request-timeout=40s",
    ]


def configmap_payload():
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": FIXTURE["canary"]["name"], "namespace": NAMESPACE},
        "data": FIXTURE["canary"]["data"],
    }


def role_payload():
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "saf-audit-probe", "namespace": NAMESPACE},
        "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                    "verbs": ["create", "get"]},
                   {"apiGroups": [""], "resources": ["secrets"],
                    "verbs": ["create"]}],
    }


def binding_payload():
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {"name": "saf-audit-probe", "namespace": NAMESPACE},
        "subjects": [{"kind": "User", "name": IDENTITY, "apiGroup": "rbac.authorization.k8s.io"}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                    "name": "saf-audit-probe"},
    }


def prepare_identity(lab, cluster, kubeconfig=None):
    args = lab.kubectl if kubeconfig is None else lambda *a, **kw: lab.command(
        *client_args(cluster, kubeconfig), *a, **kw
    )
    for resource in (role_payload(), binding_payload()):
        args("create", "-f", "-", "-o", "name", payload=json.dumps(resource))


def synthetic_requests(lab, cluster, kubeconfig=None):
    args = lab.kubectl if kubeconfig is None else lambda *a, **kw: lab.command(
        *client_args(cluster, kubeconfig), *a, **kw
    )
    impersonate = ("--as", IDENTITY)
    canary_result = args(
        *impersonate, "create", "-f", "-", "-o", "name",
        payload=json.dumps(configmap_payload()),
    )
    empty_secret = {
        "apiVersion": "v1", "kind": "Secret",
        "metadata": {"name": FIXTURE["secret"]["name"], "namespace": NAMESPACE},
        "type": "Opaque",
    }
    secret_result = args(
        *impersonate, "create", "-f", "-", "-o", "name",
        payload=json.dumps(empty_secret),
    )
    allowed_result = args(
        *impersonate, "get", "configmap", FIXTURE["allowed"]["name"], "-o", "name",
    )
    denied_result = args(
        *impersonate, "get", "pod", FIXTURE["denied"]["name"], "-o", "name",
        allow_failure=True,
    )
    # The invalid marker is a public test value, with no valid credential material.
    review = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
              "spec": {"token": "synthetic-audit-fixture-invalid-value"}}
    token_review = args("create", "--raw", TOKEN_REVIEW_URI, "-f", "-",
                        payload=json.dumps(review))
    observed_review = json.loads(token_review.stdout)
    # The kubelet requests a normal projected token. This case never opens the
    # volume and checks only workload readiness and selected audit metadata.
    args("create", "serviceaccount", FIXTURE_SERVICE_ACCOUNT, "-o", "name")
    fixture_pod = pod("saf-audit-projection", [container("fixture")],
                      serviceAccountName=FIXTURE_SERVICE_ACCOUNT,
                      automountServiceAccountToken=True)
    args("create", "-f", "-", "-o", "name", payload=json.dumps(fixture_pod))
    ready = args("wait", "--for=condition=Ready", "pod/saf-audit-projection", "--timeout=95s",
                 timeout=105)
    return {
        "canary": canary_result.returncode == 0 and canary_result.stdout.strip()
        == f"configmap/{FIXTURE['canary']['name']}",
        "secret": secret_result.returncode == 0 and secret_result.stdout.strip()
        == f"secret/{FIXTURE['secret']['name']}",
        "allowed": allowed_result.returncode == 0 and allowed_result.stdout.strip()
        == f"configmap/{FIXTURE['allowed']['name']}",
        "denied": denied_result.returncode != 0 and "Forbidden" in denied_result.stderr,
        "token_review": observed_review.get("kind") == "TokenReview"
        and not observed_review.get("status", {}).get("authenticated"),
        "projection": ready.stdout.strip() == "pod/saf-audit-projection condition met",
    }


def baseline_backend_state(lab):
    script = r'''set -eu
manifest=/etc/kubernetes/manifests/kube-apiserver.yaml
test -r "$manifest"
if grep -q -- '--audit-' "$manifest"; then flags=present; else flags=absent; fi
if test -e /var/log/kubernetes/audit.log; then logfile=present; else logfile=absent; fi
printf 'audit_flags=%s audit_log=%s\n' "$flags" "$logfile"
'''
    result = lab.command("docker", "exec", f"{lab.cluster}-control-plane", "sh", "-c", script)
    return result.stdout.strip()


def safe_event_summaries(lab, cluster):
    # jq parses the complete JSON line in the node and emits only whitelisted
    # fields plus request/response body-presence booleans. No event or body exits.
    script = r'''set -eu
command -v jq >/dev/null 2>&1 || exit 127
log="$1"
authuser="$2"
identity="$3"
namespace="$4"
canary="$5"
secret="$6"
denied="$7"
svc="$8"
nodeuser="$9"
test -f "$log" || exit 0
jq -c --arg authuser "$authuser" --arg identity "$identity" \
  --arg namespace "$namespace" --arg canary "$canary" \
  --arg secret "$secret" --arg denied "$denied" --arg svc "$svc" \
  --arg nodeuser "$nodeuser" '
  select(.stage == "ResponseComplete" and ((.user.username == $authuser and
    (.impersonatedUser.username // .user.username) == $identity and
    .objectRef.namespace == $namespace and
    (.objectRef.name == $canary or .objectRef.name == $secret or .objectRef.name == $denied)) or
    (.user.username == $authuser and .verb == "create" and
      .objectRef.apiGroup == "authentication.k8s.io" and .objectRef.resource == "tokenreviews") or
    (.user.username == $nodeuser and .objectRef.namespace == $namespace and
      .objectRef.resource == "serviceaccounts" and .objectRef.subresource == "token" and
      .objectRef.name == $svc))) |
  def actor: if . == $nodeuser then "fixture-kubelet" else . end;
  {username:(.user.username|actor),
   identity:((.impersonatedUser.username // .user.username)|actor), verb:.verb, resource:.objectRef.resource,
   namespace:(.objectRef.namespace // ""), name:(.objectRef.name // ""),
   subresource:(.objectRef.subresource // ""),
   status:.responseStatus.code, decision:.annotations["authorization.k8s.io/decision"],
   level:.level, stage:.stage, requestObject:has("requestObject"),
   responseObject:has("responseObject")}' "$log"
'''
    node = f"{cluster}-control-plane"
    result = lab.command(
        "docker", "exec", node, "sh", "-c", script, "audit-safe-summary", LOG_PATH,
        FIXTURE["authenticatedIdentity"], IDENTITY, NAMESPACE,
        FIXTURE["canary"]["name"], FIXTURE["secret"]["name"],
        FIXTURE["denied"]["name"], FIXTURE_SERVICE_ACCOUNT, f"system:node:{node}",
        timeout=30, allow_failure=True,
    )
    if result.returncode == 127:
        lab.block("jq is unavailable in the kind node; refusing to export audit lines")
    if result.returncode:
        lab.block("Could not produce the fixed-field audit summary")
    try:
        return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    except json.JSONDecodeError:
        lab.block("The in-node audit summary was not valid JSON")


def expected_events():
    common = {"username": FIXTURE["authenticatedIdentity"], "identity": IDENTITY,
              "namespace": NAMESPACE, "stage": "ResponseComplete", "subresource": ""}
    rows = []
    for key in ("canary", "secret", "allowed", "denied"):
        item = FIXTURE[key]
        if key == "canary":
            item = {**item["request"], "name": item["name"]}
        rows.append({
            **common, "verb": item["verb"], "resource": item["resource"],
            "name": item["name"], "status": item["status"],
            "decision": item["decision"], "level": item["level"],
            "requestObject": item["requestObject"],
            "responseObject": item["responseObject"],
        })
    metadata_create = {**common, "verb": "create", "status": 201, "decision": "allow",
                       "level": "Metadata", "requestObject": False, "responseObject": False}
    rows.extend([
        {**metadata_create, "identity": FIXTURE["authenticatedIdentity"], "resource": "tokenreviews",
         "namespace": "", "name": ""},
        {**metadata_create, "username": "fixture-kubelet", "identity": "fixture-kubelet",
         "resource": "serviceaccounts", "name": FIXTURE_SERVICE_ACCOUNT, "subresource": "token"},
    ])
    return sorted(rows, key=lambda row: (row["resource"], row["verb"]))


def policy_static_checks(lab):
    policy = (CASE_DIR / "revised-audit-policy.yaml").read_text()
    # Deliberately simple source assertions: protect ordering and each required
    # credential-class mapping without needing a YAML package in the runner.
    credential_index = policy.index("resources:\n          - secrets")
    body_index = policy.index("- level: Request")
    catchall_index = policy.rindex("- level: Metadata")
    credential_rows = FIXTURE["credentialPolicy"]
    checks = [
        credential_index < body_index < catchall_index,
        policy.count("- level:") == 3,
        all(row["level"] == "Metadata" and f"- {row['resource']}" in policy[:body_index]
            for row in credential_rows),
        all(row["group"] in policy[:body_index] for row in credential_rows),
        "verbs:\n      - create" in policy and "namespaces:\n      - saf-test" in policy,
        "users:\n      - kubernetes-admin" in policy,
        "resources:\n          - configmaps" in policy,
        "RequestResponse" not in policy and "responseObject" not in policy,
    ]
    lab.check(
        "positive", "Policy source keeps credential classes Metadata-only ahead of the canary rule",
        all(checks), "credential metadata rules precede scoped Request rule; Metadata catch-all is last",
    )


@contextmanager
def audited_cluster(lab):
    cluster = f"{lab.cluster}-audit-revised"
    if cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block(f"Additional analysis cluster already exists: {cluster}")
    with tempfile.TemporaryDirectory(prefix="saf-audit-revised-") as temp:
        temp_path = Path(temp)
        kubeconfig = temp_path / "kubeconfig"
        config = temp_path / "audited-kind-config.yaml"
        policy = CASE_DIR / "revised-audit-policy.yaml"
        config.write_text(
            "kind: Cluster\n"
            "apiVersion: kind.x-k8s.io/v1alpha4\n"
            "nodes:\n"
            "  - role: control-plane\n"
            "    extraMounts:\n"
            f"      - hostPath: {json.dumps(str(policy))}\n"
            "        containerPath: /etc/kubernetes/revised-audit-policy.yaml\n"
            "        readOnly: true\n"
            "kubeadmConfigPatches:\n"
            "  - |\n"
            "    apiVersion: kubeadm.k8s.io/v1beta4\n"
            "    kind: ClusterConfiguration\n"
            "    apiServer:\n"
            "      extraArgs:\n"
            "        - name: audit-policy-file\n"
            "          value: /etc/kubernetes/revised-audit-policy.yaml\n"
            f"        - name: audit-log-path\n          value: {LOG_PATH}\n"
            "      extraVolumes:\n"
            "        - name: revised-audit-policy\n"
            "          hostPath: /etc/kubernetes/revised-audit-policy.yaml\n"
            "          mountPath: /etc/kubernetes/revised-audit-policy.yaml\n"
            "          readOnly: true\n"
            "          pathType: File\n"
            "        - name: audit-log\n"
            "          hostPath: /var/log/kubernetes\n"
            "          mountPath: /var/log/kubernetes\n"
            "          readOnly: false\n"
            "          pathType: DirectoryOrCreate\n"
        )
        attempted = False
        try:
            attempted = True
            lab.command(
                "kind", "create", "cluster", "--name", cluster, "--image", NODE_IMAGE,
                "--config", str(config), "--kubeconfig", str(kubeconfig),
                "--wait", "90s", timeout=480,
            )
            lab.command(*client_args(cluster, kubeconfig), "create", "namespace", NAMESPACE)
            yield cluster, kubeconfig
        finally:
            if attempted:
                deleted = lab.command(
                    "kind", "delete", "cluster", "--name", cluster,
                    "--kubeconfig", str(kubeconfig), timeout=90, allow_failure=True,
                )
                if deleted.returncode:
                    lab.block(f"Could not confirm cleanup of case-owned cluster {cluster}")


def run(lab):
    policy_static_checks(lab)

    # The runner's default cluster is the unaudited red comparison. The same
    # names, identity, verbs, and targets are used again on the audited cluster.
    prepare_identity(lab, lab.cluster)
    baseline = synthetic_requests(lab, lab.cluster)
    baseline_ok = all(baseline.values())
    lab.check(
        "positive", "Same-named synthetic requests retain their outcomes on the no-audit profile",
        baseline_ok,
        ", ".join(f"{key}={'pass' if value else 'fail'}" for key, value in baseline.items()),
    )
    backend = baseline_backend_state(lab)
    lab.check(
        "red", "Default comparison cluster has no configured audit backend",
        "audit_flags=absent" in backend and "audit_log=absent" in backend,
        backend,
    )

    with audited_cluster(lab) as (cluster, kubeconfig):
        prepare_identity(lab, cluster, kubeconfig)
        observed = synthetic_requests(lab, cluster, kubeconfig)
        lab.check(
            "positive", "Synthetic requests retain the intended allow and forbid outcomes",
            all(observed.values()),
            ", ".join(f"{key}={'pass' if value else 'fail'}" for key, value in observed.items()),
        )
        expected = expected_events()
        summaries = []
        deadline = time.monotonic() + 10
        while len(summaries) < len(expected) and time.monotonic() < deadline:
            summaries = safe_event_summaries(lab, cluster)
            if len(summaries) < len(expected):
                time.sleep(0.25)
        matched = sorted(summaries, key=lambda row: (row.get("resource", ""), row.get("verb", "")))
        lab.check(
            "green", "Audit records exact identity, decisions, targets, status, and canary body boundary",
            matched == expected,
            json.dumps(matched, sort_keys=True),
        )
