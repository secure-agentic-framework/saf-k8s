"""Check v1.36.1 bound-token delivery and legacy token controller behavior."""
import json
from contextlib import contextmanager
import tempfile
import time
from pathlib import Path


NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
CONTROLLER_NAME = "serviceaccount-token-controller"
NAMESPACE = "saf-token-controller"
SERVICE_ACCOUNT = "saf-token-probe"
LEGACY_SECRET = "saf-explicit-legacy-token-probe"
TOKEN_POD = "saf-projected-token-probe"
TIMEOUT = 20
POLICY = "saf-k8s-no-legacy-token-secrets"
POLICY_LABEL = "saf-k8s.example/legacy-token-policy=enabled"
POLICY_MESSAGE = "legacy service account token Secrets are prohibited"
SCOPE = (
    "Kubernetes v1.36.1 on disposable local kind clusters. Compare the stock "
    "kube-controller-manager with a profile that sets the legacy controller "
    "exclusion flag. Observe that no legacy token Secret is auto-generated "
    "and both profiles still populate an explicitly requested fixture. "
    "Apply namespace-scoped admission and confirm it rejects the same request "
    "while a harmless Pod still receives a projected, expiring bound token. "
    "Only boolean field-presence and boolean JWT-claim observations are retained; "
    "no token or Secret data is emitted. This does not assess production or "
    "managed-provider configuration."
)

HERE = Path(__file__).resolve().parent

# This script runs inside the disposable probe pod. The bearer value is read and
# decoded only in process memory. Its only output is four boolean claim checks.
CLAIM_OBSERVER = r'''set -eu
token=$(cat /var/run/saf-projected/token)
payload=${token#*.}
payload=${payload%%.*}
payload=$(printf '%s' "$payload" | tr '_-' '/+')
case $((${#payload} % 4)) in
  0) ;;
  2) payload="${payload}==" ;;
  3) payload="${payload}=" ;;
  *) exit 9 ;;
esac
claims=$(printf '%s' "$payload" | base64 -d 2>/dev/null)
expiry=$(printf '%s' "$claims" | sed -n 's/.*"exp":\([0-9][0-9]*\).*/\1/p')
now=$(date +%s)
has_exp=false; has_aud=false; has_pod=false; has_serviceaccount=false
if [ -n "$expiry" ] && [ "$expiry" -gt "$now" ] && [ "$expiry" -le "$((now + 605))" ]; then
  has_exp=true
fi
printf '%s' "$claims" | grep -Fq '"aud":["saf-token-probe.identity.invalid"]' && has_aud=true
printf '%s' "$claims" | grep -Fq "\"pod\":{\"name\":\"saf-projected-token-probe\",\"uid\":\"$POD_UID\"}" && has_pod=true
printf '%s' "$claims" | grep -Fq '"sub":"system:serviceaccount:saf-token-controller:saf-token-probe"' && has_serviceaccount=true
printf 'claims_exp=%s claims_aud=%s claims_pod=%s claims_serviceaccount=%s\n' \
  "$has_exp" "$has_aud" "$has_pod" "$has_serviceaccount"
'''


def kubectl(lab, kubeconfig, cluster, *args, timeout=TIMEOUT, payload=None,
            allow_failure=False):
    return lab.command(
        "kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
        f"--request-timeout={max(1, timeout - 5)}s", *args,
        timeout=timeout, payload=payload, allow_failure=allow_failure,
    )


def component_args(lab, kubeconfig, cluster):
    pod = f"kube-controller-manager-{cluster}-control-plane"
    row = json.loads(kubectl(
        lab, kubeconfig, cluster, "-n", "kube-system", "get", f"pod/{pod}", "-o", "json"
    ).stdout)
    matches = [container for container in row["spec"]["containers"]
               if container.get("name") == "kube-controller-manager"]
    if len(matches) != 1:
        lab.block("Could not identify the kube-controller-manager container")
    container = matches[0]
    command = container.get("command") or []
    args = command + container.get("args", [])
    if not args or Path(args[0]).name != "kube-controller-manager":
        lab.block("Unexpected kube-controller-manager command")
    return args


def controller_selection(args):
    values = []
    index = 0
    while index < len(args):
        value = args[index]
        if value == "--controllers":
            values.append(args[index + 1] if index + 1 < len(args) else "<missing>")
            index += 1
        elif value.startswith("--controllers="):
            values.append(value.split("=", 1)[1])
        index += 1
    return values


def observe_legacy_fields(lab, kubeconfig, cluster):
    # kubectl's Go template returns only fixed booleans, never Secret values.
    template = (
        '{{if index .data "token"}}token=true{{else}}token=false{{end}} '
        '{{if index .data "namespace"}}namespace=true{{else}}namespace=false{{end}} '
        '{{if index .data "ca.crt"}}ca=true{{else}}ca=false{{end}}'
    )
    deadline = time.monotonic() + 12
    expected = dict.fromkeys(("token", "namespace", "ca"), "true")
    while True:
        result = kubectl(
            lab, kubeconfig, cluster, "-n", NAMESPACE, "get", f"secret/{LEGACY_SECRET}",
            "-o", f"go-template={template}", timeout=TIMEOUT, allow_failure=True,
        )
        if result.returncode:
            lab.block("Could not observe the case-owned legacy Secret without emitting its data")
        observed = dict(part.split("=", 1) for part in result.stdout.split())
        matched = observed == expected
        if time.monotonic() >= deadline or matched:
            return matched, observed
        time.sleep(1)


def assert_no_autogenerated_secret(lab, kubeconfig, cluster, phase):
    # In v1.36.1 there should be no auto-created Secret reference on the SA.
    names = kubectl(
        lab, kubeconfig, cluster, "-n", NAMESPACE, "get",
        f"serviceaccount/{SERVICE_ACCOUNT}", "-o", "jsonpath={.secrets[*].name}",
    ).stdout.strip()
    secret_types = kubectl(
        lab, kubeconfig, cluster, "-n", NAMESPACE, "get", "secrets",
        "-o", "custom-columns=TYPE:.type", "--no-headers",
    ).stdout.split()
    lab.check(
        phase,
        "The ServiceAccount has no auto-generated long-lived token Secret reference",
        not names and "kubernetes.io/service-account-token" not in secret_types,
        {"secret_references_present": bool(names), "observed_secret_types": secret_types},
    )


def demonstrate_legacy_behavior(lab, kubeconfig, cluster, context):
    kubectl(lab, kubeconfig, cluster, "create", "namespace", NAMESPACE)
    # Keep the probe SA free of implicit token injection. The fixture's explicit
    # projected token is the positive path under test.
    sa = {
        "apiVersion": "v1", "kind": "ServiceAccount",
        "metadata": {"name": SERVICE_ACCOUNT, "namespace": NAMESPACE},
        "automountServiceAccountToken": False,
    }
    kubectl(lab, kubeconfig, cluster, "create", "-f", "-", payload=json.dumps(sa))
    time.sleep(2)
    assert_no_autogenerated_secret(lab, kubeconfig, cluster, "red")

    secret = json.loads((HERE / "legacy-token-secret.json").read_text())
    kubectl(lab, kubeconfig, cluster, "create", "-f", "-", payload=json.dumps(secret))
    try:
        outcome, observed = observe_legacy_fields(lab, kubeconfig, cluster)
        lab.check(
            "red", f"{context} an explicitly requested legacy Secret is populated",
            outcome,
            {"legacy_secret_field_presence": observed},
        )
    finally:
        # Remove the fixture immediately after observing field presence.
        kubectl(
            lab, kubeconfig, cluster, "-n", NAMESPACE, "delete", f"secret/{LEGACY_SECRET}",
            "--wait=true", timeout=TIMEOUT,
        )
    return secret


def observe_projection(lab, kubeconfig, cluster):
    pod = json.loads((HERE / "projected-token-probe.json").read_text())
    kubectl(lab, kubeconfig, cluster, "create", "-f", "-", payload=json.dumps(pod))
    kubectl(
        lab, kubeconfig, cluster, "-n", NAMESPACE, "wait", "--for=condition=Ready",
        f"pod/{TOKEN_POD}", "--timeout=150s", timeout=TIMEOUT + 140,
    )
    result = kubectl(
        lab, kubeconfig, cluster, "-n", NAMESPACE, "exec", TOKEN_POD, "--",
        "/bin/sh", "-c", CLAIM_OBSERVER,
    ).stdout.strip()
    claims = dict(part.split("=", 1) for part in result.split())
    expected_claims = {
        "claims_exp": "true", "claims_aud": "true", "claims_pod": "true",
        "claims_serviceaccount": "true",
    }
    lab.check(
        "positive",
        "Projected token is present, time bounded, audience-bearing, and bound to Pod and ServiceAccount claims",
        claims == expected_claims,
        claims,
    )


def enforce_policy(lab, kubeconfig, cluster, legacy_secret):
    kubectl(lab, kubeconfig, cluster, "label", "namespace", NAMESPACE, POLICY_LABEL)
    kubectl(lab, kubeconfig, cluster, "apply", "-f", str(HERE / "admission-policy.yaml"))
    # Wait for the admission policy and binding to reach the active chain using
    # dry-run. Then exercise the same actual create operation as the red case.
    deadline = time.monotonic() + 20
    while True:
        result = kubectl(
            lab, kubeconfig, cluster, "create", "-f", "-", "--dry-run=server",
            payload=json.dumps(legacy_secret), allow_failure=True,
        )
        if result.returncode or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    stage_ready = result.returncode != 0 and POLICY in result.stderr and POLICY_MESSAGE in result.stderr
    if not stage_ready:
        lab.block("The case-owned policy did not deny the legacy dry-run")
    result = kubectl(lab, kubeconfig, cluster, "create", "-f", "-",
                     payload=json.dumps(legacy_secret), allow_failure=True)
    denied = result.returncode != 0 and POLICY in result.stderr and POLICY_MESSAGE in result.stderr
    lab.check("green", "Admission rejects the identical explicit legacy Secret create",
              denied, {"policy": POLICY, "message": result.stderr.strip()})
    opaque = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
              "metadata": {"name": "non-token-fixture", "namespace": NAMESPACE}}
    allowed = kubectl(lab, kubeconfig, cluster, "create", "-f", "-", "--dry-run=server",
                      payload=json.dumps(opaque), allow_failure=True)
    lab.check("positive", "The policy still accepts a harmless non-token Secret",
              allowed.returncode == 0, allowed.returncode)


def disabled_profile_config(selection):
    # Kube-controller-manager v1.36.1 calls this controller
    # serviceaccount-token-controller; preserve the stock selections.
    return (
        "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\n"
        "kubeadmConfigPatches:\n  - |\n"
        "    apiVersion: kubeadm.k8s.io/v1beta4\n"
        "    kind: ClusterConfiguration\n"
        "    controllerManager:\n"
        "      extraArgs:\n"
        "        - name: controllers\n"
        f"          value: \"{selection},-{CONTROLLER_NAME}\"\n"
    )


@contextmanager
def disabled_profile(lab, selection):
    cluster = f"{lab.cluster}-legacy-off"
    if cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block(f"Case-owned profile cluster already exists: {cluster}")
    with tempfile.TemporaryDirectory(prefix="saf-token-controller-") as temp:
        kubeconfig = Path(temp) / "kubeconfig"
        config = Path(temp) / "kind.yaml"
        config.write_text(disabled_profile_config(selection))
        attempted = False
        try:
            attempted = True
            lab.command(
                "kind", "create", "cluster", "--name", cluster, "--image", NODE_IMAGE,
                "--config", str(config), "--kubeconfig", str(kubeconfig), "--wait", "90s",
                timeout=480,
            )
            yield cluster, kubeconfig
        finally:
            if attempted:
                result = lab.command(
                    "kind", "delete", "cluster", "--name", cluster,
                    "--kubeconfig", str(kubeconfig), timeout=90, allow_failure=True,
                )
                if result.returncode:
                    lab.block(f"Could not confirm cleanup of profile cluster {cluster}")


def run(lab):
    baseline_args = component_args(lab, lab.kubeconfig, lab.cluster)
    baseline_selection = controller_selection(baseline_args)
    if len(baseline_selection) > 1:
        lab.block("Expected at most one stock controller selection")
    baseline = baseline_selection[0] if baseline_selection else "*"
    baseline_enabled = not {"-" + CONTROLLER_NAME, "-serviceaccount-token"} & set(baseline.split(","))
    lab.check(
        "red", "Stock kubeadm controller-manager has the legacy token controller enabled",
        baseline_enabled,
        {"controller_selection": baseline_selection or ["implicit default *"]},
    )
    demonstrate_legacy_behavior(lab, lab.kubeconfig, lab.cluster, "With the stock controller,")
    observe_projection(lab, lab.kubeconfig, lab.cluster)

    with disabled_profile(lab, baseline) as (cluster, kubeconfig):
        args = component_args(lab, kubeconfig, cluster)
        selection = controller_selection(args)
        has_exclusion = selection == [f"{baseline},-{CONTROLLER_NAME}"]
        lab.check(
            "red", "The live kube-controller-manager process has the controller exclusion flag",
            has_exclusion,
            {"controller_selection": selection},
        )
        secret = demonstrate_legacy_behavior(lab, kubeconfig, cluster, "With the exclusion flag present,")
        enforce_policy(lab, kubeconfig, cluster, secret)
        observe_projection(lab, kubeconfig, cluster)
