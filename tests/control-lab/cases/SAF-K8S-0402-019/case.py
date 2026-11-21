"""Verify distinct workload ServiceAccounts and per-fixture least privilege."""
from pathlib import Path

from fixtures import pod, ready

SCOPE = (
    "Two workloads with explicitly provisioned Kubernetes ServiceAccounts and "
    "separate namespace Roles; projected Kubernetes API tokens and local synthetic fixtures. "
    "External cloud identity federation and cloud IAM permissions are outside this lab."
)
TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
API_IMAGE = (
    "docker.io/curlimages/curl:8.17.0@sha256:"
    "935d9100e9ba842cdb060de42472c7ca90cfe9a7c96e4dacb55e79e560b3ff40"
)
NAMESPACE = "saf-test"
WORKLOADS = {
    "workload-alpha": ("saf-0402-019-alpha", "saf-0402-019-alpha-fixture", "alpha-marker"),
    "workload-beta": ("saf-0402-019-beta", "saf-0402-019-beta-fixture", "beta-marker"),
}


def api_pod(name, service_account):
    return pod(name, [{
        "name": "probe", "image": API_IMAGE,
        "command": ["sh", "-c", "sleep 3600"],
        "securityContext": {"allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                            "runAsNonRoot": True, "runAsUser": 100,
                            "seccompProfile": {"type": "RuntimeDefault"}},
    }], serviceAccountName=service_account, automountServiceAccountToken=True)


def api_probe(lab, pod_name, configmap, expected_marker=None):
    script = r'''set -eu
umask 077
token_file=/var/run/secrets/kubernetes.io/serviceaccount/token
ca_file=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
config=/tmp/saf-0402-019-curl.conf
body=/tmp/saf-0402-019-response.json
trap 'rm -f "$config" "$body"' EXIT
printf 'header = "Authorization: Bearer %s"\n' "$(cat "$token_file")" > "$config"
unset token_file
status=$(curl --silent --show-error --cacert "$ca_file" --config "$config" \
  --output "$body" --write-out '%{http_code}' "$1")
marker_pattern="\"$2\""
if [ "$status" = 200 ] && grep -Fq "$marker_pattern" "$body"; then
  printf '%s expected-marker' "$status"
else
  printf '%s no-expected-marker' "$status"
fi
'''
    url = f"https://kubernetes.default.svc/api/v1/namespaces/{NAMESPACE}/configmaps/{configmap}"
    result = lab.kubectl("exec", pod_name, "--", "sh", "-c", script, "probe",
                         url, expected_marker or "__no_marker_expected__")
    return result.stdout.strip()


def subject(lab, pod_name):
    # Decode only the JWT subject in the Pod; the credential itself never leaves it.
    script = r'''set -eu
token_file=/var/run/secrets/kubernetes.io/serviceaccount/token
payload=$(cut -d. -f2 "$token_file" | tr '_-' '/+')
case $((${#payload} % 4)) in
  2) payload="${payload}==" ;;
  3) payload="${payload}=" ;;
esac
printf '%s' "$payload" | base64 -d | sed -n 's/.*"sub":"\([^"]*\)".*/\1/p'
'''
    return lab.kubectl("exec", pod_name, "--", "sh", "-c", script, "probe").stdout.strip()


def run(lab):
    case_dir = Path(__file__).parent
    lab.apply(case_dir / "fixtures-and-identities.yaml")

    for name, (service_account, _, _) in WORKLOADS.items():
        lab.create(api_pod(name, service_account))
        ready(lab, name)

    alpha_identity = subject(lab, "workload-alpha")
    beta_identity = subject(lab, "workload-beta")
    lab.check(
        "positive", "Running Pods have distinct explicitly assigned ServiceAccount identities",
        alpha_identity == f"system:serviceaccount:{NAMESPACE}:saf-0402-019-alpha"
        and beta_identity == f"system:serviceaccount:{NAMESPACE}:saf-0402-019-beta"
        and alpha_identity != beta_identity,
        f"alpha={alpha_identity}; beta={beta_identity}",
    )

    for pod_name, (_, own_fixture, _) in WORKLOADS.items():
        observed = api_probe(lab, pod_name, own_fixture)
        lab.check("red", f"{pod_name} cannot read its fixture before its intended binding",
                  observed == "403 no-expected-marker", observed)

    lab.apply(case_dir / "scoped-roles-and-bindings.yaml")

    for pod_name, (_, own_fixture, own_marker) in WORKLOADS.items():
        observed = api_probe(lab, pod_name, own_fixture, own_marker)
        lab.check("positive", f"{pod_name} reads its own fixture over verified TLS",
                  observed == "200 expected-marker", observed)

    for pod_name, (_, own_fixture, _) in WORKLOADS.items():
        other_fixture = next(
            fixture for other_name, (_, fixture, _) in WORKLOADS.items()
            if other_name != pod_name
        )
        observed = api_probe(lab, pod_name, other_fixture)
        lab.check("green", f"{pod_name} is denied the other workload fixture",
                  observed == "403 no-expected-marker", observed)
