"""Verify opt-out at both supported scopes using live container observations."""
from pathlib import Path

from fixtures import container, pod, ready

SCOPE = "Linux Pod and ServiceAccount opt-out, Pod-level precedence, and least-privilege API access."
TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
API_IMAGE = (
    "docker.io/curlimages/curl:8.17.0@sha256:"
    "935d9100e9ba842cdb060de42472c7ca90cfe9a7c96e4dacb55e79e560b3ff40"
)
NAMESPACE = "saf-test"
TARGET = "saf-0304-007-allowed"
OTHER = "saf-0304-007-denied"


def observe(lab, name, phase, expected, **spec):
    lab.create(pod(name, [container("probe")], **spec))
    ready(lab, name)
    observed = lab.kubectl(
        "exec", name, "--", "sh", "-c",
        'if test -s "$1"; then printf present; else printf absent; fi',
        "probe", TOKEN,
    ).stdout.strip()
    lab.check(phase, f"{name} token is {expected}", observed == expected, observed)


def api_probe(lab, name, path, expected_status, *, phase, expected_marker=False):
    script = r'''set -eu
umask 077
token_file=/var/run/secrets/kubernetes.io/serviceaccount/token
ca_file=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
config=/tmp/saf-api-curl.conf
body=/tmp/saf-api-response.json
trap 'rm -f "$config" "$body"' EXIT
printf 'header = "Authorization: Bearer %s"\n' "$(cat "$token_file")" > "$config"
unset token_file
status=$(curl --silent --show-error --cacert "$ca_file" --config "$config" \
  --output "$body" --write-out '%{http_code}' "$1")
if grep -q 'saf-0304-007-granted-marker' "$body"; then
  printf '%s marker-present' "$status"
else
  printf '%s marker-absent' "$status"
fi
'''
    url = f"https://kubernetes.default.svc/api/v1/namespaces/{NAMESPACE}/{path}"
    result = lab.kubectl("exec", name, "--", "sh", "-c", script, "probe", url)
    observed = result.stdout.strip()
    expected = f"{expected_status} marker-present" if expected_marker else f"{expected_status} marker-absent"
    lab.check(phase, f"TLS API request {path} returns {expected}", observed == expected,
             observed)


def run(lab):
    observe(lab, "default-mount", "red", "present")
    lab.apply(Path(__file__).with_name("serviceaccounts.yaml"))
    observe(lab, "pod-opt-out", "green", "absent", automountServiceAccountToken=False)
    observe(lab, "account-opt-out", "green", "absent", serviceAccountName="opted-out")
    observe(lab, "explicit-opt-in", "positive", "present",
            serviceAccountName="opted-out", automountServiceAccountToken=True)

    case_dir = Path(__file__).parent
    lab.apply(case_dir / "api-resources.yaml")
    api_name = "explicit-api-probe"
    lab.create(pod(
        api_name,
        [{"name": "probe", "image": API_IMAGE, "command": ["sh", "-c", "sleep 3600"],
          "securityContext": {"allowPrivilegeEscalation": False,
                              "capabilities": {"drop": ["ALL"]},
                              "runAsNonRoot": True, "runAsUser": 100,
                              "seccompProfile": {"type": "RuntimeDefault"}}}],
        serviceAccountName="opted-out", automountServiceAccountToken=True,
    ))
    ready(lab, api_name)

    api_probe(lab, api_name, f"configmaps/{TARGET}", "403", phase="red")

    lab.apply(case_dir / "api-rolebinding.yaml")
    api_probe(lab, api_name, f"configmaps/{TARGET}", "200", phase="positive", expected_marker=True)
    api_probe(lab, api_name, f"configmaps/{OTHER}", "403", phase="green")
    api_probe(lab, api_name, "configmaps", "403", phase="green")
