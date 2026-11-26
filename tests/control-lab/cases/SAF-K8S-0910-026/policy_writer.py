"""In-cluster writer for one fixed SAF-K8S-0910-026 synthetic bundle."""
import hashlib
import json
from pathlib import Path
import ssl
import sys
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener


NS = "saf026-control"
APPROVAL = "saf026-approved-baseline"
ENVELOPE = "saf026-approved-envelope"
WRONG = "saf026-wrong-version-envelope"
POLICY = "saf026-ai-deployment-baseline-v1"
BINDING = "saf026-ai-deployment-baseline-v1"
TOKEN = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
API = "https://kubernetes.default.svc"


def request(opener, token, method, path, value=None):
    body = None if value is None else json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/merge-patch+json"
    req = Request(API + path, data=body, headers=headers, method=method)
    with opener.open(req, timeout=8) as response:
        raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("bounded API response exceeded")
        return response.status, json.loads(raw) if raw else {}


def emit(value):
    print(json.dumps(value, sort_keys=True, separators=(",", ":")), flush=True)


def main(mode):
    if mode not in {"withhold", "apply"}:
        emit({"decision": "error", "matched": False})
        return 2
    try:
        token = TOKEN.read_text().strip()
        if not token:
            raise ValueError("projected token missing")
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context(cafile=CA)))
        prefix = "/api/v1/namespaces/" + NS + "/configmaps/"
        approval_status, approval = request(opener, token, "GET", prefix + APPROVAL)
        source_name = WRONG if mode == "withhold" else ENVELOPE
        envelope_status, source = request(opener, token, "GET", prefix + source_name)
        data = source.get("data", {})
        encoded = data.get("resources.json", "")
        payload = encoded.encode()
        payload_sha = hashlib.sha256(payload).hexdigest()
        envelope = json.loads(encoded)
        resources = envelope.get("resources", [])
        policy = next((item for item in resources if item.get("kind") == "ValidatingAdmissionPolicy"), {})
        binding = next((item for item in resources if item.get("kind") == "ValidatingAdmissionPolicyBinding"), {})
        fixed_resources = (
            len(resources) == 2
            and policy.get("metadata", {}).get("name") == POLICY
            and binding.get("metadata", {}).get("name") == BINDING
            and policy.get("apiVersion") == "admissionregistration.k8s.io/v1"
            and binding.get("apiVersion") == "admissionregistration.k8s.io/v1"
        )
        approved = approval.get("data", {})
        version_match = data.get("version") == approved.get("version") == "v1"
        bundle_match = data.get("bundle_sha256") == approved.get("sha256")
        envelope_match = payload_sha == approved.get("envelope_sha256") == data.get("sha256")
        if approval_status != 200 or envelope_status != 200:
            raise ValueError("approval or envelope read did not succeed")
        if not (version_match and bundle_match and envelope_match and fixed_resources):
            emit({"decision": "withheld", "version_match": version_match,
                  "bundle_match": bundle_match, "envelope_match": envelope_match,
                  "fixed_resources": fixed_resources, "no_write": True})
            return 0 if mode == "withhold" and not version_match else 1
        if mode == "withhold":
            emit({"decision": "error", "version_match": True, "no_write": True})
            return 1

        policy_path = "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/" + POLICY
        binding_path = "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/" + BINDING
        policy_status, _ = request(opener, token, "PATCH", policy_path,
                                   {"metadata": {"annotations": policy["metadata"]["annotations"]},
                                    "spec": policy["spec"]})
        binding_status, _ = request(opener, token, "PATCH", binding_path,
                                    {"metadata": {"annotations": binding["metadata"]["annotations"]},
                                     "spec": binding["spec"]})
        emit({"decision": "applied", "version_match": version_match,
              "bundle_match": bundle_match, "envelope_match": envelope_match,
              "fixed_resources": fixed_resources,
              "policy_patch_accepted": policy_status == 200,
              "binding_patch_accepted": binding_status == 200})
        return 0 if policy_status == binding_status == 200 else 1
    except (OSError, ValueError, KeyError, StopIteration, HTTPError, URLError, TimeoutError):
        emit({"decision": "error", "matched": False})
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) == 2 else ""))
