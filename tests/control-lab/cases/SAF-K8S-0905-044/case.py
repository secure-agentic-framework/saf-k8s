"""Exercise a synthetic public-model quarantine and offline scan release gate."""
import base64
import hashlib
import json
import ssl
import subprocess
import time
import urllib.error
import urllib.request

from fixtures import BUSYBOX_IMAGE


QUARANTINE = "saf-model-quarantine"
RELEASE = "saf-model-release"
RELEASE_SA = "model-release-authorizer"
UNAUTHORIZED_SA = "model-unapproved-caller"
RELEASE_POD = "clean-model-release-witness"
POLICY = "model-release-requires-clean-scan"
APPROVED_DIGEST = "saf.example/model-metadata-sha256"
SCAN_LABEL = "saf.example/scan-decision"
AUTH_LABEL = "saf.example/release-authorization"

PUBLIC_FIXTURE = {
    "source": "fixture://public-model-hub/example/model-v1",
    "model_id": "example/model-v1",
    "revision": "fixture-revision-001",
    "contains_model_bytes": False,
}
MODEL_METADATA_SHA256 = hashlib.sha256(
    json.dumps(PUBLIC_FIXTURE, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()

SCOPE = (
    "A disposable Kubernetes v1.36.1 Kind cluster uses synthetic public-model metadata only; "
    "no model bytes or scanner signatures are downloaded or created. The case applies a restricted "
    "quarantine namespace and default-deny ingress/egress NetworkPolicy, then uses the built-in "
    "Pod Security Admission controller and a ValidatingAdmissionPolicy to reject nonconforming "
    "pods and release pods whose clean-scan decision or exact metadata digest does not match. "
    "A narrowly bound ServiceAccount creates the positive release pod through the Kubernetes API; "
    "a different ServiceAccount is denied. Synthetic offline scanner records exercise malware, "
    "unsafe-format, embedded-content, missing, and subject-mismatch decisions. This verifies the "
    "fixture policy, Kubernetes admission, API authorization, and exact metadata-digest readback. "
    "It does not execute a scanner, inspect actual model content, prove NetworkPolicy packet drops "
    "on Kind's default CNI, or prove production scanner coverage, source authenticity, model "
    "behavioral safety, promotion workflow adoption, or durable audit storage."
)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _sha256(value):
    return hashlib.sha256(value).hexdigest()


def _scan_decision(subject_digest, results):
    expected = {"malicious_payloads": "clean",
                "format": "safe",
                "embedded_content": "allowed"}
    if subject_digest != MODEL_METADATA_SHA256:
        return "reject-subject-mismatch"
    for category, wanted in expected.items():
        if results.get(category) != wanted:
            return "reject-" + category
    return "release-clean"


def _ns(name, purpose):
    return {"apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": name,
                         "labels": {
                             "pod-security.kubernetes.io/enforce": "restricted",
                             "pod-security.kubernetes.io/enforce-version": "v1.36",
                             "saf.example/purpose": purpose,
                         }}}


def _release_policy():
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {
                "matchPolicy": "Equivalent",
                "namespaceSelector": {"matchLabels": {"saf.example/purpose": "model-release"}},
                "resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                   "operations": ["CREATE", "UPDATE"], "resources": ["pods"]}],
            },
            "validations": [{
                "expression": (
                    "has(object.metadata.labels) && "
                    f"object.metadata.labels['{SCAN_LABEL}'] == 'clean' && "
                    f"object.metadata.labels['{AUTH_LABEL}'] == 'approved' && "
                    "has(object.metadata.annotations) && "
                    f"object.metadata.annotations['{APPROVED_DIGEST}'] == '{MODEL_METADATA_SHA256}'"
                ),
                "message": "release pod must carry the clean decision and exact approved model metadata digest",
            }],
        },
    }


def _policy_binding():
    return {"apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "ValidatingAdmissionPolicyBinding",
            "metadata": {"name": POLICY},
            "spec": {"policyName": POLICY,
                     "validationActions": ["Deny"],
                     "matchResources": {"namespaceSelector": {
                         "matchLabels": {"saf.example/purpose": "model-release"}}}}}


def _pod(name, digest, scan="clean", authorization="approved"):
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name,
                         "labels": {SCAN_LABEL: scan, AUTH_LABEL: authorization},
                         "annotations": {APPROVED_DIGEST: digest}},
            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                     "containers": [{"name": "fixture", "image": BUSYBOX_IMAGE,
                                     "command": ["sh", "-c", "sleep 3600"],
                                     "securityContext": {"allowPrivilegeEscalation": False,
                                                         "capabilities": {"drop": ["ALL"]},
                                                         "runAsNonRoot": True,
                                                         "runAsUser": 65534,
                                                         "seccompProfile": {"type": "RuntimeDefault"}}}]}}


def _api_client(lab, service_account):
    """Build an in-memory API client; never write or log the short-lived token."""
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
            f"kind-{lab.cluster}", "--namespace", RELEASE, "create", "token",
            service_account, "--duration=10m"]
    try:
        token_result = subprocess.run(args, text=True, capture_output=True,
                                      env=dict(lab.env), timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("Release ServiceAccount TokenRequest did not complete")
    if token_result.returncode or not token_result.stdout.strip():
        lab.block("Release ServiceAccount TokenRequest failed")
    token = token_result.stdout.strip()

    view_args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
                 f"kind-{lab.cluster}", "config", "view", "--raw", "-o", "json"]
    try:
        view = subprocess.run(view_args, text=True, capture_output=True,
                             env=dict(lab.env), timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        lab.block("Could not read the temporary Kind API endpoint")
    if view.returncode:
        lab.block("Could not read the temporary Kind API endpoint")
    config = json.loads(view.stdout)
    context = next(item["context"] for item in config["contexts"]
                   if item["name"] == f"kind-{lab.cluster}")
    cluster = next(item["cluster"] for item in config["clusters"]
                   if item["name"] == context["cluster"])
    ca = base64.b64decode(cluster["certificate-authority-data"])
    return cluster["server"], token, ssl.create_default_context(cadata=ca.decode())


def _api_post_pod(lab, service_account, manifest, *, dry_run=False):
    server, token, tls = _api_client(lab, service_account)
    url = f"{server}/api/v1/namespaces/{RELEASE}/pods"
    if dry_run:
        url += "?dryRun=All"
    request = urllib.request.Request(
        url, data=json.dumps(manifest, sort_keys=True).encode(), method="POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPSHandler(context=tls))
        with opener.open(request, timeout=15) as response:
            status = response.status
            body = json.load(response)
    except urllib.error.HTTPError as response:
        status = response.code
        try:
            body = json.load(response)
        except (ValueError, OSError):
            body = {"reason": "non-json-api-error"}
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        lab.block("Kubernetes API request for the release witness failed")
    return status, body


def _denial_reason(body):
    details = body.get("details", {}) if isinstance(body, dict) else {}
    return body.get("reason") or details.get("causes", [{}])[0].get("reason") or "unknown"


def create_in(lab, namespace, obj):
    result = lab.kubectl("-n", namespace, "create", "-f", "-", "-o", "json",
                         payload=json.dumps(obj, sort_keys=True))
    return json.loads(result.stdout)


def run(lab):
    raw = {"fixture_metadata": PUBLIC_FIXTURE,
           "fixture_metadata_sha256": MODEL_METADATA_SHA256,
           "synthetic_scanner": {"mode": "offline-fixture-only",
                                 "scanner_executed": False,
                                 "signatures_downloaded": False}}

    # A control-off public source reference can enter the default runner namespace.
    baseline = {"apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": "unchecked-public-model-reference",
                             "annotations": {"saf.example/model-source": PUBLIC_FIXTURE["source"]}},
                "spec": _pod("baseline", MODEL_METADATA_SHA256)["spec"]}
    baseline_result = lab.kubectl("create", "-f", "-", "-o", "json",
                                  payload=json.dumps(baseline, sort_keys=True),
                                  allow_failure=True)
    baseline_status = 201 if baseline_result.returncode == 0 else 0
    raw["admission_baseline"] = {"status": baseline_status,
                                  "stdout": baseline_result.stdout,
                                  "stderr": baseline_result.stderr}
    if baseline_status == 201:
        lab.kubectl("delete", "pod", "unchecked-public-model-reference", "--ignore-not-found=true")

    lab.create(_ns(QUARANTINE, "model-quarantine"))
    lab.create(_ns(RELEASE, "model-release"))
    default_deny = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                    "metadata": {"name": "default-deny-all", "namespace": QUARANTINE},
                    "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}}
    create_in(lab, QUARANTINE, default_deny)
    observed_policy = json.loads(lab.kubectl(
        "get", "networkpolicy", "default-deny-all", "-n", QUARANTINE, "-o", "json").stdout)
    raw["quarantine_network_policy"] = observed_policy
    candidate = _pod("quarantined-model-candidate", MODEL_METADATA_SHA256)
    candidate["metadata"]["namespace"] = QUARANTINE
    candidate["metadata"]["annotations"].update({
        "saf.example/model-source": PUBLIC_FIXTURE["source"],
        "saf.example/artifact-content": "metadata-only-fixture",
    })
    create_in(lab, QUARANTINE, candidate)
    candidate_readback = json.loads(lab.kubectl(
        "get", "pod", "quarantined-model-candidate", "-n", QUARANTINE, "-o", "json").stdout)
    raw["quarantined_candidate"] = candidate_readback

    # Pod Security Admission is a real API-server admission test in the quarantined namespace.
    privileged = {"apiVersion": "v1", "kind": "Pod",
                  "metadata": {"name": "privileged-quarantine-probe", "namespace": QUARANTINE},
                  "spec": {"containers": [{"name": "probe", "image": BUSYBOX_IMAGE,
                                            "command": ["sh", "-c", "sleep 10"],
                                            "securityContext": {"privileged": True}}]}}
    psa = lab.kubectl("-n", QUARANTINE, "create", "--dry-run=server", "-f", "-", "-o", "json",
                      payload=json.dumps(privileged),
                      allow_failure=True)
    psa_text = psa.stdout + psa.stderr
    raw["pod_security_admission"] = {"status": 201 if psa.returncode == 0 else 0,
                                      "stdout": psa.stdout, "stderr": psa.stderr}

    # Model intake decisions are synthetic scanner metadata, never model content.
    clean_results = {"malicious_payloads": "clean", "format": "safe",
                     "embedded_content": "allowed"}
    scenarios = {
        "clean": (MODEL_METADATA_SHA256, clean_results),
        "malicious_payload": (MODEL_METADATA_SHA256,
                              {**clean_results, "malicious_payloads": "detected"}),
        "unsafe_format": (MODEL_METADATA_SHA256,
                          {**clean_results, "format": "unsafe"}),
        "disallowed_embedded_content": (MODEL_METADATA_SHA256,
                                        {**clean_results, "embedded_content": "disallowed"}),
        "subject_mismatch": ("0" * 64, clean_results),
        "missing_category": (MODEL_METADATA_SHA256,
                             {"malicious_payloads": "clean", "format": "safe"}),
    }
    decisions = {}
    for name, (digest, result) in scenarios.items():
        decisions[name] = {"subject_sha256": digest, "synthetic_results": result,
                           "decision": _scan_decision(digest, result)}
    raw["scan_decisions"] = decisions

    # The release admission policy requires all three fixed evidence labels and the exact digest.
    lab.create(_release_policy())
    lab.create(_policy_binding())
    for name in (RELEASE_SA, UNAUTHORIZED_SA):
        create_in(lab, RELEASE, {"apiVersion": "v1", "kind": "ServiceAccount",
                    "metadata": {"name": name, "namespace": RELEASE}})
    create_in(lab, RELEASE, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": "model-release-pod-creator", "namespace": RELEASE},
                "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}]})
    create_in(lab, RELEASE, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": "model-release-pod-creator", "namespace": RELEASE},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                            "name": "model-release-pod-creator"},
                "subjects": [{"kind": "ServiceAccount", "name": RELEASE_SA,
                              "namespace": RELEASE}]})

    # Exercise the policy with different records and with two distinct API principals.
    wrong_digest = _pod("wrong-digest-release-witness", "0" * 64)
    deadline = time.monotonic() + 30
    while True:
        mismatch_status, mismatch_body = _api_post_pod(lab, RELEASE_SA, wrong_digest, dry_run=True)
        if "exact approved model metadata digest" in mismatch_body.get("message", ""):
            break
        if time.monotonic() >= deadline:
            lab.block("Release policy did not produce the expected native admission decision")
        time.sleep(0.5)
    unauthorized_status, unauthorized_body = _api_post_pod(
        lab, UNAUTHORIZED_SA, _pod("unauthorized-release-witness", MODEL_METADATA_SHA256))
    clean_status, clean_body = _api_post_pod(
        lab, RELEASE_SA, _pod(RELEASE_POD, MODEL_METADATA_SHA256))
    if clean_status == 201:
        lab.kubectl("-n", RELEASE, "wait", "--for=condition=Ready", f"pod/{RELEASE_POD}",
                    "--timeout=95s", timeout=105)
    clean_readback = json.loads(lab.kubectl("get", "pod", RELEASE_POD, "-n", RELEASE,
                                            "-o", "json").stdout) if clean_status == 201 else {}
    raw["release_api_attempts"] = {
        "wrong_digest": {"status": mismatch_status, "body": mismatch_body},
        "unauthorized_principal": {"status": unauthorized_status, "body": unauthorized_body},
        "authorized_clean": {"status": clean_status, "body": clean_body,
                              "readback": clean_readback},
    }

    normalized = {
        "case": "SAF-K8S-0905-044",
        "fixture_metadata_sha256": MODEL_METADATA_SHA256,
        "scanner": {"mode": "synthetic-offline-decision-witness",
                    "executed": False, "model_bytes_present": False,
                    "signatures_downloaded": False},
        "red": {"unchecked_public_reference_admitted": baseline_status == 201},
        "isolation": {
            "quarantine_namespace_pod_security": "restricted",
            "candidate_admitted_to_quarantine": candidate_readback.get("metadata", {}).get(
                "namespace") == QUARANTINE,
            "privileged_pod_rejected": psa.returncode != 0 and "violates PodSecurity" in psa_text,
            "default_deny_ingress_and_egress_policy_present": (
                observed_policy.get("spec") == {"podSelector": {},
                                                  "policyTypes": ["Ingress", "Egress"]}),
            "network_policy_packet_drop_proven": False,
        },
        "scan_decisions": {name: row["decision"] for name, row in decisions.items()},
        "release": {
            "wrong_digest_admission_denied": mismatch_status == 422 and _denial_reason(mismatch_body) == "Invalid" and
                "exact approved model metadata digest" in mismatch_body.get("message", ""),
            "unauthorized_service_account_denied": unauthorized_status == 403,
            "authorized_clean_digest_admitted": clean_status == 201 and
                clean_readback.get("metadata", {}).get("annotations", {}).get(APPROVED_DIGEST)
                == MODEL_METADATA_SHA256,
            "release_readback_sha256": MODEL_METADATA_SHA256 if clean_readback else None,
        },
    }

    (lab.evidence / "raw-observations.json").write_text(
        json.dumps(raw, indent=2, sort_keys=True) + "\n")
    (lab.evidence / "normalized-evidence.json").write_text(
        json.dumps(normalized, indent=2, sort_keys=True) + "\n")

    lab.check("red", "An unchecked public-model reference is admitted in the default runner namespace",
              baseline_status == 201,
              {"status": baseline_status, "source": PUBLIC_FIXTURE["source"]})
    policy_matches = (observed_policy.get("spec") == {"podSelector": {},
                                                        "policyTypes": ["Ingress", "Egress"]})
    lab.check("green", "Quarantine applies restricted Pod Security and a default-deny policy",
              candidate_readback.get("metadata", {}).get("namespace") == QUARANTINE and
              psa.returncode != 0 and "violates PodSecurity" in psa_text and policy_matches,
              {"candidate_namespace": candidate_readback.get("metadata", {}).get("namespace"),
               "pod_security_denied": psa.returncode != 0 and "violates PodSecurity" in psa_text,
               "network_policy": policy_matches,
               "traffic_drop_proven": False})
    expected_rejections = {
        "malicious_payload": "reject-malicious_payloads",
        "unsafe_format": "reject-format",
        "disallowed_embedded_content": "reject-embedded_content",
        "subject_mismatch": "reject-subject-mismatch",
        "missing_category": "reject-embedded_content",
    }
    all_rejected = all(decisions[name]["decision"] == wanted
                       for name, wanted in expected_rejections.items())
    lab.check("green", "Synthetic offline scan results block unsafe, incomplete, or mismatched records",
              all_rejected, {name: decisions[name]["decision"] for name in expected_rejections})
    lab.check("green", "Release admission rejects a nonmatching model metadata digest",
              mismatch_status == 422 and _denial_reason(mismatch_body) == "Invalid" and "exact approved model metadata digest" in mismatch_body.get("message", ""),
              {"status": mismatch_status, "reason": _denial_reason(mismatch_body)})
    lab.check("green", "Release RBAC denies a different ServiceAccount",
              unauthorized_status == 403 and UNAUTHORIZED_SA in unauthorized_body.get("message", "")
              and "cannot create resource" in unauthorized_body.get("message", ""),
              {"status": unauthorized_status, "reason": _denial_reason(unauthorized_body)})
    lab.check("positive", "The authorized release principal admits and reads back the exact clean digest",
              clean_status == 201
              and clean_readback["metadata"]["uid"] == clean_body["metadata"]["uid"]
              and clean_readback["status"]["containerStatuses"][0]["ready"] and
              clean_readback.get("metadata", {}).get("labels", {}).get(SCAN_LABEL) == "clean" and
              clean_readback.get("metadata", {}).get("labels", {}).get(AUTH_LABEL) == "approved" and
              clean_readback.get("metadata", {}).get("annotations", {}).get(APPROVED_DIGEST)
              == MODEL_METADATA_SHA256,
              {"status": clean_status, "digest": clean_readback.get("metadata", {}).get(
                  "annotations", {}).get(APPROVED_DIGEST)})
