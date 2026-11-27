"""Exercise a synthetic public-model quarantine and offline scan release gate."""
import base64
import hashlib
import json
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from fixtures import BUSYBOX_IMAGE, container, pod


QUARANTINE = "saf-model-quarantine"
RELEASE = "saf-model-release"
RELEASE_SA = "model-release-authorizer"
UNAUTHORIZED_SA = "model-unapproved-caller"
UPDATE_SA = "model-release-update-reviewer"
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

PYTHON_SCANNER_IMAGE = (
    "docker.io/library/python:3.13.2-alpine@sha256:"
    "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352"
)
MODEL_ARTIFACT = {
    "format": "saf-inert-model-json-v1",
    "model_id": "fixture-model-0905-044",
    "marker": "approved-fixture-marker-v1",
    "parameters": [0.25, -0.5],
}
MODEL_ARTIFACT_BYTES = json.dumps(
    MODEL_ARTIFACT, sort_keys=True, separators=(",", ":")
).encode("utf-8")
MODEL_ARTIFACT_SHA256 = hashlib.sha256(MODEL_ARTIFACT_BYTES).hexdigest()
ARTIFACT_DIGEST_ANNOTATION = "saf.example/scanned-artifact-sha256"
SCANNER_JOB = "saf-fixture-model-scanner"
SCANNER_SOURCE = r'''import hashlib, json, math
from pathlib import Path

raw = Path("/fixture/model.json").read_bytes()
bounded = len(raw) <= 2048
status = "reject"
format_allowed = False
marker_policy_allowed = False
if bounded:
    try:
        value = json.loads(raw.decode("utf-8"))
        format_allowed = (isinstance(value, dict)
                          and value.get("format") == "saf-inert-model-json-v1"
                          and value.get("model_id") == "fixture-model-0905-044"
                          and set(value) == {"format", "model_id", "marker", "parameters"})
        parameters = value.get("parameters", []) if isinstance(value, dict) else []
        marker_policy_allowed = (
            isinstance(value, dict)
            and value.get("marker") == "approved-fixture-marker-v1"
            and isinstance(parameters, list) and len(parameters) == 2
            and all(type(item) in (int, float) and math.isfinite(item) and -1 <= item <= 1
                    for item in parameters)
        )
        if format_allowed and marker_policy_allowed:
            status = "pass"
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
print(json.dumps({"status": status,
                  "artifact_sha256": hashlib.sha256(raw).hexdigest(),
                  "format_allowed": format_allowed,
                  "marker_policy_allowed": marker_policy_allowed,
                  "within_size_limit": bounded}, sort_keys=True))
'''

SCOPE = (
    "A disposable Kubernetes v1.36.1 Kind cluster uses synthetic public-model metadata and "
    "fixed inert model-like JSON specimens. The pinned YARA-X engine evaluates a local "
    "marker rule offline. Bundled kindnet is checked "
    "ready. The case applies a restricted quarantine namespace and default-deny ingress/egress "
    "NetworkPolicy, then proves its egress effect against two case-owned marker-only listeners "
    "with one exact allow exception and an unaffected comparator. It then uses the built-in "
    "Pod Security Admission controller and a ValidatingAdmissionPolicy to reject nonconforming "
    "pods and release pods whose clean-scan decision or exact metadata digest does not match. "
    "A narrowly bound ServiceAccount creates the positive release pod through the Kubernetes API; "
    "an additional tokenless restricted Job reads a fixed inert model-like JSON fixture, checks only "
    "its approved format and fixed marker policy, hashes the exact bytes, and binds the observed hash "
    "to the native release ValidatingAdmissionPolicy. A different ServiceAccount is denied. "
    "Synthetic offline decision records exercise malware, "
    "unsafe-format, embedded-content, missing, and subject-mismatch decisions. This verifies the "
    "fixture policy, Kubernetes admission, API authorization, and exact metadata-digest readback. "
    "The marker comparison establishes the YARA-X rule behavior for these inert JSON specimens. "
    "Real model contents, scanner coverage, the adopted CNI, source authenticity, behavioral safety, "
    "production promotion and durable audit storage need deployment evidence. A scoped update identity "
    "also verifies that native release admission preserves the exact scanned digest after creation."
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
            }, {
                "expression": (
                    "has(object.metadata.annotations) && "
                    f"object.metadata.annotations['{ARTIFACT_DIGEST_ANNOTATION}'] == '{MODEL_ARTIFACT_SHA256}'"
                ),
                "message": "release pod must carry the exact scanned artifact digest",
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


def _pod(name, digest, scan="clean", authorization="approved",
         artifact_digest=MODEL_ARTIFACT_SHA256):
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name,
                         "labels": {SCAN_LABEL: scan, AUTH_LABEL: authorization},
                         "annotations": {APPROVED_DIGEST: digest,
                                         ARTIFACT_DIGEST_ANNOTATION: artifact_digest}},
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


def _api_patch_pod(lab, service_account, name, patch):
    """Send one in-memory merge patch as a case-owned ServiceAccount."""
    server, token, tls = _api_client(lab, service_account)
    url = f"{server}/api/v1/namespaces/{RELEASE}/pods/{name}"
    request = urllib.request.Request(
        url, data=json.dumps(patch, sort_keys=True).encode(), method="PATCH",
        headers={"Authorization": "Bearer " + token,
                 "Content-Type": "application/merge-patch+json"})
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPSHandler(context=tls))
        with opener.open(request, timeout=15) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as response:
        status = response.code
        try:
            body = json.load(response)
        except (ValueError, OSError):
            body = {"reason": "non-json-api-error"}
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        lab.block("Kubernetes API request for the release metadata update failed")
    return status, body


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


def _run_scanner_job(lab, job_name, image, image_pull_policy, data):
    """Run a restricted scanner against immutable fixture data."""
    config_name = job_name + "-inputs"
    config_created = False
    try:
        create_in(lab, QUARANTINE, {
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": config_name, "labels": {"saf.example/fixture": "model-scan"}},
            "immutable": True,
            "data": data,
        })
        config_created = True
        create_in(lab, QUARANTINE, {
            "apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": job_name, "labels": {"saf.example/fixture": "model-scan"}},
            "spec": {
                "backoffLimit": 0,
                "activeDeadlineSeconds": 45,
                "template": {
                    "metadata": {"labels": {"saf.example/fixture": "model-scan"}},
                    "spec": {
                        "restartPolicy": "Never",
                        "automountServiceAccountToken": False,
                        "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                             "runAsGroup": 1000,
                                             "seccompProfile": {"type": "RuntimeDefault"}},
                        "containers": [{
                            "name": "fixture-inspector",
                            "image": image,
                            "imagePullPolicy": image_pull_policy,
                            "command": ["python", "-B", "/fixture/scanner.py"],
                            "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
                            "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                          "limits": {"cpu": "250m", "memory": "192Mi"}},
                            "securityContext": {"allowPrivilegeEscalation": False,
                                                 "readOnlyRootFilesystem": True,
                                                 "capabilities": {"drop": ["ALL"]}},
                        }],
                        "volumes": [{"name": "fixture", "configMap": {"name": config_name}}],
                    },
                },
            },
        })
        lab.kubectl("-n", QUARANTINE, "wait", "--for=condition=complete", f"job/{job_name}",
                    "--timeout=50s", timeout=60)
        output = lab.kubectl("-n", QUARANTINE, "logs", f"job/{job_name}").stdout.strip()
        receipt = json.loads(output)
    except (ValueError, KeyError):
        lab.block("The bounded fixture scanner returned no stable JSON receipt")
    finally:
        lab.kubectl("-n", QUARANTINE, "delete", "job", job_name,
                    "--ignore-not-found=true", "--wait=true", allow_failure=True)
        if config_created:
            lab.kubectl("-n", QUARANTINE, "delete", "configmap", config_name,
                        "--ignore-not-found=true", allow_failure=True)
    return receipt


def _run_fixture_scanner(lab):
    receipt = _run_scanner_job(lab, SCANNER_JOB, PYTHON_SCANNER_IMAGE, "IfNotPresent", {
        "model.json": MODEL_ARTIFACT_BYTES.decode(), "scanner.py": SCANNER_SOURCE,
    })
    expected_fields = {"status", "artifact_sha256", "format_allowed",
                       "marker_policy_allowed", "within_size_limit"}
    return receipt if set(receipt) == expected_fields else {}


def _run_yara_scan(lab):
    """Run a verified pinned YARA-X wheel against two owned inert inputs."""
    root = Path(__file__).resolve().parent
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    architectures = {node["status"]["nodeInfo"]["architecture"] for node in nodes}
    wheels = json.loads((root / "yara-wheel-lock.json").read_text())
    if len(architectures) != 1 or not architectures <= wheels.keys():
        lab.block("No one shared Kind architecture has a pinned YARA-X wheel")
    architecture = architectures.pop()
    wheel = wheels[architecture]
    image = f"saf-quarantine-yara:{lab.cluster}"
    rule_name = "FixtureExcludedMarker"
    rule = """rule FixtureExcludedMarker {
    strings:
        $marker = "disallowed-fixture-marker-v1"
    condition:
        $marker
}
"""
    flagged = _canonical({**MODEL_ARTIFACT, "marker": "disallowed-fixture-marker-v1"})
    try:
        with tempfile.TemporaryDirectory(prefix="saf-yara-wheel-") as path:
            build = Path(path)
            artifact = build / wheel["filename"]
            lab.command("curl", "-fsSL", "--proto", "=https", "--proto-redir", "=https",
                        "--max-time", "45", "--max-filesize", str(wheel["size"]),
                        "--output", str(artifact), wheel["url"], timeout=55)
            wheel_hash = hashlib.sha256(artifact.read_bytes()).hexdigest()
            if artifact.stat().st_size != wheel["size"] or wheel_hash != wheel["sha256"]:
                lab.block("Pinned YARA-X wheel integrity did not verify")
            shutil.copyfile(root / "Dockerfile.yara", build / "Dockerfile")
            lab.command("docker", "build", "--network=none", "--platform", f"linux/{architecture}",
                        "-t", image, str(build), timeout=120)
            image_id = lab.command("docker", "image", "inspect", "--format={{.Id}}", image,
                                   timeout=20).stdout.strip()
            lab.command("kind", "load", "docker-image", image, "--name", lab.cluster, timeout=90)
        observed = _run_scanner_job(lab, "saf-yara-model-marker", image, "Never", {
            "model.json": MODEL_ARTIFACT_BYTES.decode(), "flagged.json": flagged.decode(),
            "fixture.yar": rule, "scanner.py": (root / "yara_probe.py").read_text(),
        })
    finally:
        lab.command("docker", "image", "rm", image, allow_failure=True, timeout=25)

    expected = {
        "scanner": "yara-x",
        "version": "1.24.0",
        "rule_sha256": hashlib.sha256(rule.encode()).hexdigest(),
        "approved": {"sha256": MODEL_ARTIFACT_SHA256, "matching_rules": []},
        "flagged": {"sha256": hashlib.sha256(flagged).hexdigest(), "matching_rules": [rule_name]},
    }
    if observed != expected:
        lab.block("YARA-X marker names or artifact digests did not match the reviewed inputs")
    provenance = {"wheel_sha256": wheel_hash, "architecture": architecture, "image_id": image_id}
    return observed, provenance

MARKER_NS = "saf-model-marker-fixture"
CONTROL_NS = "saf-model-marker-control"
APPROVED_MARKER = "saf-model-approved-marker-0905-044"
DENIED_MARKER = "saf-model-unapproved-marker-0905-044"
MARKER_PORT = 8080
APPROVED_MARKER_POD = "approved-marker"
DENIED_MARKER_POD = "unapproved-marker"
MARKER_CONTROL_POD = "unaffected-client"
EGRESS_EXCEPTION = "quarantine-approved-marker-only"


def _marker_pod(name, marker=None, *, client=False, namespace):
    if client:
        c = container("probe", command=["sh", "-ec", "sleep 900"])
    else:
        body = APPROVED_MARKER if marker == "approved" else DENIED_MARKER
        serve = (f"printf '%s' '{body}' >/tmp/marker.txt; "
                 f"exec httpd -f -p {MARKER_PORT} -h /tmp")
        c = container("marker", command=["sh", "-ec", serve],
                      ports=[{"name": "http", "containerPort": MARKER_PORT}],
                      readinessProbe={"tcpSocket": {"port": MARKER_PORT},
                                      "periodSeconds": 1, "failureThreshold": 30})
    obj = pod(name, [c], automountServiceAccountToken=False)
    obj["metadata"]["namespace"] = namespace
    obj["metadata"]["labels"] = {"saf.example/marker-role": "client" if client else marker}
    return obj


def _marker_reachable(lab, namespace, source_pod, target_ip, expected_marker):
    result = lab.kubectl(
        "-n", namespace, "exec", source_pod, "--", "wget", "-qT", "2", "-O-",
        f"http://{target_ip}:{MARKER_PORT}/marker.txt", allow_failure=True, timeout=12)
    if result.returncode == 0:
        if result.stdout != expected_marker:
            lab.block("Owned marker endpoint returned an unexpected response")
        return True
    if any(reason in result.stderr.lower()
           for reason in ("timed out", "timeout", "operation timed out")):
        return False
    lab.block("Owned marker request failed outside the expected policy timeout")


def _wait_marker(lab, namespace, source_pod, target_ip, expected_marker, should_reach):
    deadline = time.monotonic() + 26
    consecutive = 0
    observed = None
    while consecutive < 2 and time.monotonic() < deadline:
        observed = _marker_reachable(lab, namespace, source_pod, target_ip,
                                     expected_marker)
        consecutive = consecutive + 1 if observed == should_reach else 0
        if consecutive < 2:
            time.sleep(0.25)
    return consecutive == 2


def _wait_case_pod(lab, namespace, name):
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=70s", timeout=80)
    result = json.loads(lab.kubectl("-n", namespace, "get", f"pod/{name}",
                                    "-o", "json").stdout)
    ip = result.get("status", {}).get("podIP")
    if not ip:
        lab.block("Owned marker fixture Pod has no Pod IP")
    return ip


def _quarantine_packet_check(lab, default_deny_observed):
    """Show existing quarantine default-deny with one narrow owned egress exception."""
    lab.kubectl("-n", "kube-system", "rollout", "status", "daemonset/kindnet",
                "--timeout=60s", timeout=70)
    lab.create(_ns(MARKER_NS, "marker-fixture"))
    lab.create(_ns(CONTROL_NS, "marker-control"))
    created = []
    cleanup_ok = True
    values = {
        "kindnet_ready": False,
        "default_deny_policy_present": False,
        "default_deny_blocks_both_markers": False,
        "exception_policy_matches": False,
        "approved_marker_allowed": False,
        "unapproved_marker_blocked": False,
        "unaffected_client_reaches_unapproved_marker": False,
        "approved_marker_blocked_after_exception_removed": False,
        "exception_removed": False,
    }
    try:
        for name, role in ((APPROVED_MARKER_POD, "approved"),
                           (DENIED_MARKER_POD, "unapproved")):
            create_in(lab, MARKER_NS, _marker_pod(name, role, namespace=MARKER_NS))
            created.append((MARKER_NS, name))
        create_in(lab, CONTROL_NS, _marker_pod(
            MARKER_CONTROL_POD, client=True, namespace=CONTROL_NS))
        created.append((CONTROL_NS, MARKER_CONTROL_POD))
        approved_ip = _wait_case_pod(lab, MARKER_NS, APPROVED_MARKER_POD)
        denied_ip = _wait_case_pod(lab, MARKER_NS, DENIED_MARKER_POD)
        _wait_case_pod(lab, CONTROL_NS, MARKER_CONTROL_POD)
        _wait_case_pod(lab, QUARANTINE, "quarantined-model-candidate")

        default_blocks = (
            _wait_marker(lab, QUARANTINE, "quarantined-model-candidate", approved_ip,
                         APPROVED_MARKER, False)
            and _wait_marker(lab, QUARANTINE, "quarantined-model-candidate", denied_ip,
                             DENIED_MARKER, False))
        control_baseline = _wait_marker(
            lab, CONTROL_NS, MARKER_CONTROL_POD, denied_ip, DENIED_MARKER, True)

        exception = {
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": EGRESS_EXCEPTION, "namespace": QUARANTINE},
            "spec": {
                "podSelector": {"matchLabels": {SCAN_LABEL: "clean", AUTH_LABEL: "approved"}},
                "policyTypes": ["Egress"],
                "egress": [{
                    "to": [{
                        "namespaceSelector": {"matchLabels": {
                            "kubernetes.io/metadata.name": MARKER_NS}},
                        "podSelector": {"matchLabels": {"saf.example/marker-role": "approved"}},
                    }],
                    "ports": [{"protocol": "TCP", "port": MARKER_PORT}],
                }],
            },
        }
        create_in(lab, QUARANTINE, exception)
        observed = json.loads(lab.kubectl(
            "get", "networkpolicy", EGRESS_EXCEPTION, "-n", QUARANTINE, "-o", "json").stdout)
        policy_matches = observed.get("spec") == exception["spec"]
        approved_allowed = _wait_marker(
            lab, QUARANTINE, "quarantined-model-candidate", approved_ip,
            APPROVED_MARKER, True)
        denied_stays_blocked = _wait_marker(
            lab, QUARANTINE, "quarantined-model-candidate", denied_ip,
            DENIED_MARKER, False)
        unaffected_stays_allowed = _wait_marker(
            lab, CONTROL_NS, MARKER_CONTROL_POD, denied_ip, DENIED_MARKER, True)

        deleted = lab.kubectl("-n", QUARANTINE, "delete", "networkpolicy",
                              EGRESS_EXCEPTION, "--wait=true", timeout=30,
                              allow_failure=True)
        cleanup_ok = deleted.returncode == 0
        recovered_deny = _wait_marker(
            lab, QUARANTINE, "quarantined-model-candidate", approved_ip,
            APPROVED_MARKER, False)
        values = {
            "kindnet_ready": True,
            "default_deny_policy_present": default_deny_observed,
            "default_deny_blocks_both_markers": default_blocks,
            "exception_policy_matches": policy_matches,
            "approved_marker_allowed": approved_allowed,
            "unapproved_marker_blocked": denied_stays_blocked,
            "unaffected_client_reaches_unapproved_marker": control_baseline and unaffected_stays_allowed,
            "approved_marker_blocked_after_exception_removed": recovered_deny,
            "exception_removed": cleanup_ok,
        }
    finally:
        result = lab.kubectl("-n", QUARANTINE, "delete", "networkpolicy", EGRESS_EXCEPTION,
                             "--ignore-not-found=true", "--wait=true", allow_failure=True)
        if result.returncode:
            cleanup_ok = False
        for namespace, name in created:
            result = lab.kubectl("-n", namespace, "delete", "pod", name,
                                 "--ignore-not-found=true", "--wait=true", allow_failure=True)
            if result.returncode:
                cleanup_ok = False
        for namespace in (MARKER_NS, CONTROL_NS):
            result = lab.kubectl("delete", "namespace", namespace,
                                 "--ignore-not-found=true", "--wait=true",
                                 allow_failure=True, timeout=40)
            if result.returncode:
                cleanup_ok = False
    values["owned_fixture_cleanup_succeeded"] = cleanup_ok
    return values


def run(lab):
    raw = {"fixture_metadata": PUBLIC_FIXTURE,
           "fixture_metadata_sha256": MODEL_METADATA_SHA256,
           "synthetic_decision_matrix": {"mode": "offline-fixture-only",
                                 "model_content_inspected": False,
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

    # A separate tokenless Job reads the fixed inert JSON bytes from its
    # read-only ConfigMap mount. No model payload is copied into evidence.
    scanner_receipt = _run_fixture_scanner(lab)
    yara_receipt, yara_provenance = _run_yara_scan(lab)
    scanner_digest = scanner_receipt.get("artifact_sha256", "")
    scanner_match = (
        scanner_receipt.get("status") == "pass"
        and scanner_digest == MODEL_ARTIFACT_SHA256
        and scanner_receipt.get("format_allowed") is True
        and scanner_receipt.get("marker_policy_allowed") is True
        and scanner_receipt.get("within_size_limit") is True
    )
    if not scanner_match:
        lab.block("The case-owned scanner did not return the exact allowed fixture-byte digest and predicates")
    raw["fixture_byte_scan"] = {
        "scanner_job_completed": True,
        "status_passed": scanner_receipt["status"] == "pass",
        "artifact_digest_matches_runner_fixture": scanner_digest == MODEL_ARTIFACT_SHA256,
        "format_allowed": scanner_receipt["format_allowed"],
        "marker_policy_allowed": scanner_receipt["marker_policy_allowed"],
        "within_size_limit": scanner_receipt["within_size_limit"],
        "tokenless": True,
    }
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
    create_in(lab, RELEASE, {"apiVersion": "v1", "kind": "ServiceAccount",
                "metadata": {"name": UPDATE_SA, "namespace": RELEASE}})
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
    wrong_artifact = _pod("wrong-artifact-digest-witness", MODEL_METADATA_SHA256,
                          artifact_digest="0" * 64)
    wrong_artifact_status, wrong_artifact_body = _api_post_pod(
        lab, RELEASE_SA, wrong_artifact, dry_run=True)
    if (wrong_artifact_status != 422
            or "exact scanned artifact digest" not in wrong_artifact_body.get("message", "")):
        lab.block("Release policy did not reject the wrong observed-artifact digest")
    flagged_pod = _pod("scanned-flagged-model-witness", MODEL_METADATA_SHA256,
                       artifact_digest=yara_receipt["flagged"]["sha256"])
    flagged_status, flagged_response = _api_post_pod(lab, RELEASE_SA, flagged_pod, dry_run=True)
    unauthorized_status, unauthorized_body = _api_post_pod(
        lab, UNAUTHORIZED_SA, _pod("unauthorized-release-witness", MODEL_METADATA_SHA256))
    clean_status, clean_body = _api_post_pod(
        lab, RELEASE_SA, _pod(RELEASE_POD, MODEL_METADATA_SHA256,
                               artifact_digest=scanner_digest))
    if clean_status == 201:
        lab.kubectl("-n", RELEASE, "wait", "--for=condition=Ready", f"pod/{RELEASE_POD}",
                    "--timeout=95s", timeout=105)
    clean_readback = json.loads(lab.kubectl("get", "pod", RELEASE_POD, "-n", RELEASE,
                                            "-o", "json").stdout) if clean_status == 201 else {}
    create_in(lab, RELEASE, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": "model-release-named-pod-updater", "namespace": RELEASE},
                "rules": [{"apiGroups": [""], "resources": ["pods"],
                           "resourceNames": [RELEASE_POD], "verbs": ["patch"]}]})
    create_in(lab, RELEASE, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": "model-release-named-pod-updater", "namespace": RELEASE},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                            "name": "model-release-named-pod-updater"},
                "subjects": [{"kind": "ServiceAccount", "name": UPDATE_SA,
                              "namespace": RELEASE}]})
    allowed_update_status, allowed_update_body = _api_patch_pod(
        lab, UPDATE_SA, RELEASE_POD,
        {"metadata": {"annotations": {"saf.example/metadata-update-witness": "permitted"}}})
    rejected_update_status, rejected_update_body = _api_patch_pod(
        lab, UPDATE_SA, RELEASE_POD,
        {"metadata": {"annotations": {ARTIFACT_DIGEST_ANNOTATION: "0" * 64}}})
    update_readback = json.loads(lab.kubectl(
        "get", "pod", RELEASE_POD, "-n", RELEASE, "-o", "json").stdout)
    update_identity = (update_readback.get("metadata", {}).get("uid")
                       == clean_readback.get("metadata", {}).get("uid")
                       and bool(update_readback.get("metadata", {}).get("uid")))
    allowed_update_preserved = (allowed_update_status == 200
                                and allowed_update_body.get("metadata", {}).get("uid")
                                == clean_readback.get("metadata", {}).get("uid")
                                and allowed_update_body.get("metadata", {}).get("annotations", {}).get(
                                    "saf.example/metadata-update-witness") == "permitted")
    rejected_update_policy = (rejected_update_status == 422
                              and "exact scanned artifact digest" in rejected_update_body.get("message", ""))
    update_readback_preserved = (update_identity
                                 and update_readback.get("metadata", {}).get("annotations", {}).get(
                                     ARTIFACT_DIGEST_ANNOTATION) == scanner_digest
                                 and update_readback.get("metadata", {}).get("annotations", {}).get(
                                     APPROVED_DIGEST) == MODEL_METADATA_SHA256
                                 and update_readback.get("metadata", {}).get("labels", {}).get(
                                     SCAN_LABEL) == "clean"
                                 and update_readback.get("metadata", {}).get("labels", {}).get(
                                     AUTH_LABEL) == "approved"
                                 and update_readback.get("metadata", {}).get("annotations", {}).get(
                                     "saf.example/metadata-update-witness") == "permitted")
    raw["release_update_attempts"] = {
        "updater_service_account": UPDATE_SA,
        "role_resource_names": [RELEASE_POD],
        "allowed_metadata_update": {"status": allowed_update_status,
                                    "uid": allowed_update_body.get("metadata", {}).get("uid")},
        "denied_scanned_digest_update": {"status": rejected_update_status,
                                          "reason": _denial_reason(rejected_update_body),
                                          "message": rejected_update_body.get("message", "")},
        "independent_readback": {
            "uid": update_readback.get("metadata", {}).get("uid"),
            "scanned_artifact_digest": update_readback.get("metadata", {}).get("annotations", {}).get(
                ARTIFACT_DIGEST_ANNOTATION),
            "model_metadata_digest": update_readback.get("metadata", {}).get("annotations", {}).get(
                APPROVED_DIGEST),
            "scan_decision": update_readback.get("metadata", {}).get("labels", {}).get(SCAN_LABEL),
            "release_authorization": update_readback.get("metadata", {}).get("labels", {}).get(AUTH_LABEL),
            "ordinary_metadata_update": update_readback.get("metadata", {}).get("annotations", {}).get(
                "saf.example/metadata-update-witness"),
        },
    }

    raw["release_api_attempts"] = {
        "wrong_digest": {"status": mismatch_status, "body": mismatch_body},
        "wrong_artifact_digest": {"status": wrong_artifact_status, "body": wrong_artifact_body},
        "unauthorized_principal": {"status": unauthorized_status, "body": unauthorized_body},
        "authorized_clean": {"status": clean_status, "body": clean_body,
                              "readback": clean_readback},
    }

    normalized = {
        "case": "SAF-K8S-0905-044",
        "fixture_metadata_sha256": MODEL_METADATA_SHA256,
        "scanner": {"mode": "fixture-byte-inspector-plus-synthetic-decision-witness",
                    "fixture_inspector_executed": True,
                    "real_model_bytes_present": False,
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
            "scanned_artifact_digest": scanner_digest,
            "release_readback_sha256": MODEL_METADATA_SHA256 if clean_readback else None,
            "allowed_named_pod_metadata_update": allowed_update_preserved,
            "scanned_digest_update_denied": rejected_update_policy,
            "same_release_uid_and_digest_after_update_attempts": update_readback_preserved,
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

    default_deny_matches = (observed_policy.get("spec") == {
        "podSelector": {}, "policyTypes": ["Ingress", "Egress"]})
    network_evidence = _quarantine_packet_check(lab, default_deny_matches)
    packet_drop_proven = all(network_evidence.values())
    raw["quarantine_network_enforcement"] = network_evidence
    normalized["isolation"]["network_policy_packet_drop_proven"] = packet_drop_proven
    (lab.evidence / "raw-observations.json").write_text(
        json.dumps(raw, indent=2, sort_keys=True) + "\n")
    (lab.evidence / "normalized-evidence.json").write_text(
        json.dumps(normalized, indent=2, sort_keys=True) + "\n")
    lab.check("positive",
              "Bundled kindnet enforces quarantine default-deny and the exact marker-only egress exception",
              packet_drop_proven,
              {"namespace": QUARANTINE, "approved_target": APPROVED_MARKER_POD,
               "denied_target": DENIED_MARKER_POD, "port": MARKER_PORT,
               "conditions": network_evidence})
    lab.check(
        "positive",
        "A bounded tokenless scanner binds the allowed inert artifact bytes to native release admission",
        scanner_match
        and wrong_artifact_status == 422
        and "exact scanned artifact digest" in wrong_artifact_body.get("message", "")
        and clean_status == 201
        and clean_readback.get("metadata", {}).get("annotations", {}).get(ARTIFACT_DIGEST_ANNOTATION)
        == scanner_digest,
        {"scanner_job_completed": True,
         "format_allowed": scanner_receipt.get("format_allowed") is True,
         "fixed_marker_policy_allowed": scanner_receipt.get("marker_policy_allowed") is True,
         "artifact_bytes_within_bound": scanner_receipt.get("within_size_limit") is True,
         "scanner_digest_matches_exact_fixture": scanner_digest == MODEL_ARTIFACT_SHA256,
         "wrong_artifact_digest_refused_by_native_gate": wrong_artifact_status == 422,
         "authorized_release_readback_matches_scanner_digest": (
             clean_readback.get("metadata", {}).get("annotations", {}).get(ARTIFACT_DIGEST_ANNOTATION)
             == scanner_digest),
         "scan_scope": "fixed inert JSON format and marker only"},
    )

    (lab.evidence / "raw-observations.json").write_text(
        json.dumps(raw, indent=2, sort_keys=True) + "\n")
    (lab.evidence / "normalized-evidence.json").write_text(
        json.dumps(normalized, indent=2, sort_keys=True) + "\n")
    lab.check(
        "positive",
        "A named updater may change benign metadata but cannot change the scanned artifact digest",
        allowed_update_preserved and rejected_update_policy and update_readback_preserved,
        {"named_patch_role_scoped": True,
         "ordinary_metadata_patch_allowed": allowed_update_preserved,
         "scanned_digest_patch_rejected_by_native_admission": rejected_update_policy,
         "independent_get_preserves_same_pod_uid_and_digest": update_readback_preserved},
    )

    yara_binding = (
        flagged_status == 422
        and "exact scanned artifact digest" in flagged_response.get("message", "")
        and clean_readback.get("metadata", {}).get("annotations", {}).get(ARTIFACT_DIGEST_ANNOTATION)
            == yara_receipt["approved"]["sha256"]
    )
    (lab.evidence / "offline-yara-marker.raw.json").write_text(json.dumps({
        "scan": yara_receipt,
        "tool_provenance": yara_provenance,
        "flagged_dry_run_status": flagged_status,
        "released_digest_bound_to_clean_scan": yara_binding,
    }, indent=2, sort_keys=True) + "\n")
    lab.check(
        "positive",
        "Pinned YARA-X matches the inert excluded marker and admission retains the scanned clean digest",
        yara_binding,
        {"engine": "YARA-X", "version": yara_receipt["version"],
         "scope": "fixed inert fixture marker only",
         "approved_rule_matches": yara_receipt["approved"]["matching_rules"],
         "flagged_rule_matches": yara_receipt["flagged"]["matching_rules"],
         "flagged_digest_rejected_before_release": flagged_status == 422,
         "authorized_release_digest_matches_scanned_clean_fixture": yara_binding},
    )
