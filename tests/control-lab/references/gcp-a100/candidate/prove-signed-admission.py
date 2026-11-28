"""Exercise a one-node policy using operator-reviewed same-boot A100 records.

This script does not authenticate the records' origin. The input JSON files
must be prepared and reviewed by the operator using the documented evidence
collection/review path. Their bytes are then pinned in the synthetic API
parameter; that digest is not a signature or attestation.
"""

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import time
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import uuid4

API = "admissionregistration.k8s.io/v1"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
ANNOTATION = "fixture.example/reviewed-evidence"
SUBMITTER = "saf-fixture-a100-module-submitter"
PARAM = "signed-module-boot-review"
REQUIRED_PROVIDER_EVENTS = {"earlyBootReportEvent", "lateBootReportEvent"}
REQUIRED_MODULES = {"nvidia", "nvidia_uvm"}
HASH = re.compile(r"[0-9a-f]{64}")
RECEIPT_MAX = 65_536


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        return None


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def kubectl(*args, obj=None, timeout=15):
    return subprocess.run(["/usr/local/bin/k3s", "kubectl", *args],
                          input=json.dumps(obj) if obj is not None else None,
                          text=True, capture_output=True, timeout=timeout)


def get(kind, name, namespace=None):
    scope = () if namespace is None else ("-n", namespace)
    result = kubectl(*scope, "get", kind, name, "-o", "json")
    require(result.returncode == 0, result.stderr.strip())
    return json.loads(result.stdout)


def create(obj, *options):
    return kubectl(*options, "create", "-f", "-", "-o", "json", obj=obj)


def provision(obj):
    result = create(obj)
    require(result.returncode == 0, result.stderr.strip())
    return json.loads(result.stdout)


def metadata(api, kind, name, namespace=None):
    record = {"apiVersion": api, "kind": kind, "metadata": {"name": name}}
    if namespace:
        record["metadata"]["namespace"] = namespace
    return record


def workload(ns, node, digest):
    record = metadata("v1", "Pod", "signed-evidence-witness", ns)
    record["metadata"]["annotations"] = {ANNOTATION: digest}
    record["spec"] = {"restartPolicy": "Never", "automountServiceAccountToken": False,
                      "nodeSelector": {"kubernetes.io/hostname": node},
                      "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                          "seccompProfile": {"type": "RuntimeDefault"}},
                      "containers": [{"name": "witness", "image": IMAGE,
                                      "command": ["python", "-c", "import time; time.sleep(90)"],
                                      "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                                                    "limits": {"cpu": "100m", "memory": "40Mi"}},
                                      "securityContext": {"readOnlyRootFilesystem": True,
                                                          "allowPrivilegeEscalation": False,
                                                          "capabilities": {"drop": ["ALL"]}}}]}
    return record


def wait_denial(pod, policy, expected):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        outcome = create(pod, "--as", SUBMITTER, "--dry-run=server")
        if outcome.returncode:
            signature = f"ValidatingAdmissionPolicy '{policy}' with binding '{policy}' denied request:"
            require(signature in outcome.stderr and expected in outcome.stderr, outcome.stderr.strip())
            return
        time.sleep(0.5)
    raise SystemExit(f"Expected admission denial absent for {expected}")


def read_operator_review(path, description):
    """Accept only a root-owned, non-group/world-writable regular input file."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not (info.st_mode & 0o022),
                f"{description} must be a root-owned regular file not writable by group or other")
        raw = stream.read(RECEIPT_MAX + 1)
    require(len(raw) <= RECEIPT_MAX, f"{description} is larger than the bounded format")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Invalid {description}: {exc}")
    require(isinstance(value, dict), f"{description} must be a JSON object")
    return value, raw


def validate_module_receipt(module, current_boot_ref):
    require(module.get("schema") == "saf-a100-loaded-signed-modules-v1",
            "Unexpected loaded-module receipt schema")
    require(module.get("boot_ref_sha256") == current_boot_ref,
            "Loaded-module receipt is stale or belongs to another boot")
    require(module.get("secure_boot_efi_variable") is True and module.get("mokutil_secure_boot") is True,
            "Loaded-module receipt does not report Secure Boot enabled")
    require(any(mode in module.get("kernel_lockdown", "") for mode in ("[integrity]", "[confidentiality]"))
            and module.get("canonical_signer_label_in_builtin_trust") is True,
            "Loaded-module receipt does not report lockdown and the expected trusted signer")
    modules = module.get("modules")
    require(isinstance(modules, list) and {item.get("module") for item in modules if isinstance(item, dict)} == REQUIRED_MODULES
            and len(modules) == len(REQUIRED_MODULES),
            "Loaded-module receipt must contain exactly the required NVIDIA modules")
    versions = set()
    for item in modules:
        require(isinstance(item, dict), "Malformed module entry")
        require(item.get("detached_signature_exact_match") is True and
                item.get("loaded_version_matches") is True and
                item.get("unsigned_module_taint_present") is False and
                item.get("signer") == "Canonical Ltd. Kernel Module Signing" and
                item.get("signing_key_id") == "E9:DF:13:0F:92:92:A9:B7" and
                isinstance(item.get("module_sha256"), str) and HASH.fullmatch(item["module_sha256"]) and
                isinstance(item.get("distribution_signature_sha256"), str) and
                HASH.fullmatch(item["distribution_signature_sha256"]),
                f"Loaded-module properties failed review for {item.get('module')}")
        versions.add(item.get("driver_version"))
    require(len(versions) == 1 and None not in versions,
            "NVIDIA module driver versions do not agree")


def parse_time(value):
    require(isinstance(value, str), "Missing reviewed timestamp")
    at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(at.utcoffset() is not None, "Expected timestamp with an explicit time zone")
    return at


def current_instance_ref():
    target = Request("http://169.254.169.254/computeMetadata/v1/instance/id",
                     headers={"Metadata-Flavor": "Google"})
    with build_opener(ProxyHandler({}), NoRedirect()).open(target, timeout=4) as response:
        identity = response.read(32).decode("ascii").strip()
        require(response.headers.get("Metadata-Flavor") == "Google" and re.fullmatch(r"[1-9][0-9]{1,20}", identity),
                "Guest did not provide an exact Google Compute Engine instance ID")
    return sha256(identity.encode()).hexdigest()


def validate_same_boot(boot, module, module_raw, boot_ref, host_ref, boot_started_at):
    require(boot.get("schema") == "saf-a100-shielded-module-review-v1" and boot.get("status") == "verified"
            and all(boot.get(key) is True for key in ("module_signing_verified", "kernel_lockdown_verified"))
            and boot.get("boot_ref_sha256") == boot_ref
            and boot.get("host_ref_sha256") == host_ref
            and type(boot.get("provider_boot_counter")) is int and boot["provider_boot_counter"] > 0
            and isinstance(boot.get("signed_module_receipt_sha256"), str)
            and boot["signed_module_receipt_sha256"] == sha256(module_raw).hexdigest(),
            "The reviewed provider-module evidence does not match this boot")
    events = boot.get("provider_events")
    require(isinstance(events, dict) and set(events) == REQUIRED_PROVIDER_EVENTS and
            all(isinstance(events[name], dict) and events[name].get("policy_passed") is True and
                isinstance(events[name].get("observed_utc"), str) for name in REQUIRED_PROVIDER_EVENTS),
            "Reviewed provider evidence must include passing early and late boot events")
    validate_module_receipt(module, boot_ref)
    start = parse_time(boot.get("provider_startup_utc"))
    early = parse_time(events["earlyBootReportEvent"]["observed_utc"])
    late = parse_time(events["lateBootReportEvent"]["observed_utc"])
    captured = parse_time(module.get("captured_at_utc"))
    require(parse_time(boot.get("guest_boot_utc")) == boot_started_at
            and start < early < late <= captured
            and all(abs((when - boot_started_at).total_seconds()) <= 90 for when in (start, early, late)),
            "Provider events are not ordered around this guest's boot")


def require_independent_boot(baseline, baseline_module, baseline_module_raw, boot, host_ref):
    """Require independently reviewed, ordered boots of this approved guest."""
    first_ref = baseline.get("boot_ref_sha256")
    require(isinstance(first_ref, str) and HASH.fullmatch(first_ref),
            "The first boot reference is invalid")
    first_at = parse_time(baseline.get("guest_boot_utc"))
    validate_same_boot(baseline, baseline_module, baseline_module_raw, first_ref, host_ref, first_at)
    require(boot.get("boot_ref_sha256") != first_ref,
            "The reviewed current boot reuses the first boot reference")
    require(boot["provider_boot_counter"] > baseline["provider_boot_counter"],
            "The current provider boot counter must advance")
    current_startup = parse_time(boot.get("provider_startup_utc"))
    require(current_startup > parse_time(baseline_module.get("captured_at_utc"))
            and parse_time(boot.get("guest_boot_utc")) > first_at,
            "The first boot and its module capture must precede the new startup")
    return {
        "same_provider_instance": True,
        "independent_boot_verified": True,
        "baseline_boot_ref_sha256": first_ref,
        "baseline_provider_boot_counter": baseline["provider_boot_counter"],
        "current_provider_boot_counter": boot["provider_boot_counter"],
    }


def main(baseline_path, baseline_module_path, boot_path, module_path, out):
    hostname = socket.gethostname()
    require(re.fullmatch(r"saf-a100-[0-9]{10}", hostname), "Use the disposable A100 fixture host")
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot_id), "Live kernel boot ID is malformed")
    boot_ref = sha256(boot_id.encode()).hexdigest()
    boot, boot_raw = read_operator_review(boot_path, "provider boot review")
    module, module_raw = read_operator_review(module_path, "loaded-module receipt")
    baseline, baseline_raw = read_operator_review(baseline_path, "first provider boot review")
    baseline_module, baseline_module_raw = read_operator_review(baseline_module_path, "first loaded-module receipt")
    inputs = (baseline_path, baseline_module_path, boot_path, module_path)
    require(len({path.resolve() for path in inputs}) == len(inputs), "Provide separate files for both boot reviews and module captures")
    host_ref = current_instance_ref()
    boot_started_at = datetime.fromtimestamp(int(next(
        line.split()[1] for line in Path("/proc/stat").read_text().splitlines() if line.startswith("btime "))), timezone.utc)
    validate_same_boot(boot, module, module_raw, boot_ref, host_ref, boot_started_at)
    independent = require_independent_boot(baseline, baseline_module, baseline_module_raw, boot, host_ref)
    independent["baseline_boot_review_sha256"] = sha256(baseline_raw).hexdigest()
    independent["baseline_module_receipt_sha256"] = sha256(baseline_module_raw).hexdigest()
    node = get("node", hostname)
    require(node["metadata"]["labels"].get("kubernetes.io/hostname") == hostname
            and node["status"]["nodeInfo"]["bootID"] == boot_id, "Kubernetes Node identity differs from live guest")
    ns = f"saf-module-review-{boot_ref[:12]}-{uuid4().hex[:8]}"
    policy = ns
    realm = metadata("v1", "Namespace", ns)
    realm["metadata"]["labels"] = {"pod-security.kubernetes.io/enforce": "restricted"}
    provision(realm)
    role = metadata("rbac.authorization.k8s.io/v1", "Role", policy, ns)
    role["rules"] = [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [PARAM], "verbs": ["get"]},
                     {"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}]
    provision(role)
    link = metadata("rbac.authorization.k8s.io/v1", "RoleBinding", policy, ns)
    link["subjects"] = [{"kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": SUBMITTER}]
    link["roleRef"] = {"kind": "Role", "apiGroup": "rbac.authorization.k8s.io", "name": policy}
    provision(link)

    # Pin all four operator-reviewed inputs in their required order.
    digest = sha256(b"\0".join((baseline_raw, baseline_module_raw, boot_raw, module_raw))).hexdigest()
    wrong = "0" * 64
    baseline = create(workload(ns, hostname, wrong), "--as", SUBMITTER, "--dry-run=server")
    require(baseline.returncode == 0, baseline.stderr.strip())

    cfg = metadata("v1", "ConfigMap", PARAM, ns)
    cfg.update({"immutable": True, "data": {"verified": "true", "boot-ref": boot_ref,
                                          "receipt-digest": digest, "hostname": hostname}})
    installed = provision(cfg)
    parameter_id = installed["metadata"]["uid"]
    gate = metadata(API, "ValidatingAdmissionPolicy", policy)
    gate["spec"] = {"failurePolicy": "Fail", "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
                    "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                            "operations": ["CREATE"], "resources": ["pods"]}]},
                    "validations": [
                        {"expression": "params != null && params.data['verified'] == 'true' && "
                         f"params.data['boot-ref'] == '{boot_ref}'",
                         "message": "Signed module review for this boot required"},
                        {"expression": f"has(object.metadata.annotations) && '{ANNOTATION}' in "
                         f"object.metadata.annotations && object.metadata.annotations['{ANNOTATION}'] "
                         "== params.data['receipt-digest']", "message": "Reviewed evidence digest does not match"},
                        {"expression": "(!has(object.spec.nodeName) || object.spec.nodeName == '') && "
                         "has(object.spec.nodeSelector) && 'kubernetes.io/hostname' in object.spec.nodeSelector && "
                         "object.spec.nodeSelector['kubernetes.io/hostname'] == params.data['hostname']",
                         "message": "Reviewed accelerator node placement required"}]}
    provision(gate)
    bind = metadata(API, "ValidatingAdmissionPolicyBinding", policy)
    bind["spec"] = {"policyName": policy, "validationActions": ["Deny"],
                    "paramRef": {"name": PARAM, "namespace": ns, "parameterNotFoundAction": "Deny"},
                    "matchResources": {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": ns}}}}
    provision(bind)

    wait_denial(workload(ns, hostname, wrong), policy, "Reviewed evidence digest does not match")
    wait_denial(workload(ns, "unreviewed-fixture-node", digest), policy, "Reviewed accelerator node placement required")
    server = create(workload(ns, hostname, digest), "--as", SUBMITTER)
    require(server.returncode == 0, server.stderr.strip())
    ready = kubectl("-n", ns, "wait", "--for=condition=Ready", "pod/signed-evidence-witness",
                    "--timeout=40s", timeout=45)
    require(ready.returncode == 0, ready.stderr.strip())
    pod = get("pod", "signed-evidence-witness", ns)
    policy_status = get("validatingadmissionpolicy", policy)
    require("typeChecking" in policy_status.get("status", {}) and
            not policy_status["status"]["typeChecking"].get("expressionWarnings"),
            "Policy CEL did not pass type checking")
    require(pod["spec"]["nodeName"] == hostname and pod["status"]["phase"] == "Running",
            "Real witness failed to run on the reviewed accelerator host")

    query = kubectl("--as", SUBMITTER, "-n", ns, "get", "cm", PARAM, "-o", "json")
    require(query.returncode == 0 and json.loads(query.stdout)["metadata"]["uid"] == parameter_id,
            "Submitter could not read the exact reviewed parameter")
    patch = kubectl("--as", SUBMITTER, "-n", ns, "patch", "cm", PARAM, "--type=merge",
                    "-p", '{"data":{"verified":"false"}}')
    denial = patch.stderr.lower()
    require(patch.returncode != 0 and "error from server (forbidden)" in denial and
            f'configmaps "{PARAM}" is forbidden' in denial and
            f'user "{SUBMITTER.lower()}" cannot patch resource "configmaps"' in denial and
            f'namespace "{ns}"' in denial,
            f"Expected exact Kubernetes Forbidden patch denial; got: {patch.stderr.strip()}")
    after = get("cm", PARAM, ns)
    require(after["metadata"]["uid"] == parameter_id and after["data"] == cfg["data"] and
            after["immutable"] is True, "Reviewed parameter changed after denial")
    result = {"schema": "saf-a100-signed-admission-v2", "status": "passed", "boot_ref_sha256": boot_ref,
              **independent,
              "reviewed_receipt_sha256": digest,
              "boot_review_sha256": sha256(boot_raw).hexdigest(),
              "loaded_module_receipt_sha256": sha256(module_raw).hexdigest(),
              "admitted_wrong_digest_before_policy": True,
              "wrong_digest_denied": True, "unreviewed_node_denied": True,
              "reviewed_pod_running_on_reviewed_node": True, "submitter_evidence_write_forbidden": True,
              "review_parameter_unchanged": True, "cel_type_check_passed": True,
              "node_uid_sha256": sha256(node["metadata"]["uid"].encode()).hexdigest(),
              "scope": "CPU witness scheduled onto actual A100 host from root-owned, operator-reviewed evidence of two ordered boots; input authenticity is not verified by this script"}
    with out.open("x") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print("PASS: operator-reviewed evidence from two ordered boots enforced for the exact live Kubernetes admission fixture")


if __name__ == "__main__":
    require(os.geteuid() == 0, "Run only as the operator on the disposable GCE lab guest")
    require(len(sys.argv) == 6,
            "Usage: prove-signed-admission.py FIRST_BOOT.json FIRST_MODULES.json CURRENT_BOOT.json CURRENT_MODULES.json OUT.json")
    main(*(Path(value) for value in sys.argv[1:]))
