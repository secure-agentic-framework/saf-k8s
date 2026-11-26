"""Matched, dry-run admission federation control for SAF-K8S-0910-026."""
import hashlib
import importlib.util
import json
import copy
from pathlib import Path
import time
import yaml

HERE = Path(__file__).resolve().parent
VERSION = "v1"
BUNDLE_SHA256 = "f3242795f4c3f2d9158755996adc41e0f535ab19a86f8eb136ae9587f34a1767"
BUNDLE_PATH = HERE / "admission-policy.yaml"
SCOPE = 'Native Deployment admission on two separately owned Kind API servers using the same hash-bound approved policy bundle. All policy probes use server-side dry run.'
CONTROL_NS = "saf026-control"
WORKLOAD_NS = "saf026-workloads"
APPROVAL_CM = "saf026-approved-baseline"
CANDIDATE_SA = "saf026-candidate-publisher"
WRITER_SA = "saf026-baseline-writer"
ENVELOPE_CM = "saf026-approved-envelope"
WRONG_ENVELOPE_CM = "saf026-wrong-version-envelope"
WRITER_CODE_CM = "saf026-writer-code"
POLICY = "saf026-ai-deployment-baseline-v1"
DENIAL_MESSAGE = (
    "SAF-K8S-0910-026: privileged containers are not approved in synthetic AI deployments"
)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def locate_case_library():
    for parent in HERE.parents:
        direct = parent
        if ((direct / "SAF-K8S-0910-020" / "owned_peer.py").is_file()
                and (direct / "SAF-K8S-0908-001" / "case.py").is_file()):
            return direct
        nested = parent / "saf-k8s-control-lab" / "cases"
        if ((nested / "SAF-K8S-0910-020" / "owned_peer.py").is_file()
                and (nested / "SAF-K8S-0908-001" / "case.py").is_file()):
            return nested
    raise RuntimeError("Could not locate the two existing case helpers")


class Target:
    def __init__(self, name, kubectl):
        self.name = name
        self.kubectl = kubectl


def row(kind, name, api="v1", **fields):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields}


def approval_record(bundle_hash, envelope_hash):
    return row(
        "ConfigMap", APPROVAL_CM,
        immutable=True,
        metadata={"name": APPROVAL_CM,
                  "labels": {"saf-k8s.example/control": "SAF-K8S-0910-026"},
                  "annotations": {"saf-k8s.example/bundle-version": VERSION}},
        data={"version": VERSION, "sha256": bundle_hash,
              "envelope_sha256": envelope_hash, "policy": POLICY,
              "approval_ref": "fixture-central-baseline-v1"},
    )


def output(target, *args, **kwargs):
    result = target.kubectl(*args, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{target.name} kubectl {' '.join(args)} failed: {result.stderr}")
    return result.stdout


def create_fixture(target, obj, namespace=None):
    args = ["create"]
    if namespace:
        args.extend(["-n", namespace])
    args.extend(["-f", "-"])
    output(target, *args, payload=json.dumps(obj, sort_keys=True))


def grant_candidate_read_access(target):
    api = "rbac.authorization.k8s.io/v1"
    namespace_subject = {"kind": "ServiceAccount", "name": CANDIDATE_SA, "namespace": CONTROL_NS}
    for kind, binding, groups, resource, name, namespace in (
        ("Role", "RoleBinding", "", "configmaps", APPROVAL_CM, CONTROL_NS),
        ("ClusterRole", "ClusterRoleBinding", "admissionregistration.k8s.io",
         "validatingadmissionpolicies", POLICY, None),
    ):
        create_fixture(target, row(kind, CANDIDATE_SA, api=api, rules=[{
            "apiGroups": [groups], "resources": [resource], "resourceNames": [name], "verbs": ["get"],
        }]), namespace)
        create_fixture(target, row(binding, CANDIDATE_SA, api=api,
            roleRef={"kind": kind, "name": CANDIDATE_SA, "apiGroup": "rbac.authorization.k8s.io"},
            subjects=[namespace_subject]), namespace)


def read_approval_object(target):
    raw = output(target, "-n", CONTROL_NS, "get", "configmap", APPROVAL_CM, "-o", "json")
    return json.loads(raw)


def summarize_approval(value):
    return {"version": value["data"].get("version"),
            "sha256": value["data"].get("sha256"),
            "envelope_sha256": value["data"].get("envelope_sha256"),
            "policy": value["data"].get("policy"),
            "immutable": value.get("immutable") is True}


def read_approval(target):
    return summarize_approval(read_approval_object(target))


def attempt_wrong_version(target):
    identity = f"system:serviceaccount:{CONTROL_NS}:{CANDIDATE_SA}"
    patch = {"data": {"version": "v0", "sha256": "0" * 64,
                       "policy": "unapproved-saf026-candidate"}}
    result = target.kubectl(
        "--as", identity, "-n", CONTROL_NS, "patch", "configmap", APPROVAL_CM,
        "--type=merge", "-p", json.dumps(patch, sort_keys=True), allow_failure=True,
    )
    target_denial = (result.returncode != 0 and "Forbidden" in result.stderr
                     and identity in result.stderr
                     and 'cannot patch resource "configmaps"' in result.stderr)
    return {"candidate_write_denied": target_denial,
            "stderr": result.stderr.strip()}


def attempt_policy_replacement(target):
    identity = f"system:serviceaccount:{CONTROL_NS}:{CANDIDATE_SA}"
    patch = {
        "metadata": {"annotations": {"saf-k8s.example/bundle-version": "v0"}},
        "spec": {"validations": [{"expression": "true",
                                    "message": "unapproved synthetic candidate"}]},
    }
    result = target.kubectl(
        "--as", identity, "patch", "validatingadmissionpolicy", POLICY,
        "--type=merge", "-p", json.dumps(patch, sort_keys=True), allow_failure=True,
    )
    target_denial = (result.returncode != 0 and "Forbidden" in result.stderr
                     and identity in result.stderr
                     and 'cannot patch resource "validatingadmissionpolicies"' in result.stderr)
    return {"candidate_write_denied": target_denial,
            "stderr": result.stderr.strip()}


def read_policy_state(target):
    raw = output(target, "get", "validatingadmissionpolicy", POLICY, "-o", "json")
    obj = json.loads(raw)
    return {"version": obj.get("metadata", {}).get("annotations", {}).get(
                "saf-k8s.example/bundle-version"),
            "expression": obj.get("spec", {}).get("validations", [{}])[0].get("expression"),
            "failurePolicy": obj.get("spec", {}).get("failurePolicy")}


def admit(target, obj):
    result = target.kubectl(
        "-n", WORKLOAD_NS, "create", "-f", "-", "--dry-run=server", "-o", "json",
        payload=json.dumps(obj, sort_keys=True), allow_failure=True,
    )
    if result.returncode == 0:
        return {"decision": "accepted", "policy_message": ""}
    if "Forbidden" in result.stderr and DENIAL_MESSAGE in result.stderr:
        return {"decision": "denied-by-policy", "policy_message": DENIAL_MESSAGE}
    return {"decision": "unexpected-error", "policy_message": result.stderr.strip()}


def policy_ready(target, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = target.kubectl("get", "validatingadmissionpolicy", POLICY,
                                "-o", "json", allow_failure=True)
        if result.returncode == 0:
            checking = json.loads(result.stdout).get("status", {}).get("typeChecking")
            if isinstance(checking, dict) and not checking.get("expressionWarnings", []):
                return True
        time.sleep(0.5)
    return False


def bundle_resources(bundle_text):
    resources = list(yaml.safe_load_all(bundle_text))
    if len(resources) != 2:
        raise ValueError("Approved bundle must contain exactly two resources")
    expected = {"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"}
    if {obj.get("kind") for obj in resources} != expected:
        raise ValueError("Approved bundle has unexpected resource kinds")
    if any(obj.get("metadata", {}).get("name") != POLICY for obj in resources):
        raise ValueError("Approved bundle has unexpected resource names")
    return resources


def writer_access(target):
    api = "rbac.authorization.k8s.io/v1"
    subject = {"kind": "ServiceAccount", "name": WRITER_SA, "namespace": CONTROL_NS}
    create_fixture(target, row("ServiceAccount", WRITER_SA, automountServiceAccountToken=False), CONTROL_NS)
    create_fixture(target, row("Role", WRITER_SA, api=api, rules=[{
        "apiGroups": [""], "resources": ["configmaps"],
        "resourceNames": [APPROVAL_CM, ENVELOPE_CM, WRONG_ENVELOPE_CM], "verbs": ["get"],
    }]), CONTROL_NS)
    create_fixture(target, row("RoleBinding", WRITER_SA, api=api,
        roleRef={"kind": "Role", "name": WRITER_SA,
                 "apiGroup": "rbac.authorization.k8s.io"}, subjects=[subject]), CONTROL_NS)
    create_fixture(target, row("ClusterRole", WRITER_SA, api=api, rules=[{
        "apiGroups": ["admissionregistration.k8s.io"],
        "resources": ["validatingadmissionpolicies", "validatingadmissionpolicybindings"],
        "resourceNames": [POLICY], "verbs": ["patch"],
    }]))
    create_fixture(target, row("ClusterRoleBinding", WRITER_SA, api=api,
        roleRef={"kind": "ClusterRole", "name": WRITER_SA,
                 "apiGroup": "rbac.authorization.k8s.io"}, subjects=[subject]))


def placeholder_resources(resources):
    policy, binding = (copy.deepcopy(item) for item in resources)
    policy["spec"]["validations"] = [{"expression": "true", "message": "inactive fixture placeholder"}]
    selector = binding["spec"]["matchResources"]["namespaceSelector"]["matchLabels"]
    selector["saf-k8s.example/admission-baseline"] = "fixture-not-enabled"
    return policy, binding


def writer_pod(target, image, mode, suffix):
    name = f"saf026-writer-{suffix}"
    obj = row("Pod", name, metadata={"name": name, "namespace": CONTROL_NS,
        "labels": {"saf-k8s.example/control": "SAF-K8S-0910-026"}}, spec={
            "serviceAccountName": WRITER_SA,
            "automountServiceAccountToken": False,
            "restartPolicy": "Never",
            "activeDeadlineSeconds": 45,
            "terminationGracePeriodSeconds": 2,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                "runAsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
            "volumes": [
                {"name": "writer", "configMap": {"name": WRITER_CODE_CM,
                                                     "defaultMode": 0o444}},
                {"name": "api", "projected": {"sources": [
                    {"serviceAccountToken": {"path": "token", "expirationSeconds": 600}},
                    {"configMap": {"name": "kube-root-ca.crt", "items": [
                        {"key": "ca.crt", "path": "ca.crt"}]}}
                ]}},
            ],
            "containers": [{
                "name": "writer", "image": image, "imagePullPolicy": "Never",
                "command": ["python", "-B", "/writer/policy_writer.py", mode],
                "env": [{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}],
                "volumeMounts": [
                    {"name": "writer", "mountPath": "/writer", "readOnly": True},
                    {"name": "api", "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
                     "readOnly": True},
                ],
                "resources": {"requests": {"cpu": "25m", "memory": "32Mi"},
                              "limits": {"cpu": "100m", "memory": "64Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}},
            }],
        })
    create_fixture(target, obj, CONTROL_NS)
    deadline = time.monotonic() + 55
    observation = None
    try:
        while time.monotonic() < deadline:
            result = target.kubectl("-n", CONTROL_NS, "get", "pod", name, "-o", "json",
                                    allow_failure=True)
            if result.returncode == 0:
                pod_obj = json.loads(result.stdout)
                phase = pod_obj.get("status", {}).get("phase")
                if phase in {"Succeeded", "Failed"}:
                    identity_matches = pod_obj.get("spec", {}).get("serviceAccountName") == WRITER_SA
                    logs = target.kubectl("-n", CONTROL_NS, "logs", "pod/" + name,
                                          allow_failure=True, timeout=15)
                    parsed = None
                    if logs.returncode == 0:
                        try:
                            parsed = json.loads(logs.stdout.strip().splitlines()[-1])
                        except (ValueError, IndexError):
                            parsed = None
                    observation = {"phase_succeeded": phase == "Succeeded",
                                   "writer_service_account": identity_matches,
                                   "result": parsed or {"decision": "missing-result"}}
                    return observation
            time.sleep(0.5)
        return {"phase_succeeded": False, "writer_service_account": False,
                "result": {"decision": "timeout"}}
    finally:
        target.kubectl("-n", CONTROL_NS, "delete", "pod", name, "--wait=true",
                       "--timeout=8s", allow_failure=True, timeout=15)


def read_binding_state(target):
    raw = output(target, "get", "validatingadmissionpolicybinding", POLICY, "-o", "json")
    return json.loads(raw)


def binding_placeholder_state(target):
    obj = read_binding_state(target)
    return {
        "policy_name": obj.get("spec", {}).get("policyName"),
        "selector_value": obj.get("spec", {}).get("matchResources", {})
            .get("namespaceSelector", {}).get("matchLabels", {})
            .get("saf-k8s.example/admission-baseline"),
    }


def resources_match(target, expected):
    observed = {
        "ValidatingAdmissionPolicy": json.loads(output(
            target, "get", "validatingadmissionpolicy", POLICY, "-o", "json")),
        "ValidatingAdmissionPolicyBinding": read_binding_state(target),
    }
    for desired in expected:
        current = observed[desired["kind"]]
        expected_spec = copy.deepcopy(desired["spec"])
        match_key = ("matchConstraints" if desired["kind"] == "ValidatingAdmissionPolicy" else "matchResources")
        selectors = expected_spec[match_key]
        selectors.setdefault("matchPolicy", "Equivalent")
        selectors.setdefault("namespaceSelector", {})
        selectors.setdefault("objectSelector", {})
        if current.get("spec") != expected_spec:
            return False
        annotations = current.get("metadata", {}).get("annotations", {})
        if annotations.get("saf-k8s.example/bundle-version") != VERSION:
            return False
        if annotations.get("saf-k8s.example/control") != "SAF-K8S-0910-026":
            return False
    return True


def run(lab):
    bundle_bytes = BUNDLE_PATH.read_bytes()
    bundle_text = bundle_bytes.decode("utf-8")
    actual_hash = hashlib.sha256(bundle_bytes).hexdigest()
    if actual_hash != BUNDLE_SHA256:
        lab.block("The checked-in admission bundle does not match its pinned SHA-256")
    resources = bundle_resources(bundle_text)
    envelope_value = {"version": VERSION, "bundle_sha256": actual_hash,
                      "resources": resources}
    envelope_text = json.dumps(envelope_value, sort_keys=True, separators=(",", ":"))
    envelope_hash = hashlib.sha256(envelope_text.encode()).hexdigest()

    case_library = locate_case_library()
    peer_bridge = load(case_library / "SAF-K8S-0910-020" / "owned_peer.py", "saf_baseline_peer")
    runtime = load(case_library / "SAF-K8S-0908-001" / "case.py", "saf_baseline_runtime")
    deployment = load(HERE / "workload_fixture.py", "saf_baseline_workload").deployment
    image = runtime.load_runtime(lab)
    with peer_bridge.owned_peer(lab, image) as (peer_kubectl, _):
        local = Target("local", lab.kubectl)
        remote = Target("remote", peer_kubectl)
        targets = (local, remote)

        local_uid = output(local, "get", "namespace", "kube-system", "-o",
                           "jsonpath={.metadata.uid}").strip()
        remote_uid = output(remote, "get", "namespace", "kube-system", "-o",
                            "jsonpath={.metadata.uid}").strip()
        if not local_uid or not remote_uid or local_uid == remote_uid:
            lab.block("The local and owned peer API servers must have distinct cluster identities")

        # Namespaces and approval are synthetic fixtures. The local immutable
        # ConfigMap is the test's central approval record; its exact object is
        # mirrored to the independently owned peer before policy distribution.
        for target in targets:
            create_fixture(target, row("Namespace", CONTROL_NS))
            create_fixture(target, row("Namespace", WORKLOAD_NS,
                                      metadata={"name": WORKLOAD_NS,
                                                "labels": {"saf-k8s.example/admission-baseline": "required"}}))
            create_fixture(target, row("ServiceAccount", CANDIDATE_SA,
                                      automountServiceAccountToken=False), CONTROL_NS)
            grant_candidate_read_access(target)
            writer_access(target)
            create_fixture(target, row("ConfigMap", WRITER_CODE_CM, immutable=True,
                                       data={"policy_writer.py": (HERE / "policy_writer.py").read_text()}),
                           CONTROL_NS)
        approved = approval_record(actual_hash, envelope_hash)
        create_fixture(local, approved, CONTROL_NS)
        # Read back the protected source and copy that observed state, rather
        # than trusting a caller-supplied approval boolean or digest.
        local_approval_object = read_approval_object(local)
        local_approval = summarize_approval(local_approval_object)
        if local_approval != {"version": VERSION, "sha256": actual_hash,
                              "envelope_sha256": envelope_hash,
                              "policy": POLICY, "immutable": True}:
            lab.block("The central protected approval record does not bind this exact bundle")
        observed_approval = {
            "apiVersion": local_approval_object["apiVersion"],
            "kind": local_approval_object["kind"],
            "metadata": {"name": local_approval_object["metadata"]["name"],
                         "labels": local_approval_object["metadata"].get("labels", {}),
                         "annotations": local_approval_object["metadata"].get("annotations", {})},
            "immutable": local_approval_object.get("immutable") is True,
            "data": dict(local_approval_object["data"]),
        }
        create_fixture(remote, observed_approval, CONTROL_NS)
        for target in targets:
            create_fixture(target, row("ConfigMap", ENVELOPE_CM, immutable=True, data={
                "version": VERSION, "sha256": envelope_hash,
                "bundle_sha256": actual_hash, "resources.json": envelope_text,
            }), CONTROL_NS)
            create_fixture(target, row("ConfigMap", WRONG_ENVELOPE_CM, immutable=True, data={
                "version": "v0", "sha256": envelope_hash,
                "bundle_sha256": actual_hash, "resources.json": envelope_text,
            }), CONTROL_NS)

        baseline_obj = deployment("saf026-privileged-fixture", privileged=True)
        baseline = {target.name: admit(target, baseline_obj) for target in targets}
        baseline_ok = all(v["decision"] == "accepted" for v in baseline.values())
        lab.check("red", "Both dry-run requests are accepted before admission policy", baseline_ok, baseline)

        wrong_version = {target.name: attempt_wrong_version(target) for target in targets}
        protected_after = {target.name: read_approval(target) for target in targets}
        protection_ok = all(v["candidate_write_denied"] for v in wrong_version.values()) and all(
            v == {"version": VERSION, "sha256": actual_hash,
                  "envelope_sha256": envelope_hash,
                  "policy": POLICY, "immutable": True}
            for v in protected_after.values()
        )

        # Gate application on observed protected state at both API servers.
        approved_at_both = all(v == local_approval for v in protected_after.values())
        if not approved_at_both:
            lab.block("The peer does not hold the exact centrally approved version and hash")

        # Start with exact named, non-enforcing resources. The member-side
        # ServiceAccount can patch these only after its own API read confirms
        # the approved immutable bytes and version.
        placeholders = placeholder_resources(resources)
        for target in targets:
            for obj in placeholders:
                create_fixture(target, obj)
        wrong_writer = {target.name: writer_pod(target, image, "withhold", target.name + "-wrong")
                        for target in targets}
        placeholder_after_wrong = {
            target.name: {"policy": read_policy_state(target),
                          "binding": binding_placeholder_state(target)}
            for target in targets
        }
        placeholder_unchanged = all(
            value["policy"]["expression"] == "true"
            and value["policy"]["version"] == VERSION
            and value["binding"] == {"policy_name": POLICY,
                                     "selector_value": "fixture-not-enabled"}
            for value in placeholder_after_wrong.values())
        compliant_after_wrong = {
            target.name: admit(target, deployment("saf026-compliant-before-approved", privileged=False))
            for target in targets
        }
        wrong_version_preserved_api = all(
            value["decision"] == "accepted" for value in compliant_after_wrong.values())
        wrong_withheld = all(
            result["phase_succeeded"] and result["writer_service_account"]
            and result["result"].get("decision") == "withheld"
            and result["result"].get("version_match") is False
            and result["result"].get("envelope_match") is True
            and result["result"].get("no_write") is True
            for result in wrong_writer.values())

        writer_results = {target.name: writer_pod(target, image, "apply", target.name + "-approved")
                          for target in targets}
        policy_readback = {target.name: resources_match(target, resources) for target in targets}
        apply_results = {name: {"phase_succeeded": result["phase_succeeded"],
                                "writer_service_account": result["writer_service_account"],
                                "decision": result["result"].get("decision"),
                                "version_match": result["result"].get("version_match") is True,
                                "bundle_match": result["result"].get("bundle_match") is True,
                                "envelope_match": result["result"].get("envelope_match") is True,
                                "fixed_resources": result["result"].get("fixed_resources") is True,
                                "policy_patch_accepted": result["result"].get("policy_patch_accepted") is True,
                                "binding_patch_accepted": result["result"].get("binding_patch_accepted") is True}
                         for name, result in writer_results.items()}
        apply_ok = all(
            result["phase_succeeded"] and result["writer_service_account"]
            and result["result"].get("decision") == "applied"
            and result["result"].get("version_match") is True
            and result["result"].get("bundle_match") is True
            and result["result"].get("envelope_match") is True
            and result["result"].get("fixed_resources") is True
            and result["result"].get("policy_patch_accepted") is True
            and result["result"].get("binding_patch_accepted") is True
            for result in writer_results.values()) and all(policy_readback.values())
        if not apply_ok:
            lab.block("The scoped member writer did not apply and read back the approved bundle")
        accepted = {target.name: policy_ready(target) for target in targets}

        unapproved_policy = {target.name: attempt_policy_replacement(target) for target in targets}
        active_policy = {target.name: read_policy_state(target) for target in targets}
        policy_protection_ok = all(v["candidate_write_denied"] for v in unapproved_policy.values()) and all(
            v["version"] == VERSION and v["failurePolicy"] == "Fail"
            and v["expression"] and v["expression"] != "true"
            for v in active_policy.values()
        )

        denial = {}
        for target in targets:
            deadline = time.monotonic() + 15
            observation = admit(target, baseline_obj)
            while observation["decision"] == "accepted" and time.monotonic() < deadline:
                time.sleep(0.25)
                observation = admit(target, baseline_obj)
            denial[target.name] = observation
        compliant_obj = deployment("saf026-compliant-fixture", privileged=False)
        compliant = {target.name: admit(target, compliant_obj) for target in targets}

        decisions = {
            "before_policy": {name: value["decision"] for name, value in baseline.items()},
            "after_policy_denial": {name: value["decision"] for name, value in denial.items()},
            "approved_behavior": {name: value["decision"] for name, value in compliant.items()},
        }
        matched = all(len(set(phase.values())) == 1 for phase in decisions.values())
        expected = (
            all(v == "accepted" for v in decisions["before_policy"].values())
            and all(v == "denied-by-policy" for v in decisions["after_policy_denial"].values())
            and all(v == "accepted" for v in decisions["approved_behavior"].values())
        )
        outcome = {
            "control": "SAF-K8S-0910-026",
            "version": VERSION,
            "bundle_sha256": actual_hash,
            "independent_api_servers": True,
            "approval": {"wrong_version_update": wrong_version,
                         "protected_state_after_attempt": protected_after,
                         "protection_passed": protection_ok,
                         "active_policy_replacement": unapproved_policy,
                         "active_policy_after_attempt": active_policy,
                         "active_policy_protection_passed": policy_protection_ok},
            "bundle_applied": apply_results,
            "scoped_writer": {"wrong_version": wrong_writer,
                              "placeholder_after_wrong": placeholder_after_wrong,
                              "compliant_after_wrong_version": {
                                  name: value["decision"] for name, value in compliant_after_wrong.items()},
                              "wrong_version_preserved_api": wrong_version_preserved_api,
                              "wrong_version_withheld": wrong_withheld,
                              "placeholder_unchanged": placeholder_unchanged,
                              "approved_readback": policy_readback},
            "policy_accepted": accepted,
            "observations": {"before_policy": baseline,
                             "after_policy_denial": denial,
                             "approved_behavior": compliant},
            "normalized_decisions": decisions,
            "independently_matched": matched,
            "expected_behavior": expected,
        }
        (lab.evidence / "saf-k8s-0910-026-matched-observations.json").write_text(
            json.dumps(outcome, sort_keys=True, indent=2) + "\n"
        )
        lab.check("green", "Wrong-version candidate cannot alter protected approval state",
                  protection_ok and policy_protection_ok, outcome["approval"])
        lab.check("green", "Both API servers type-check the same hash-bound bundle without warnings",
                  all(accepted.values()) and apply_ok and approved_at_both,
                  {"apply": apply_results, "accepted": accepted})
        distribution_observed = {
            "two_owned_targets": len(targets) == 2 and local_uid != remote_uid,
            "writer_identity_used": all(v["writer_service_account"] and v["phase_succeeded"]
                                         for v in writer_results.values()),
            "approved_version_and_digest_matched": all(
                v["result"].get("version_match") is True
                and v["result"].get("bundle_match") is True
                and v["result"].get("envelope_match") is True
                and v["result"].get("fixed_resources") is True
                for v in writer_results.values()),
            "approved_resources_read_back_on_both": all(policy_readback.values()),
            "wrong_version_withheld_on_both": wrong_withheld,
            "wrong_version_left_placeholders_unchanged": placeholder_unchanged,
            "both_apis_accepted_compliant_request_after_wrong_version": wrong_version_preserved_api,
            "compliant_request_accepted_after_distribution_on_both": all(
                v["decision"] == "accepted" for v in compliant.values()),
        }
        lab.check("green", "Scoped in-cluster writers distribute only the approved bundle on both APIs",
                  all(distribution_observed.values()), distribution_observed)
        lab.check("green", "Both independent clusters deny the privileged synthetic Deployment",
                  all(v["decision"] == "denied-by-policy" for v in denial.values())
                  and matched, denial)
        lab.check("positive", "Both clusters admit the compliant synthetic Deployment",
                  all(v["decision"] == "accepted" for v in compliant.values()) and matched,
                  compliant)
        lab.check("positive", "Local and remote decisions match in every phase",
                  matched and expected, decisions)
