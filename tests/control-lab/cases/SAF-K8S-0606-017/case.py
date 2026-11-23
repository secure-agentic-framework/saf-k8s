"""Exercise pre-runtime delivery checks and one separate live runtime check."""

import copy
import hashlib
import json
import time

SCOPE = "Four distinct checkpoints for a single public fixture workload in Kind."
IMAGE = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
TAG_ONLY = IMAGE.split("@", 1)[0]
MARKER = "saf-public-lifecycle-v1"
POLICY = "saf-fixture-release-image"


def workload(name, *, image=IMAGE):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "fixture", "image": image,
                                     "command": ["/bin/sh", "-c", "printf '%s\\n' \"$MARKER\"; exec sleep 240"],
                                     "env": [{"name": "MARKER", "value": MARKER}],
                                     "readinessProbe": {"exec": {"command": ["/bin/true"]}, "periodSeconds": 1},
                                     "securityContext": {"allowPrivilegeEscalation": False,
                                                         "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}}}]}}


def digest(source):
    return "sha256:" + hashlib.sha256(source.encode()).hexdigest()


def stage(lab, name, source, approved):
    if digest(source) != approved:
        return False
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "immutable": True,
                "data": {"workload.json": source, "sha256": approved}})
    return True


def install_policy(lab):
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
                "metadata": {"name": POLICY}, "spec": {"failurePolicy": "Fail", "matchConstraints": {
                    "resourceRules": [{"operations": ["CREATE"], "apiGroups": [""], "apiVersions": ["v1"],
                                       "resources": ["pods"], "scope": "Namespaced"}]},
                    "validations": [{"expression": f"object.spec.containers.all(c, c.image == '{IMAGE}')",
                                     "message": "the fixture release requires the approved image digest"}]}})
    lab.create({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
                "metadata": {"name": POLICY}, "spec": {"policyName": POLICY, "validationActions": ["Deny"],
                    "matchResources": {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "saf-test"}}}}})


def run(lab):
    candidate = workload("approved-lifecycle")
    incomplete_config = copy.deepcopy(candidate)
    del incomplete_config["spec"]["containers"][0]["securityContext"]["allowPrivilegeEscalation"]
    develop_unchecked = lab.create(incomplete_config, dry_run=True)
    deploy_unchecked = lab.create(workload("candidate-tag-only", image=TAG_ONLY), dry_run=True)
    lab.check("red", "Without the fixture guardrails, Kubernetes admits both declarations in server dry runs",
              develop_unchecked["metadata"]["name"] == "approved-lifecycle"
              and deploy_unchecked["spec"]["containers"][0]["image"] == TAG_ONLY,
              {"no_develop_restriction_yet": True, "no_digest_enforcement_yet": True})
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    developed = lab.create(candidate, dry_run=True)
    dev_denied = lab.create(incomplete_config, dry_run=True, allow_failure=True)
    develop = (developed["metadata"]["name"] == candidate["metadata"]["name"] and dev_denied.returncode != 0
               and "violates PodSecurity" in dev_denied.stderr and "allowPrivilegeEscalation" in dev_denied.stderr)
    lab.check("green", "Develop preflight rejects an incomplete restricted Pod specification", develop,
              {"approved_manifest_admitted": bool(developed), "policy_denial_observed": develop})
    source = json.dumps(candidate, sort_keys=True)
    expected = digest(source)
    changed = copy.deepcopy(candidate)
    changed["metadata"]["annotations"] = {"example.invalid/revision": "other-public-source"}
    rejected_copy = not stage(lab, "rejected-release", json.dumps(changed, sort_keys=True), expected)
    missing_copy = not lab.kubectl("get", "configmap", "rejected-release", "-o", "name", "--ignore-not-found").stdout.strip()
    distributed = stage(lab, "released-workload", source, expected)
    released = json.loads(lab.kubectl("get", "configmap", "released-workload", "-o", "json").stdout)
    staged = released["data"]["workload.json"]
    transfer = bool(distributed and released["immutable"] and expected == released["data"]["sha256"] == digest(staged))
    lab.check("green", "Distribute rejects the changed artifact and readback matches the approved digest",
              rejected_copy and missing_copy and transfer,
              {"different_bytes_refused": rejected_copy and missing_copy, "approved_digest": expected})
    install_policy(lab)
    cutoff = time.monotonic() + 40
    while time.monotonic() < cutoff:
        denied = lab.create(workload("candidate-tag-only", image=TAG_ONLY), dry_run=True, allow_failure=True)
        if denied.returncode != 0 and POLICY in denied.stderr and "requires the approved image digest" in denied.stderr:
            break
        time.sleep(1)
    else:
        lab.block("The fixture deployment binding did not enforce the expected image policy")
    applied = lab.create(json.loads(staged))
    exact = applied["spec"]["containers"][0]["image"] == IMAGE
    lab.check("green", "Deploy admission blocks the tag-only candidate and admits the digest-pinned artifact",
              exact, {"tag_only_refused": True, "approved_image": IMAGE})
    name = applied["metadata"]["name"]
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + name, "--timeout=70s", timeout=80)
    actual = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
    public_log = lab.kubectl("logs", name).stdout.strip()
    same_workload = actual["metadata"]["uid"] == applied["metadata"]["uid"]
    running = actual["status"]["phase"] == "Running" and actual["status"]["containerStatuses"][0]["ready"]
    runtime = {"same_workload": same_workload, "ready": running, "marker_matches": public_log == MARKER,
               "different_runtime_expectation_refused": public_log != "different-public-runtime-marker"}
    lab.check("positive", "Runtime verifies the admitted Pod is Ready and emitted the expected marker",
              all(runtime.values()), runtime)
    (lab.evidence / "phase-observations.json").write_text(json.dumps({
        "develop_preflight_enforced": develop, "distribution_artifact_sha256": expected,
        "deploy_policy": POLICY, "runtime": runtime,
    }, indent=2) + "\n")
