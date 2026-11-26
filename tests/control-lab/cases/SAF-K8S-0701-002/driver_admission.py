"""Admission comparison for the owned CSI driver namespace.

Call run_driver_admission(lab, driver_pod, pinned_images) after the existing
pinned driver is Ready and before final cleanup. Pod probes use server dry-run;
no probe Pod is persisted. VAP objects are case-owned and deleted on success.
"""
import copy
import json
import time

DRIVER_NAMESPACE = "saf-0701-002-driver"
POLICY = "saf-0701-002-reviewed-csi-images"
BINDING = "saf-0701-002-reviewed-csi-images"
SCOPE_LABEL = "saf.example/csi-admission-scope"
SCOPE_VALUE = "0701-002"
MESSAGE = "CSI driver image must match reviewed references"


def _kubectl(lab, *args, allow_failure=False, payload=None):
    return lab.kubectl(*args, allow_failure=allow_failure, timeout=30, payload=payload)


def _not_found(result):
    return result.returncode != 0 and "NotFound" in result.stderr


def _container_images(spec):
    return [(item.get("name"), item.get("image"))
            for item in spec.get("containers", [])]


def run_driver_admission(lab, driver_pod, pinned_images):
    """Compare harmless dry-run Pod admission before and after a scoped VAP."""
    expected = {
        "hostpath": pinned_images["hostpath"],
        "node-driver-registrar": pinned_images["registrar"],
        "csi-provisioner": pinned_images["provisioner"],
    }
    if dict(_container_images(driver_pod["spec"])) != expected:
        lab.block("The live CSI Pod does not exactly match reviewed image references")

    _kubectl(lab, "label", "namespace", DRIVER_NAMESPACE,
             f"{SCOPE_LABEL}={SCOPE_VALUE}", "--overwrite")

    def candidate(name, images):
        spec = copy.deepcopy(driver_pod["spec"])
        spec.pop("nodeName", None)
        spec.pop("hostname", None)
        for container in spec["containers"]:
            container["image"] = images[container["name"]]
        return {
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": DRIVER_NAMESPACE,
                         "labels": copy.deepcopy(driver_pod["metadata"].get("labels", {}))},
            "spec": spec,
        }

    approved = candidate("saf-0701-002-approved-image-dryrun", expected)
    unapproved_images = dict(expected)
    unapproved_images["hostpath"] = "registry.invalid/saf-fixture/hostpathplugin:unapproved"
    unapproved = candidate("saf-0701-002-unapproved-image-dryrun", unapproved_images)

    # Baseline oracle: same inert altered image reference is API-valid before the policy.
    baseline = _kubectl(lab, "create", "-n", DRIVER_NAMESPACE, "-f", "-", "--dry-run=server", "-o", "json",
                        payload=json.dumps(unapproved), allow_failure=True)
    baseline_absent = _not_found(_kubectl(
        lab, "get", "pod", unapproved["metadata"]["name"], "-n", DRIVER_NAMESPACE,
        "-o", "name", allow_failure=True))

    policy = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {"resourceRules": [{
                "apiGroups": [""], "apiVersions": ["v1"],
                "operations": ["CREATE"], "resources": ["pods"],
                "scope": "Namespaced",
            }]},
            "matchConditions": [{
                "name": "only-owned-driver-namespace",
                "expression": "request.namespace == 'saf-0701-002-driver'",
            }],
            "validations": [{
                "expression": (
                    "object.spec.containers.size() == 3 && "
                    "object.spec.containers.exists(c, c.name == 'hostpath' && c.image == '" + expected["hostpath"] + "') && "
                    "object.spec.containers.exists(c, c.name == 'node-driver-registrar' && c.image == '" + expected["node-driver-registrar"] + "') && "
                    "object.spec.containers.exists(c, c.name == 'csi-provisioner' && c.image == '" + expected["csi-provisioner"] + "') && "
                    "(!has(object.spec.initContainers) || object.spec.initContainers.size() == 0)"
                ),
                "message": MESSAGE,
            }],
        },
    }
    binding = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": BINDING},
        "spec": {"policyName": POLICY, "validationActions": ["Deny"],
                 "matchResources": {"namespaceSelector": {
                     "matchLabels": {SCOPE_LABEL: SCOPE_VALUE},
                 }}},
    }
    _kubectl(lab, "create", "-f", "-", payload=json.dumps(policy))
    _kubectl(lab, "create", "-f", "-", payload=json.dumps(binding))

    def denied_by_policy():
        result = _kubectl(lab, "create", "-n", DRIVER_NAMESPACE, "-f", "-", "--dry-run=server", "-o", "json",
                          payload=json.dumps(unapproved), allow_failure=True)
        return result if result.returncode != 0 and MESSAGE in result.stderr else None

    deadline = time.monotonic() + 30
    refusal = None
    while time.monotonic() < deadline and refusal is None:
        refusal = denied_by_policy()
        if refusal is None:
            time.sleep(1)
    accepted = _kubectl(lab, "create", "-n", DRIVER_NAMESPACE, "-f", "-", "--dry-run=server", "-o", "json",
                        payload=json.dumps(approved), allow_failure=True)
    unapproved_absent = _not_found(_kubectl(
        lab, "get", "pod", unapproved["metadata"]["name"], "-n", DRIVER_NAMESPACE,
        "-o", "name", allow_failure=True))
    approved_absent = _not_found(_kubectl(
        lab, "get", "pod", approved["metadata"]["name"], "-n", DRIVER_NAMESPACE,
        "-o", "name", allow_failure=True))
    lab.check("positive", "Scoped VAP allows pinned refs and denies the same altered ref that passed baseline dry-run",
              baseline.returncode == 0 and baseline_absent and refusal is not None
              and accepted.returncode == 0 and unapproved_absent and approved_absent,
              {"unapproved_baseline_dry_run_accepted": baseline.returncode == 0,
               "baseline_candidate_absent": baseline_absent,
               "unapproved_after_policy_denied_by_exact_message": refusal is not None,
               "approved_after_policy_accepted": accepted.returncode == 0,
               "both_post_policy_candidates_absent": unapproved_absent and approved_absent})

    after = json.loads(_kubectl(lab, "get", "pod", driver_pod["metadata"]["name"],
                                "-n", DRIVER_NAMESPACE, "-o", "json").stdout)
    unchanged = (after["metadata"].get("uid") == driver_pod["metadata"].get("uid")
                 and _container_images(after["spec"]) == _container_images(driver_pod["spec"]))
    lab.check("positive", "Dry-run admission leaves the already-running pinned CSI Pod unchanged",
              unchanged,
              {"same_live_pod_uid": unchanged,
               "same_live_container_image_refs": unchanged})
    _kubectl(lab, "delete", "validatingadmissionpolicybinding", BINDING,
             "--wait=true", "--timeout=20s")
    _kubectl(lab, "delete", "validatingadmissionpolicy", POLICY,
             "--wait=true", "--timeout=20s")
