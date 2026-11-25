"""Demonstrate exact cleanup of one synthetic retired AI workload."""
import json
from pathlib import Path
import time


HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
CONTROL_ID = "SAF-K8S-1007-006"
CASE_LABEL = "saf-lab.example/control"
FIXTURE_LABEL = "saf-lab.example/fixture"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)

NAMES = {
    "configmap": ["saf-1007-006-data-marker"],
    "secret": ["saf-1007-006-empty-secret"],
    "serviceaccount": ["saf-1007-006-retired-sa"],
    "role": ["saf-1007-006-target-read"],
    "rolebinding": ["saf-1007-006-target-grant"],
    "pod": ["saf-1007-006-retired-workload"],
    "networkpolicy": ["saf-1007-006-target-network-policy"],
    "resourcequota": ["saf-1007-006-gpu-quota-placeholder"],
    "syntheticartifacts.saf-lab.example": ["saf-1007-006-registry-placeholder"],
    "persistentvolume": ["saf-1007-006-storage-placeholder"],
    "customresourcedefinition": ["syntheticartifacts.saf-lab.example"],
}
COMPARATOR = {
    "serviceaccount": "saf-1007-006-comparator-sa",
    "role": "saf-1007-006-comparator-read",
    "rolebinding": "saf-1007-006-comparator-grant",
    "configmap": "saf-1007-006-comparator-marker",
}
OWNERSHIP_KIND = {"syntheticartifacts.saf-lab.example": "syntheticartifact"}

SCOPE = (
    "One disposable Kind Kubernetes v1.36.1 cluster and synthetic objects in saf-test. "
    "The case first leaves an inert Pod's ConfigMap, empty Secret, ServiceAccount, scoped "
    "RBAC grant, NetworkPolicy, GPU-named ResourceQuota, unbound CSI PV record, and a "
    "synthetic CRD/custom resource after deleting the mock workload. It records the stale "
    "grant using Kubernetes authorization, removes the exact grant and residual objects, "
    "and verifies target absence plus a separate comparator grant. No credential values, "
    "real identity, external registry/provider, GPU device, storage backend, or data are used. "
    "Kubernetes API object deletion is not proof of backend erasure, registry deletion, "
    "GPU release, external identity revocation, or production process coverage."
)


def owned(kind, name, *, namespace=True, labels=None, **body):
    metadata = {"name": name, "labels": {CASE_LABEL: CONTROL_ID, FIXTURE_LABEL: "true"}}
    if namespace:
        metadata["namespace"] = NAMESPACE
    if labels:
        metadata["labels"].update(labels)
    return {"apiVersion": "v1", "kind": kind, "metadata": metadata, **body}


def create_owned(lab, resource):
    created = lab.create(resource)
    metadata = created.get("metadata", {})
    labels = metadata.get("labels", {})
    if (labels.get(CASE_LABEL) != CONTROL_ID or labels.get(FIXTURE_LABEL) != "true"
            or not metadata.get("uid")):
        lab.block("Created fixture did not return the exact case ownership labels and UID")
    key = (created["kind"].lower(), metadata.get("name"))
    lab.case_owned_uids[key] = metadata["uid"]
    return created


def assert_owned(lab, kind, name):
    key = (OWNERSHIP_KIND.get(kind, kind), name)
    expected_uid = lab.case_owned_uids.get(key)
    if not expected_uid:
        lab.block(f"No creation UID was recorded for case object {kind}/{name}")
    result = lab.kubectl("get", kind, name, "--ignore-not-found", "-o", "json", allow_failure=True)
    if result.returncode != 0:
        lab.block(f"Could not verify ownership of case object {kind}/{name}")
    if not result.stdout.strip():
        return False
    current = json.loads(result.stdout).get("metadata", {})
    labels = current.get("labels", {})
    if (current.get("uid") != expected_uid or labels.get(CASE_LABEL) != CONTROL_ID
            or labels.get(FIXTURE_LABEL) != "true"):
        lab.block(f"Refusing to clean up object whose UID or ownership labels changed: {kind}/{name}")
    return True


def create_fixtures(lab):
    workload_label = {"saf-lab.example/workload": "retired"}
    comparator_label = {"saf-lab.example/workload": "comparator"}

    create_owned(lab, owned("ConfigMap", NAMES["configmap"][0],
                            data={"fixture": "synthetic-non-sensitive-marker"}))
    # Empty by design: the runner logs create requests. No credential material is present.
    create_owned(lab, owned("Secret", NAMES["secret"][0], type="Opaque"))
    create_owned(lab, owned("ServiceAccount", NAMES["serviceaccount"][0], automountServiceAccountToken=False))
    create_owned(lab, owned("ServiceAccount", COMPARATOR["serviceaccount"], automountServiceAccountToken=False))

    rule = {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [NAMES["configmap"][0]], "verbs": ["get"]}
    create_owned(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": NAMES["role"][0], "namespace": NAMESPACE,
                             "labels": {CASE_LABEL: CONTROL_ID, FIXTURE_LABEL: "true"}}, "rules": [rule]})
    create_owned(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": NAMES["rolebinding"][0], "namespace": NAMESPACE,
                             "labels": {CASE_LABEL: CONTROL_ID, FIXTURE_LABEL: "true"}},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": NAMES["role"][0]},
                "subjects": [{"kind": "ServiceAccount", "name": NAMES["serviceaccount"][0], "namespace": NAMESPACE}]})

    comparator_rule = {"apiGroups": [""], "resources": ["configmaps"],
                       "resourceNames": [COMPARATOR["configmap"]], "verbs": ["get"]}
    create_owned(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": COMPARATOR["configmap"], "namespace": NAMESPACE,
                             "labels": {CASE_LABEL: CONTROL_ID, FIXTURE_LABEL: "true"}},
                "data": {"fixture": "unrelated-positive-comparator"}})
    create_owned(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": COMPARATOR["role"], "namespace": NAMESPACE,
                             "labels": {CASE_LABEL: CONTROL_ID, FIXTURE_LABEL: "true"}}, "rules": [comparator_rule]})
    create_owned(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                "metadata": {"name": COMPARATOR["rolebinding"], "namespace": NAMESPACE,
                             "labels": {CASE_LABEL: CONTROL_ID, FIXTURE_LABEL: "true"}},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": COMPARATOR["role"]},
                "subjects": [{"kind": "ServiceAccount", "name": COMPARATOR["serviceaccount"], "namespace": NAMESPACE}]})

    create_owned(lab, owned("Pod", NAMES["pod"][0], labels=workload_label, spec={
        "restartPolicy": "Never", "terminationGracePeriodSeconds": 3,
        "serviceAccountName": NAMES["serviceaccount"][0],
        "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "mock-workload", "image": PYTHON_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "-c", "import time; time.sleep(3600)"],
                        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                                      "limits": {"cpu": "100m", "memory": "64Mi"}},
                        "securityContext": {"readOnlyRootFilesystem": True,
                                            "allowPrivilegeEscalation": False,
                                            "capabilities": {"drop": ["ALL"]}}}],
    }))
    create_owned(lab, owned("NetworkPolicy", NAMES["networkpolicy"][0],
                     apiVersion="networking.k8s.io/v1", spec={
                         "podSelector": {"matchLabels": workload_label},
                         "policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": [],
                     }))
    create_owned(lab, owned("ResourceQuota", NAMES["resourcequota"][0], spec={
        "hard": {"requests.example.com/synthetic-gpu": "1"},
    }))

    create_owned(lab, {"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
                "metadata": {"name": NAMES["customresourcedefinition"][0],
                             "labels": {CASE_LABEL: CONTROL_ID, FIXTURE_LABEL: "true"}},
                "spec": {"group": "saf-lab.example", "scope": "Namespaced",
                         "names": {"plural": "syntheticartifacts", "singular": "syntheticartifact",
                                   "kind": "SyntheticArtifact", "shortNames": ["safartifact"]},
                         "versions": [{"name": "v1", "served": True, "storage": True,
                                       "schema": {"openAPIV3Schema": {"type": "object",
                                                   "properties": {"spec": {"type": "object",
                                                               "properties": {"fixtureId": {"type": "string"}}}}}}}]}})
    wait_crd(lab)
    create_owned(lab, {"apiVersion": "saf-lab.example/v1", "kind": "SyntheticArtifact",
                "metadata": {"name": NAMES["syntheticartifacts.saf-lab.example"][0],
                             "namespace": NAMESPACE,
                             "labels": {CASE_LABEL: CONTROL_ID, FIXTURE_LABEL: "true"}},
                "spec": {"fixtureId": "SYNTH-1007-006-ARTIFACT-001"}})
    create_owned(lab, {"apiVersion": "v1", "kind": "PersistentVolume",
                "metadata": {"name": NAMES["persistentvolume"][0],
                             "labels": {CASE_LABEL: CONTROL_ID, FIXTURE_LABEL: "true"}},
                "spec": {"capacity": {"storage": "1Mi"}, "accessModes": ["ReadWriteOnce"],
                         "persistentVolumeReclaimPolicy": "Retain", "storageClassName": "saf-synthetic-unbound",
                         "csi": {"driver": "synthetic-csi.example.com", "volumeHandle": "synth-1007-006-no-backend"}}})


def wait_crd(lab):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        result = lab.kubectl("get", "crd", NAMES["customresourcedefinition"][0], "-o", "json", allow_failure=True)
        if result.returncode == 0:
            crd = json.loads(result.stdout)
            if any(condition.get("type") == "Established" and condition.get("status") == "True"
                   for condition in ((crd.get("status") or {}).get("conditions") or [])):
                return
        time.sleep(0.25)
    lab.block("Synthetic CRD did not become discoverable")


def marker_access(lab, identity, resource_name, marker):
    subject = f"system:serviceaccount:{NAMESPACE}:{identity}"
    result = lab.kubectl(f"--as={subject}", "-n", NAMESPACE, "get", "configmap",
                         resource_name, "-o", "jsonpath={.data.fixture}", allow_failure=True)
    if result.returncode == 0 and result.stdout == marker:
        return True
    if result.returncode != 0 and "(Forbidden)" in result.stderr and subject in result.stderr:
        return False
    lab.block("Named marker lookup returned neither the expected bytes nor a scoped RBAC refusal")


def wait_workload(lab):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        result = lab.kubectl("get", "pod", NAMES["pod"][0], "-o", "json")
        pod = json.loads(result.stdout)
        conditions = (pod.get("status") or {}).get("conditions") or []
        if any(row.get("type") == "Ready" and row.get("status") == "True" for row in conditions):
            return
        phase = pod.get("status", {}).get("phase")
        if phase == "Failed":
            lab.block("Synthetic mock workload failed before retirement")
        time.sleep(1)
    lab.block("Synthetic mock workload did not become Ready before retirement")


def exists(lab, kind, name):
    if kind == "syntheticartifacts.saf-lab.example":
        crd = NAMES["customresourcedefinition"][0]
        if not exists(lab, "customresourcedefinition", crd):
            return False
    result = lab.kubectl("get", kind, name, "--ignore-not-found", "-o", "name")
    return bool(result.stdout.strip())


def resource_uri(kind, name):
    core = f"/api/v1/namespaces/{NAMESPACE}"
    namespaced_rbac = f"/apis/rbac.authorization.k8s.io/v1/namespaces/{NAMESPACE}"
    targets = {
        "pod": f"{core}/pods",
        "secret": f"{core}/secrets",
        "configmap": f"{core}/configmaps",
        "serviceaccount": f"{core}/serviceaccounts",
        "resourcequota": f"{core}/resourcequotas",
        "networkpolicy": f"/apis/networking.k8s.io/v1/namespaces/{NAMESPACE}/networkpolicies",
        "role": f"{namespaced_rbac}/roles",
        "rolebinding": f"{namespaced_rbac}/rolebindings",
        "syntheticartifacts.saf-lab.example":
            f"/apis/saf-lab.example/v1/namespaces/{NAMESPACE}/syntheticartifacts",
        "customresourcedefinition": "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
        "persistentvolume": "/api/v1/persistentvolumes",
    }
    return f"{targets[kind]}/{name}"


def delete_by_uid(lab, kind, name, uid, *, allow_failure=False):
    options = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid}}
    return lab.kubectl("delete", "--raw", resource_uri(kind, name), "-f", "-",
                       payload=json.dumps(options), allow_failure=allow_failure)


def delete(lab, kind, name):
    if not assert_owned(lab, kind, name):
        return
    key = (OWNERSHIP_KIND.get(kind, kind), name)
    delete_by_uid(lab, kind, name, lab.case_owned_uids[key])
    deadline = time.monotonic() + 40
    while exists(lab, kind, name):
        if time.monotonic() >= deadline:
            lab.block(f"Owned object did not disappear after UID-bound deletion: {kind}/{name}")
        time.sleep(0.25)


def remove_target(lab):
    delete(lab, "rolebinding", NAMES["rolebinding"][0])
    deadline = time.monotonic() + 20
    while marker_access(lab, NAMES["serviceaccount"][0], NAMES["configmap"][0],
                        "synthetic-non-sensitive-marker"):
        if time.monotonic() >= deadline:
            lab.block("Retired ServiceAccount remained authorized after RoleBinding removal")
        time.sleep(0.25)

    # Observe the refusal while the marker still exists, then remove only the owned objects.
    if not exists(lab, "configmap", NAMES["configmap"][0]):
        lab.block("The authorization reversal was not independently observed against an existing object")
    for kind in ("pod", "networkpolicy", "resourcequota", "secret", "configmap", "serviceaccount", "role",
                 "syntheticartifacts.saf-lab.example", "customresourcedefinition", "persistentvolume"):
        for name in NAMES[kind]:
            delete(lab, kind, name)


def target_absent(lab):
    return {f"{kind}/{name}": not exists(lab, kind, name)
            for kind, names in NAMES.items() for name in names}


def run(lab):
    boundary = json.loads((HERE / "fixtures" / "scope-boundaries.json").read_text())
    if boundary.get("fixture_id") != "SYNTH-1007-006-SCOPE-001":
        lab.block("Synthetic scope boundary fixture identity mismatch")
    lab.case_owned_uids = {}
    create_fixtures(lab)

    # A retired workload leaves its exact named support objects and grant behind.
    wait_workload(lab)
    delete(lab, "pod", NAMES["pod"][0])
    leftovers = {f"{kind}/{name}": exists(lab, kind, name)
                 for kind, names in NAMES.items() for name in names}
    stale_access = marker_access(lab, NAMES["serviceaccount"][0], NAMES["configmap"][0],
                                 "synthetic-non-sensitive-marker")
    comparator_before = marker_access(lab, COMPARATOR["serviceaccount"], COMPARATOR["configmap"],
                                              "unrelated-positive-comparator")
    residual = {key: value for key, value in leftovers.items()
                if key != f"pod/{NAMES['pod'][0]}"}
    lab.check("red", "The retired mock workload is absent while named artifacts and a stale grant remain",
              (not exists(lab, "pod", NAMES["pod"][0]) and all(residual.values()) and stale_access
               and comparator_before),
              {"retired_workload_absent": not exists(lab, "pod", NAMES["pod"][0]),
               "residual_objects_present": sum(residual.values()), "stale_mock_grant_authorizes": stale_access,
               "comparator_initially_authorized": comparator_before})

    target_name = NAMES["configmap"][0]
    incorrect_uid = "00000000-0000-0000-0000-000000000000"
    comparison = delete_by_uid(lab, "configmap", target_name, incorrect_uid, allow_failure=True)
    mismatch_rejected = (comparison.returncode != 0 and "(Conflict)" in comparison.stderr
                         and "uid in the precondition" in comparison.stderr.lower()
                         and assert_owned(lab, "configmap", target_name))
    lab.check("green", "A deletion carrying the wrong UID cannot remove the case-owned record",
              mismatch_rejected, {"mismatched_uid_rejected": mismatch_rejected})
    remove_target(lab)
    absence = target_absent(lab)
    retired_access = marker_access(lab, NAMES["serviceaccount"][0], NAMES["configmap"][0],
                                   "synthetic-non-sensitive-marker")
    lab.check("green", "Exact target grant is revoked and every named target Kubernetes object is absent",
              all(absence.values()) and not retired_access,
              {"all_target_objects_absent": all(absence.values()), "absent_object_count": sum(absence.values()),
               "retired_mock_grant_authorizes": retired_access})

    comparator_access = marker_access(lab, COMPARATOR["serviceaccount"], COMPARATOR["configmap"],
                                              "unrelated-positive-comparator")
    comparator_present = all(exists(lab, kind, name) for kind, name in COMPARATOR.items())
    lab.check("positive", "Unrelated comparator grant and its named marker remain usable after target cleanup",
              comparator_access and comparator_present,
              {"comparator_authorized": comparator_access, "comparator_objects_present": comparator_present})

    # Remove the test comparator and check the whole case-owned object inventory is clean.
    for kind in ("rolebinding", "role", "serviceaccount", "configmap"):
        delete(lab, kind, COMPARATOR[kind])
    leftovers = {f"{kind}/{name}": exists(lab, kind, name)
                 for kind, names in NAMES.items() for name in names}
    comparator_leftovers = {f"{kind}/{name}": exists(lab, kind, name) for kind, name in COMPARATOR.items()}
    lab.check("positive", "All exact case-owned target and comparator names are absent after final cleanup",
              not any(leftovers.values()) and not any(comparator_leftovers.values()),
              {"target_leftover_count": sum(leftovers.values()),
               "comparator_leftover_count": sum(comparator_leftovers.values()),
               "external_scope": boundary})

    (lab.evidence / "decommission-observations.raw.json").write_text(json.dumps({
        "owned_uids": {f"{kind}/{name}": uid for (kind, name), uid in lab.case_owned_uids.items()},
        "observed_objects_before": residual, "removed_target_objects": absence,
        "comparator_access_before": comparator_before, "comparator_access_after": comparator_access,
        "wrong_uid_rejected": mismatch_rejected, "checks": lab.checks,
    }, indent=2, sort_keys=True) + "\n")
