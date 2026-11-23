"""Verify separate controller execution and authorized fixture ownership."""

import json
from pathlib import Path

SCOPE = "Real native Kubernetes deployment reconciliation plus a separate cloud-controller fixture without cloud credentials."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
RBAC = "rbac.authorization.k8s.io"
IDENTITY = "fixture-cloud-controller"
CLOUD = "fixture-cloud-state"
CORE = "fixture-core-state"
NATIVE = "fixture-native-workload"
NS = "saf-test"


def pod_spec(command, **settings):
    unit = {"name": "unit", "image": IMAGE, "command": command,
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                          "limits": {"cpu": "100m", "memory": "48Mi"}}}
    return {"securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [unit], "automountServiceAccountToken": False, **settings}


def marker(lab, name):
    return json.loads(lab.kubectl("get", "configmap", name, "-o", "json").stdout)["data"]["state"]


def set_scope(lab, names):
    lab.kubectl("patch", "role", IDENTITY, "--type=merge", "-p", json.dumps({
        "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["patch"], "resourceNames": names}],
    }))


def fixture(lab, name):
    spec = pod_spec(["python", "-B", "/fixture/controller.py"], serviceAccountName=IDENTITY,
                    automountServiceAccountToken=True, restartPolicy="Never",
                    volumes=[{"name": "source", "configMap": {"name": IDENTITY}}])
    spec["containers"][0]["volumeMounts"] = [{"name": "source", "mountPath": "/fixture", "readOnly": True}]
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                "spec": {"backoffLimit": 0, "template": {"spec": spec}}})
    lab.kubectl("wait", "--for=condition=Complete", "job/" + name, "--timeout=65s", timeout=75)
    result = json.loads(lab.kubectl("logs", "job/" + name).stdout)
    pod, = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={name}", "-o", "json").stdout)["items"]
    return result, pod


def core_manager(lab):
    matches = json.loads(lab.kubectl("-n", "kube-system", "get", "pods",
                                      "-l", "component=kube-controller-manager", "-o", "json").stdout)["items"]
    if len(matches) != 1:
        lab.block("Expected one native kube-controller-manager Pod in the test cluster")
    return matches[0]


def run(lab):
    lab.kubectl("label", "namespace", NS, "pod-security.kubernetes.io/enforce=restricted")
    manager = core_manager(lab)
    lab.kubectl("-n", "kube-system", "wait", "--for=condition=Ready",
                "pod/" + manager["metadata"]["name"], "--timeout=45s", timeout=55)
    lease_before = json.loads(lab.kubectl("-n", "kube-system", "get", "lease", "kube-controller-manager",
                                         "-o", "json").stdout)["spec"]["holderIdentity"]
    for name in (CLOUD, CORE):
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                    "data": {"state": "initial"}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": IDENTITY},
                "data": {"controller.py": Path(__file__).with_name("fixture_controller.py").read_text()}})
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": IDENTITY},
                "automountServiceAccountToken": False})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "Role", "metadata": {"name": IDENTITY},
                "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["patch"], "resourceNames": [CLOUD, CORE]}]})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "RoleBinding", "metadata": {"name": IDENTITY},
                "roleRef": {"apiGroup": RBAC, "kind": "Role", "name": IDENTITY},
                "subjects": [{"kind": "ServiceAccount", "namespace": NS, "name": IDENTITY}]})

    baseline, _ = fixture(lab, "fixture-cloud-broad")
    lab.check("red", "A separate workload can still touch both owned fixture markers when it has broad permissions",
              baseline == {"fixture_update": 200, "other_marker_update": 200}, baseline)
    lab.kubectl("patch", "configmap", CORE, "--type=merge", "-p", '{"data":{"state":"owned-by-core"}}')
    set_scope(lab, [CLOUD])
    result, own = fixture(lab, "fixture-cloud-reviewed")
    distinct = own["metadata"]["uid"] != manager["metadata"]["uid"] and own["spec"]["serviceAccountName"] == IDENTITY
    native_lease_denied = lab.kubectl("auth", "can-i", "patch", "leases.coordination.k8s.io/kube-controller-manager",
                                     "-n", "kube-system", "--as", f"system:serviceaccount:{NS}:{IDENTITY}",
                                     allow_failure=True).stdout.strip() == "no"
    lab.check("green", "The separate reviewed workload updates its own marker and cannot alter the core marker or lease",
              distinct and native_lease_denied and result == {"fixture_update": 200, "other_marker_update": 403}
              and marker(lab, CORE) == "owned-by-core" and marker(lab, CLOUD) == "fixture-reconciled",
              {**result, "independent_pod_and_identity": distinct, "native_lease_denied": native_lease_denied})

    lab.kubectl("delete", "job", "fixture-cloud-broad", "fixture-cloud-reviewed", "--wait=true")
    selector = {"app": NATIVE}
    workload = pod_spec(["python", "-c", "import time; time.sleep(120)"])
    lab.create({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": NATIVE},
                "spec": {"replicas": 1, "selector": {"matchLabels": selector},
                         "template": {"metadata": {"labels": selector}, "spec": workload}}})
    lab.kubectl("rollout", "status", "deployment/" + NATIVE, "--timeout=70s", timeout=80)
    lease_after = json.loads(lab.kubectl("-n", "kube-system", "get", "lease", "kube-controller-manager",
                                        "-o", "json").stdout)["spec"]["holderIdentity"]
    same_core = lease_before == lease_after and core_manager(lab)["metadata"]["uid"] == manager["metadata"]["uid"]
    deployed = json.loads(lab.kubectl("get", "deployment", NATIVE, "-o", "json").stdout)["status"]["readyReplicas"] == 1
    lab.check("positive", "Native deployment reconciliation succeeds after the fixture controller is removed",
              same_core and deployed, {"same_native_controller": same_core, "native_owned_workload_ready": deployed})
    (lab.evidence / "controller-separation-observations.json").write_text(json.dumps({
        "fixture_access": result, "independent_workload": distinct, "native_lease_unchanged": same_core,
        "native_workload_ready": deployed, "provider_controller_tested": False,
    }, indent=2) + "\n")
