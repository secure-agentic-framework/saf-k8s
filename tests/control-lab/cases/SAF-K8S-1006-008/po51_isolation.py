"""PO.5.1 bounded namespace access-isolation witness; no credential data is logged."""
import json
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEV = "saf1006-po51-dev"
PROTECTED = "saf1006-po51-protected"
DEV_SA = "fixture-developer"
READER_SA = "fixture-protected-reader"
DEV_CM = "po51-dev-marker"
PROTECTED_CM = "po51-protected-marker"
DEV_MARKER = "synthetic-development-marker-v1"
PROTECTED_MARKER = "synthetic-protected-marker-v1"
CLUSTER_ROLE = "saf1006-po51-temporary-broad-read"
CLUSTER_BINDING = "saf1006-po51-temporary-broad-read-binding"
API_SCRIPT = r'''import json, os, ssl, sys, urllib.error, urllib.parse, urllib.request
from pathlib import Path

phase = sys.argv[1]
actor = os.environ["FIXTURE_ACTOR"]
namespace = os.environ["FIXTURE_NAMESPACE"]
config = json.loads(Path("/fixture/expectations.json").read_text())
ctx = ssl.create_default_context(cafile="/var/run/fixture-token/ca.crt")
token = Path("/var/run/fixture-token/token").read_text().strip()
base = "https://" + os.environ["KUBERNETES_SERVICE_HOST"] + ":" + os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443") + "/api/v1/namespaces/"

def call(target_ns, verb, name):
    if verb == "get":
        path = base + urllib.parse.quote(target_ns, safe="") + "/configmaps/" + urllib.parse.quote(name, safe="")
    else:
        selector = urllib.parse.urlencode({"fieldSelector": "metadata.name=" + name})
        path = base + urllib.parse.quote(target_ns, safe="") + "/configmaps?" + selector
    req = urllib.request.Request(path, headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=8) as response:
            body = json.loads(response.read())
            obj = body if verb == "get" else next((x for x in body.get("items", []) if x.get("metadata", {}).get("name") == name), None)
            if obj is None:
                return {"status": response.status, "found": False}
            return {"status": response.status, "found": True,
                    "namespace": obj.get("metadata", {}).get("namespace"),
                    "name": obj.get("metadata", {}).get("name"),
                    "uid": obj.get("metadata", {}).get("uid"),
                    "marker": obj.get("data", {}).get("marker")}
    except urllib.error.HTTPError as error:
        # Parse only the structured status reason; never serialize request headers or token.
        try:
            reason = json.loads(error.read()).get("reason")
        except Exception:
            reason = None
        return {"status": error.code, "reason": reason}

protected_ns = config["protected_namespace"]
dev_obj = config["developer_resource"]
protected_obj = config["protected_resource"]
checks = {}
if phase == "baseline":
    checks = {"developer_get_own": call(namespace, "get", dev_obj["name"]),
              "developer_list_own": call(namespace, "list", dev_obj["name"]),
              "developer_get_protected": call(protected_ns, "get", protected_obj["name"]),
              "developer_list_protected": call(protected_ns, "list", protected_obj["name"])}
elif phase == "restricted-developer":
    checks = {"developer_get_own": call(namespace, "get", dev_obj["name"]),
              "developer_list_own": call(namespace, "list", dev_obj["name"]),
              "developer_get_protected": call(protected_ns, "get", protected_obj["name"]),
              "developer_list_protected": call(protected_ns, "list", protected_obj["name"])}
elif phase == "approved-reader":
    checks = {"reader_get_protected": call(namespace, "get", protected_obj["name"]),
              "reader_list_protected": call(namespace, "list", protected_obj["name"])}
else:
    raise SystemExit(22)

expect_dev = config["developer_resource"]
expect_protected = config["protected_resource"]
def is_ok(result, expected):
    return (result.get("status") == 200 and result.get("found") is True
            and result.get("namespace") == expected["namespace"]
            and result.get("name") == expected["name"]
            and result.get("uid") == expected["uid"]
            and ("marker" not in expected or result.get("marker") == expected["marker"]))
if phase == "baseline":
    matched = all(is_ok(checks[key], expect_dev) for key in ("developer_get_own", "developer_list_own")) and all(
        is_ok(checks[key], expect_protected) for key in ("developer_get_protected", "developer_list_protected"))
elif phase == "restricted-developer":
    matched = all(is_ok(checks[key], expect_dev) for key in ("developer_get_own", "developer_list_own")) and all(
        checks[key] == {"status": 403, "reason": "Forbidden"} for key in ("developer_get_protected", "developer_list_protected"))
else:
    matched = all(is_ok(checks[key], expect_protected) for key in ("reader_get_protected", "reader_list_protected"))
print(json.dumps({"phase": phase, "actor": actor, "namespace": namespace,
                  "matched": matched, "observations": checks},
                 sort_keys=True))
sys.exit(0 if matched else 23)
'''


def _kubectl(lab, namespace, *args, timeout=40, payload=None, allow_failure=False):
    return lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                       "--namespace", namespace, f"--request-timeout={timeout - 5}s", *args,
                       payload=payload, timeout=timeout, allow_failure=allow_failure)


def _apply(lab, namespace, obj):
    _kubectl(lab, namespace, "apply", "-f", "-", payload=json.dumps(obj))


def _create_namespace(lab, name):
    lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                "create", "namespace", name, timeout=25)


def _role(name, namespace, marker_name):
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": name, "namespace": namespace},
            "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [marker_name],
                       "verbs": ["get", "list"]}]}


def _role_binding(name, namespace, role_name, sa_name):
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
            "metadata": {"name": name, "namespace": namespace},
            "subjects": [{"kind": "ServiceAccount", "name": sa_name, "namespace": namespace}],
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": role_name}}


def _token_job(name, namespace, service_account, actor, phase):
    return {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name, "namespace": namespace,
             "labels": {"saf.synthetic": "true", "saf.case": "1006-008-po51"}},
            "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 60, "ttlSecondsAfterFinished": 300,
                     "template": {"metadata": {"labels": {"saf.case": "1006-008-po51", "saf.actor": actor}},
                                  "spec": {"serviceAccountName": service_account,
                                           "automountServiceAccountToken": False,
                                           "restartPolicy": "Never",
                                           "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                                                "seccompProfile": {"type": "RuntimeDefault"}},
                                           "containers": [{"name": "api-observer",
                                                           "image": "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90",
                                                           "imagePullPolicy": "IfNotPresent",
                                                           "command": ["python", "-c", API_SCRIPT, phase],
                                                           "env": [{"name": "FIXTURE_ACTOR", "value": actor},
                                                                   {"name": "FIXTURE_NAMESPACE", "value": namespace}],
                                                           "resources": {"requests": {"cpu": "5m", "memory": "16Mi"},
                                                                         "limits": {"cpu": "100m", "memory": "64Mi"}},
                                                           "securityContext": {"allowPrivilegeEscalation": False,
                                                                               "readOnlyRootFilesystem": True,
                                                                               "capabilities": {"drop": ["ALL"]}},
                                                           "volumeMounts": [{"name": "identity", "mountPath": "/var/run/fixture-token",
                                                                             "readOnly": True},
                                                                            {"name": "expectations", "mountPath": "/fixture",
                                                                             "readOnly": True}]}],
                                           "volumes": [{"name": "identity", "projected": {"sources": [
                                               {"serviceAccountToken": {"path": "token", "expirationSeconds": 600}},
                                               {"configMap": {"name": "kube-root-ca.crt", "items": [
                                                   {"key": "ca.crt", "path": "ca.crt"}]}}]}},
                                                       {"name": "expectations", "configMap": {"name": "po51-expectations",
                                                                                                  "defaultMode": 292}}]}}}}


def _wait_and_capture(lab, name, namespace):
    end = time.monotonic() + 75
    observed = None
    while time.monotonic() < end:
        job = json.loads(_kubectl(lab, namespace, "get", "job", name, "-o", "json").stdout)
        observed = job
        conds = {item.get("type"): item.get("status") for item in job.get("status", {}).get("conditions", [])}
        if conds.get("Complete") == "True" or conds.get("Failed") == "True":
            break
        time.sleep(0.5)
    else:
        lab.block(f"PO.5.1 actor Job did not finish: {name}")
    pods = json.loads(_kubectl(lab, namespace, "get", "pods", "-l", "job-name=" + name, "-o", "json").stdout)
    items = pods.get("items", [])
    if len(items) != 1:
        lab.block(f"Expected one PO.5.1 observer Pod for {name}; found {len(items)}")
    pod = items[0]
    job_uid = observed.get("metadata", {}).get("uid")
    owners = [owner for owner in pod.get("metadata", {}).get("ownerReferences", [])
              if owner.get("kind") == "Job" and owner.get("controller") is True]
    owner_reference_matches = len(owners) == 1 and owners[0].get("uid") == job_uid
    logs = _kubectl(lab, namespace, "logs", pod["metadata"]["name"]).stdout
    try:
        event = json.loads(logs.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        event = None
    status = pod.get("status", {}).get("containerStatuses", [{}])[0].get("state", {}).get("terminated", {})
    exit_code = status.get("exitCode")
    spec = pod.get("spec", {})
    projections = [source.get("serviceAccountToken", {}).get("expirationSeconds")
                   for volume in spec.get("volumes", [])
                   for source in volume.get("projected", {}).get("sources", [])
                   if "serviceAccountToken" in source]
    result = {"job": observed, "pod": pod, "job_uid": job_uid,
              "selected_pod_job_owner_reference": owners[0] if len(owners) == 1 else None,
              "owner_reference_matches": owner_reference_matches,
              "event": event, "exit_code": exit_code,
              "identity": {"service_account": spec.get("serviceAccountName"),
                           "automount_service_account_token": spec.get("automountServiceAccountToken"),
                           "projected_token_expiration_seconds": projections},
              "log": logs}
    (lab.evidence / f"po51-{name}-raw.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def _assert_resource(lab, namespace, name, marker):
    obj = json.loads(_kubectl(lab, namespace, "get", "configmap", name, "-o", "json").stdout)
    metadata = obj.get("metadata", {})
    uid = metadata.get("uid")
    if (obj.get("kind") != "ConfigMap" or obj.get("immutable") is not True
            or metadata.get("namespace") != namespace or metadata.get("name") != name
            or metadata.get("labels", {}).get("saf.synthetic") != "true" or not uid
            or obj.get("data", {}).get("marker") != marker):
        lab.block(f"PO.5.1 fixture resource did not match its immutable synthetic identity: {namespace}/{name}")
    return {"namespace": namespace, "name": name, "uid": uid, "marker": marker}


def run(lab):
    """Create a bounded same-resource baseline, narrow access, and verify allowed controls."""
    created_namespaces = []
    successful = False
    try:
        for namespace in (DEV, PROTECTED):
            _create_namespace(lab, namespace)
            created_namespaces.append(namespace)
        for namespace, sa in ((DEV, DEV_SA), (PROTECTED, READER_SA)):
            _apply(lab, namespace, {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": sa}})
        _apply(lab, DEV, {"apiVersion": "v1", "kind": "ConfigMap",
                          "metadata": {"name": DEV_CM, "labels": {"saf.synthetic": "true"}},
                          "immutable": True, "data": {"marker": DEV_MARKER}})
        _apply(lab, PROTECTED, {"apiVersion": "v1", "kind": "ConfigMap",
                                "metadata": {"name": PROTECTED_CM, "labels": {"saf.synthetic": "true"}},
                                "immutable": True, "data": {"marker": PROTECTED_MARKER}})
        dev_resource = _assert_resource(lab, DEV, DEV_CM, DEV_MARKER)
        protected_resource = _assert_resource(lab, PROTECTED, PROTECTED_CM, PROTECTED_MARKER)
        protected_identity = {key: protected_resource[key] for key in ("namespace", "name", "uid")}
        dev_expectations = {"developer_namespace": DEV, "protected_namespace": PROTECTED,
                            "developer_resource": dev_resource, "protected_resource": protected_identity}
        reader_expectations = {"developer_namespace": DEV, "protected_namespace": PROTECTED,
                               "developer_resource": {key: dev_resource[key] for key in ("namespace", "name", "uid")},
                               "protected_resource": protected_resource}
        _apply(lab, DEV, {"apiVersion": "v1", "kind": "ConfigMap",
                          "metadata": {"name": "po51-expectations", "labels": {"saf.synthetic": "true"}},
                          "immutable": True, "data": {"expectations.json": json.dumps(dev_expectations, sort_keys=True)}})
        _apply(lab, PROTECTED, {"apiVersion": "v1", "kind": "ConfigMap",
                                "metadata": {"name": "po51-expectations", "labels": {"saf.synthetic": "true"}},
                                "immutable": True, "data": {"expectations.json": json.dumps(reader_expectations, sort_keys=True)}})

        _apply(lab, DEV, _role("developer-own-markers", DEV, DEV_CM))
        _apply(lab, DEV, _role_binding("developer-own-markers", DEV, "developer-own-markers", DEV_SA))
        _apply(lab, PROTECTED, _role("approved-protected-markers", PROTECTED, PROTECTED_CM))
        _apply(lab, PROTECTED, _role_binding("approved-protected-markers", PROTECTED,
                                            "approved-protected-markers", READER_SA))
        _apply(lab, DEV, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
                          "metadata": {"name": CLUSTER_ROLE},
                          "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                                    "resourceNames": [DEV_CM, PROTECTED_CM], "verbs": ["get", "list"]}]})
        _apply(lab, DEV, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                          "metadata": {"name": CLUSTER_BINDING},
                          "subjects": [{"kind": "ServiceAccount", "name": DEV_SA, "namespace": DEV}],
                          "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": CLUSTER_ROLE}})
        _kubectl(lab, DEV, "wait", "--for=create", f"serviceaccount/{DEV_SA}", "--timeout=20s", timeout=25)
        _kubectl(lab, PROTECTED, "wait", "--for=create", f"serviceaccount/{READER_SA}", "--timeout=20s", timeout=25)

        _apply(lab, DEV, _token_job("po51-baseline-developer", DEV, DEV_SA, "developer", "baseline"))
        baseline = _wait_and_capture(lab, "po51-baseline-developer", DEV)
        base_event = baseline["event"] or {}
        baseline_rows = base_event.get("observations", {})
        baseline_marker_matches = all(
            baseline_rows.get(key, {}).get("marker") == expected["marker"]
            and baseline_rows.get(key, {}).get("uid") == expected["uid"]
            and baseline_rows.get(key, {}).get("namespace") == expected["namespace"]
            for key, expected in (("developer_get_own", dev_resource), ("developer_list_own", dev_resource),
                                  ("developer_get_protected", protected_resource),
                                  ("developer_list_protected", protected_resource)))
        baseline_uid_pair_matches = (baseline_rows.get("developer_get_own", {}).get("uid") == dev_resource["uid"]
                                     and baseline_rows.get("developer_get_protected", {}).get("uid") == protected_resource["uid"])
        baseline_ok = (baseline["exit_code"] == 0 and base_event.get("matched") is True
                       and baseline_marker_matches and baseline_uid_pair_matches
                       and baseline["owner_reference_matches"]
                       and baseline["identity"] == {"service_account": DEV_SA,
                                                    "automount_service_account_token": False,
                                                    "projected_token_expiration_seconds": [600]})
        lab.check("positive", "Temporary broad grant establishes the exact positive API baseline",
                  baseline_ok, {"actor": "developer", "identity": baseline["identity"],
                                "own_get_list": baseline_ok, "protected_get_list": baseline_ok,
                                "same_resource_uid_pair": baseline_uid_pair_matches,
                                "selected_pod_owned_by_exact_job": baseline["owner_reference_matches"]})

        _kubectl(lab, DEV, "delete", "clusterrolebinding", CLUSTER_BINDING, "--wait=true", timeout=25)
        _apply(lab, DEV, _token_job("po51-restricted-developer", DEV, DEV_SA, "developer", "restricted-developer"))
        restricted = _wait_and_capture(lab, "po51-restricted-developer", DEV)
        event = restricted["event"] or {}
        observations = event.get("observations", {})
        dev_after = _assert_resource(lab, DEV, DEV_CM, DEV_MARKER)
        protected_after = _assert_resource(lab, PROTECTED, PROTECTED_CM, PROTECTED_MARKER)
        exact_same = dev_after["uid"] == dev_resource["uid"] and protected_after["uid"] == protected_resource["uid"]
        own_rows_match = all(observations.get(key, {}).get("marker") == DEV_MARKER
                             and observations.get(key, {}).get("uid") == dev_resource["uid"]
                             for key in ("developer_get_own", "developer_list_own"))
        restricted_ok = (restricted["exit_code"] == 0 and event.get("matched") is True and exact_same
                         and own_rows_match and restricted["owner_reference_matches"]
                         and restricted["identity"] == {"service_account": DEV_SA,
                                                        "automount_service_account_token": False,
                                                        "projected_token_expiration_seconds": [600]})
        lab.check("red", "After removing only the broad binding, developer gets 403 for protected GET and LIST but retains own read",
                  restricted_ok, {"developer_protected_get_403": observations.get("developer_get_protected") == {"status": 403, "reason": "Forbidden"},
                                  "developer_protected_list_403": observations.get("developer_list_protected") == {"status": 403, "reason": "Forbidden"},
                                  "developer_own_get_list": restricted_ok, "identity": restricted["identity"],
                                  "same_resource_uid_pair": exact_same,
                                  "selected_pod_owned_by_exact_job": restricted["owner_reference_matches"]})

        _apply(lab, PROTECTED, _token_job("po51-approved-reader", PROTECTED, READER_SA, "approved-reader", "approved-reader"))
        reader = _wait_and_capture(lab, "po51-approved-reader", PROTECTED)
        reader_event = reader["event"] or {}
        final_dev = _assert_resource(lab, DEV, DEV_CM, DEV_MARKER)
        final_protected = _assert_resource(lab, PROTECTED, PROTECTED_CM, PROTECTED_MARKER)
        same_resources = (final_dev["uid"] == dev_resource["uid"] and final_protected["uid"] == protected_resource["uid"])
        reader_rows = reader_event.get("observations", {})
        reader_marker_matches = all(reader_rows.get(key, {}).get("marker") == PROTECTED_MARKER
                                    and reader_rows.get(key, {}).get("uid") == protected_resource["uid"]
                                    and reader_rows.get(key, {}).get("namespace") == PROTECTED
                                    for key in ("reader_get_protected", "reader_list_protected"))
        reader_ok = (reader["exit_code"] == 0 and reader_event.get("matched") is True and same_resources
                     and reader_marker_matches and reader["owner_reference_matches"]
                     and reader["identity"] == {"service_account": READER_SA,
                                                 "automount_service_account_token": False,
                                                 "projected_token_expiration_seconds": [600]})
        lab.check("green", "Separate approved protected reader retains exact protected GET and LIST",
                  reader_ok, {"approved_reader_get_list": reader_ok, "identity": reader["identity"],
                              "same_resource_uid_pair": same_resources,
                              "selected_pod_owned_by_exact_job": reader["owner_reference_matches"],
                              "governance_and_organization_wide_protection": "unknown"})
        successful = True
    finally:
        cleanup = {}
        for resource in ("clusterrolebinding/" + CLUSTER_BINDING, "clusterrole/" + CLUSTER_ROLE):
            result = lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                                 "delete", resource, "--ignore-not-found=true", "--wait=true", timeout=25,
                                 allow_failure=True)
            cleanup[resource.replace("/", "_") + "_deleted"] = result.returncode == 0
        for namespace in reversed(created_namespaces):
            result = lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                                 "delete", "namespace", namespace, "--wait=true", "--timeout=60s",
                                 timeout=70, allow_failure=True)
            cleanup[namespace] = result.returncode == 0
        for namespace in created_namespaces:
            result = lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                                 "get", "namespace", namespace, "--ignore-not-found", "-o", "name", timeout=20, allow_failure=True)
            cleanup[namespace + "_absent"] = result.returncode == 0 and not result.stdout.strip()
        for resource in ("clusterrolebinding/" + CLUSTER_BINDING, "clusterrole/" + CLUSTER_ROLE):
            result = lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                                 "get", resource, "--ignore-not-found", "-o", "name", timeout=20, allow_failure=True)
            cleanup[resource.replace("/", "_") + "_absent"] = result.returncode == 0 and not result.stdout.strip()
        (lab.evidence / "po51-cleanup.json").write_text(json.dumps(cleanup, indent=2, sort_keys=True) + "\n")
        if successful:
            removed = (all(cleanup.get(ns, False) and cleanup.get(ns + "_absent", False) for ns in created_namespaces)
                       and all(cleanup.get(key, False) for key in (
                           "clusterrolebinding_" + CLUSTER_BINDING + "_deleted",
                           "clusterrole_" + CLUSTER_ROLE + "_deleted",
                           "clusterrolebinding_" + CLUSTER_BINDING + "_absent",
                           "clusterrole_" + CLUSTER_ROLE + "_absent")))
            lab.check("positive", "Both case-owned namespaces and fixture resources are removed",
                      removed, cleanup)
