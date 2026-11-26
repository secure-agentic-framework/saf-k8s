"""Bounded Volcano Queue, RBAC, and two-worker CPU gang witness.

Call run(lab) after volcano_install.run(lab) in the same disposable lab. This
module does not install Volcano, alter existing cases, or contact any cluster
other than the lab object passed to run().
"""

import json
import time
from pathlib import Path


SUFFIX = "saf-0901-006-volcano"
NAMESPACE = SUFFIX
TENANT = SUFFIX + "-tenant"
QUEUE = SUFFIX + "-queue"
JOB = SUFFIX + "-gang"
PODGROUP = JOB
NORMAL_PC = SUFFIX + "-normal"
HIGH_PC = SUFFIX + "-high"
QUOTA = SUFFIX + "-quota"
PROBE = SUFFIX + "-probe"
POSITIVE_POD = SUFFIX + "-tenant-positive"
CPU = "100m"
IMAGE = (
    "docker.io/library/busybox:1.37.0@"
    "sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
PROBE_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)


PROBE_PROGRAM = r'''"""Fixed authenticated API probes; no credentials are emitted."""
import json
import ssl
import urllib.error
import urllib.request

API = "https://kubernetes.default.svc"
TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
TARGETS = json.loads(__TARGETS_JSON__)


def request(operation):
    target = TARGETS[operation]
    method = target["method"]
    path = target["path"]
    if method in ("POST", "PATCH", "DELETE") and operation != "tenant_positive_pod":
        path += ("&" if "?" in path else "?") + "dryRun=All"
    body = target.get("body")
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Authorization": "Bearer " + open(TOKEN_PATH, encoding="utf-8").read().strip(),
               "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = ("application/merge-patch+json" if method == "PATCH"
                                    else "application/json")
    req = urllib.request.Request(API + path, data=data, method=method, headers=headers)
    context = ssl.create_default_context(cafile=CA_PATH)
    try:
        with urllib.request.urlopen(req, context=context, timeout=8) as response:
            status, raw = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read()
    try:
        result = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        result = {}
    metadata = result.get("metadata", {})
    return {"operation": operation, "method": method, "status": status,
            "reason": result.get("reason"), "message": result.get("message", ""),
            "returned_name": metadata.get("name"), "returned_uid": metadata.get("uid")}


results = {name: request(name) for name in TARGETS}
print(json.dumps(results, sort_keys=True))
'''


def _cmd(lab, *args, timeout=45, allow_failure=False, payload=None):
    return lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
                       f"kind-{lab.cluster}", f"--request-timeout={timeout - 5}s", *args,
                       timeout=timeout, allow_failure=allow_failure, payload=payload)


def _json(lab, *args):
    return json.loads(_cmd(lab, *args, "-o", "json").stdout)


def _json_if_present(lab, *args):
    result = _cmd(lab, *args, "-o", "json", "--ignore-not-found", allow_failure=True)
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return json.loads(result.stdout)


def _apply(lab, obj):
    namespace = obj.get("metadata", {}).get("namespace")
    scope = ["-n", namespace] if namespace else []
    _cmd(lab, *scope, "apply", "--server-side", "-f", "-",
         payload=json.dumps(obj, sort_keys=True))


def _wait(lab, predicate, description, seconds=60):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(1)
    lab.block(f"Timed out waiting for {description}; last={last!r}")


def _ready(pod):
    return any(c.get("type") == "Ready" and c.get("status") == "True"
               for c in pod.get("status", {}).get("conditions", []))


def _owned_pods(lab, job_uid):
    pods = _json(lab, "-n", NAMESPACE, "get", "pods").get("items", [])
    return [pod for pod in pods if any(
        owner.get("apiVersion") == "batch.volcano.sh/v1alpha1"
        and owner.get("kind") == "Job" and owner.get("uid") == job_uid
        and owner.get("controller") is True
        for owner in pod.get("metadata", {}).get("ownerReferences", []))]


def _podgroup(lab, podgroup_name):
    return _json(lab, "-n", NAMESPACE, "get", "podgroups.scheduling.volcano.sh", podgroup_name)


def _view(obj, extra_fields=()):
    metadata = obj.get("metadata", {})
    result = {"uid": metadata.get("uid"), "spec": obj.get("spec")}
    for key in extra_fields:
        result[key] = obj.get(key)
    return result


def _queue(name=QUEUE, capability=CPU, deserved=CPU):
    return {
        "apiVersion": "scheduling.volcano.sh/v1beta1", "kind": "Queue",
        "metadata": {"name": name, "labels": {"saf-k8s.io/fixture": SUFFIX}},
        "spec": {"reclaimable": False,
                 "capability": {"cpu": capability}, "deserved": {"cpu": deserved}},
    }


def _pc(name, value):
    return {"apiVersion": "scheduling.k8s.io/v1", "kind": "PriorityClass",
            "metadata": {"name": name, "labels": {"saf-k8s.io/fixture": SUFFIX}},
            "value": value, "globalDefault": False, "preemptionPolicy": "Never",
            "description": "Fixed CPU-only SAF-K8S-0901-006 fixture priority"}


def _tenant_probe_pod():
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": PROBE, "namespace": NAMESPACE,
                     "labels": {"saf-k8s.io/fixture": SUFFIX}},
        "spec": {"serviceAccountName": TENANT, "automountServiceAccountToken": True,
                 "restartPolicy": "Always", "terminationGracePeriodSeconds": 1,
                 "containers": [{"name": "probe", "image": PROBE_IMAGE,
                                 "command": ["python", "-c", "import time; time.sleep(3600)"],
                                 "resources": {"requests": {"cpu": "10m"}},
                                 "volumeMounts": [{"name": "probe-source", "mountPath": "/fixture",
                                                   "readOnly": True}],
                                 "securityContext": {"allowPrivilegeEscalation": False,
                                                     "capabilities": {"drop": ["ALL"]},
                                                     "runAsNonRoot": True, "runAsUser": 65534,
                                                     "readOnlyRootFilesystem": True,
                                                     "seccompProfile": {"type": "RuntimeDefault"}}}],
                 "volumes": [{"name": "probe-source", "configMap": {"name": PROBE}}]},
    }


def _tenant_positive_pod():
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": POSITIVE_POD, "namespace": NAMESPACE,
                     "labels": {"saf-k8s.io/fixture": SUFFIX}},
        "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                 "terminationGracePeriodSeconds": 1,
                 "containers": [{"name": "positive", "image": IMAGE,
                                 "imagePullPolicy": "IfNotPresent",
                                 "command": ["/bin/sh", "-c",
                                             "sleep 300; printf '%s\\n' volcano-tenant-positive"],
                                 "resources": {"requests": {"cpu": "10m"}},
                                 "securityContext": {"allowPrivilegeEscalation": False,
                                                     "capabilities": {"drop": ["ALL"]},
                                                     "runAsNonRoot": True, "runAsUser": 65534,
                                                     "readOnlyRootFilesystem": True,
                                                     "seccompProfile": {"type": "RuntimeDefault"}}}]},
    }


def _targets(podgroup_name):
    queue_path = f"/apis/scheduling.volcano.sh/v1beta1/queues/{QUEUE}"
    queue_collection = "/apis/scheduling.volcano.sh/v1beta1/queues"
    group_path = (f"/apis/scheduling.volcano.sh/v1beta1/namespaces/{NAMESPACE}"
                  f"/podgroups/{podgroup_name}")
    group_collection = f"/apis/scheduling.volcano.sh/v1beta1/namespaces/{NAMESPACE}/podgroups"
    pc_path = f"/apis/scheduling.k8s.io/v1/priorityclasses/{HIGH_PC}"
    pc_collection = "/apis/scheduling.k8s.io/v1/priorityclasses"
    quota_path = f"/api/v1/namespaces/{NAMESPACE}/resourcequotas/{QUOTA}"
    quota_collection = f"/api/v1/namespaces/{NAMESPACE}/resourcequotas"
    probe = _tenant_positive_pod()
    return {
        "queue_create": {"method": "POST", "path": queue_collection,
                         "body": _queue(QUEUE + "-tenant-probe", "999m", "999m")},
        "queue_patch": {"method": "PATCH", "path": queue_path,
                        "body": {"spec": {"capability": {"cpu": "999m"}}}},
        "queue_delete": {"method": "DELETE", "path": queue_path},
        "podgroup_create": {"method": "POST", "path": group_collection,
                             "body": {"apiVersion": "scheduling.volcano.sh/v1beta1",
                                      "kind": "PodGroup",
                                      "metadata": {"name": podgroup_name + "-tenant-probe",
                                                    "namespace": NAMESPACE},
                                      "spec": {"minMember": 1, "queue": QUEUE}}},
        "podgroup_patch": {"method": "PATCH", "path": group_path,
                           "body": {"spec": {"minMember": 1}}},
        "podgroup_delete": {"method": "DELETE", "path": group_path},
        "priorityclass_create": {"method": "POST", "path": pc_collection,
                                  "body": _pc(HIGH_PC + "-tenant-probe", 500)},
        "priorityclass_patch": {"method": "PATCH", "path": pc_path, "body": {"value": 500}},
        "priorityclass_delete": {"method": "DELETE", "path": pc_path},
        "resourcequota_create": {"method": "POST", "path": quota_collection,
                                 "body": {"apiVersion": "v1", "kind": "ResourceQuota",
                                          "metadata": {"name": QUOTA + "-tenant-probe",
                                                        "namespace": NAMESPACE},
                                          "spec": {"hard": {"requests.cpu": "999m"}}}},
        "resourcequota_patch": {"method": "PATCH", "path": quota_path,
                                "body": {"spec": {"hard": {"requests.cpu": "999m"}}}},
        "resourcequota_delete": {"method": "DELETE", "path": quota_path},
        "tenant_positive_pod": {"method": "POST",
                                "path": f"/api/v1/namespaces/{NAMESPACE}/pods",
                                "body": probe},
    }


def _probe_program(podgroup_name):
    return PROBE_PROGRAM.replace("__TARGETS_JSON__", repr(json.dumps(_targets(podgroup_name), sort_keys=True)))


def _probe_pod(lab, pod_uid):
    pod = _json(lab, "-n", NAMESPACE, "get", "pod", PROBE)
    if pod.get("metadata", {}).get("uid") != pod_uid:
        lab.block("The tenant probe Pod UID changed before API calls")
    result = _cmd(lab, "-n", NAMESPACE, "exec", PROBE, "--", "python", "/fixture/probe.py",
                  timeout=45)
    return json.loads(result.stdout)


def _job():
    return {
        "apiVersion": "batch.volcano.sh/v1alpha1", "kind": "Job",
        "metadata": {"name": JOB, "namespace": NAMESPACE,
                     "labels": {"saf-k8s.io/fixture": SUFFIX}},
        "spec": {"schedulerName": "volcano", "queue": QUEUE, "minAvailable": 2,
                 "priorityClassName": NORMAL_PC, "maxRetry": 0,
                 "tasks": [{"name": "worker", "replicas": 2,
                            "template": {"metadata": {"labels": {"saf-k8s.io/fixture": SUFFIX}},
                                         "spec": {"restartPolicy": "Never",
                                                  "automountServiceAccountToken": False,
                                                  "terminationGracePeriodSeconds": 1,
                                                  "securityContext": {"runAsNonRoot": True,
                                                                      "runAsUser": 65534,
                                                                      "seccompProfile": {"type": "RuntimeDefault"}},
                                                  "containers": [{"name": "worker", "image": IMAGE,
                                                                  "imagePullPolicy": "IfNotPresent",
                                                                  "command": ["/bin/sh", "-c",
                                                                              "sleep 120; printf '%s\\n' volcano-gang-worker"],
                                                                  "resources": {"requests": {"cpu": CPU}},
                                                                  "securityContext": {"allowPrivilegeEscalation": False,
                                                                                      "capabilities": {"drop": ["ALL"]},
                                                                                      "readOnlyRootFilesystem": True}}]}}}]},
    }


def run(lab):
    """Run after the sibling Volcano installer has completed successfully."""
    raw = {}

    install_artifact = lab.evidence / "volcano-install.json"
    if not install_artifact.is_file():
        lab.block("The separately staged Volcano installer must run first")
    install = json.loads(install_artifact.read_text())
    if install.get("release") != "v1.16.1":
        lab.block("The installed Volcano evidence is not the pinned v1.16.1 release")

    def persist():
        (lab.evidence / "volcano-workload-raw.json").write_text(
            json.dumps(raw, indent=2, sort_keys=True) + "\n")

    # Namespace and the specific authorization fixture.
    _cmd(lab, "create", "namespace", NAMESPACE)
    _apply(lab, {"apiVersion": "v1", "kind": "Namespace",
                 "metadata": {"name": NAMESPACE, "labels": {"saf-k8s.io/fixture": SUFFIX}}})
    _apply(lab, {"apiVersion": "v1", "kind": "ServiceAccount",
                 "metadata": {"name": TENANT, "namespace": NAMESPACE},
                 "automountServiceAccountToken": True})
    _apply(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                 "metadata": {"name": TENANT, "namespace": NAMESPACE},
                 "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}]})
    _apply(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                 "metadata": {"name": TENANT, "namespace": NAMESPACE},
                 "subjects": [{"kind": "ServiceAccount", "name": TENANT, "namespace": NAMESPACE}],
                 "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                             "name": TENANT}})
    # Protected objects and a finite namespace quota for the probe plus two workers.
    _apply(lab, _queue())
    _apply(lab, _pc(NORMAL_PC, 10))
    _apply(lab, _pc(HIGH_PC, 100))
    _apply(lab, {"apiVersion": "v1", "kind": "ResourceQuota",
                 "metadata": {"name": QUOTA, "namespace": NAMESPACE,
                              "labels": {"saf-k8s.io/fixture": SUFFIX}},
                 "spec": {"hard": {"pods": "4", "requests.cpu": "300m"}}})
    queue_initial = _wait(lab, lambda: (
        obj if (obj := _json(lab, "get", "queues.scheduling.volcano.sh", QUEUE))
        and obj.get("status", {}).get("state") == "Open" else None
    ), "the case Volcano Queue to become Open", seconds=45)
    raw["queue_initial"] = queue_initial
    persist()

    # Submit the VolcanoJob while its aggregate request (200m) exceeds Queue cap (100m).
    _apply(lab, _job())
    job = _wait(lab, lambda: (
        obj if (obj := _json(lab, "-n", NAMESPACE, "get", "jobs.batch.volcano.sh", JOB))
        and obj.get("metadata", {}).get("uid") else None
    ), "the exact VolcanoJob UID", seconds=45)
    job_uid = job["metadata"]["uid"]
    def owned_groups():
        items = _json(lab, "-n", NAMESPACE, "get", "podgroups.scheduling.volcano.sh").get("items", [])
        return [obj for obj in items if any(
            owner.get("uid") == job_uid and owner.get("kind") == "Job"
            and owner.get("apiVersion") == "batch.volcano.sh/v1alpha1"
            for owner in obj.get("metadata", {}).get("ownerReferences", []))]

    group_matches = _wait(lab, lambda: (groups if len(groups := owned_groups()) == 1 else None),
                          "exactly one PodGroup owned by the VolcanoJob UID", seconds=60)
    group = group_matches[0]
    podgroup_name = group.get("metadata", {}).get("name")
    if not podgroup_name or group.get("metadata", {}).get("namespace") != NAMESPACE:
        lab.block("The exact VolcanoJob-owned PodGroup has no expected namespace/name")
    matching_owner = next(owner for owner in group.get("metadata", {}).get("ownerReferences", [])
                          if owner.get("uid") == job_uid and owner.get("kind") == "Job")
    raw["podgroup_identity"] = {"name": podgroup_name, "namespace": NAMESPACE,
                                "uid": group["metadata"]["uid"], "owner_job_uid": job_uid,
                                "owner_reference": matching_owner}
    if group.get("spec", {}).get("minMember") != 2 or group.get("spec", {}).get("queue") != QUEUE:
        lab.block("The Volcano controller-created PodGroup does not retain the exact gang/Queue request")

    # Mount/API probes are created only after observing and validating the Job-owned group name.
    _apply(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                 "metadata": {"name": PROBE, "namespace": NAMESPACE,
                              "labels": {"saf-k8s.io/fixture": SUFFIX}},
                 "data": {"probe.py": _probe_program(podgroup_name)}})
    _cmd(lab, "-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(_tenant_probe_pod()))
    _cmd(lab, "-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{PROBE}",
         "--timeout=120s", timeout=130)
    probe_pod = _json(lab, "-n", NAMESPACE, "get", "pod", PROBE)
    probe_uid = probe_pod["metadata"]["uid"]
    raw["tenant_probe"] = {"uid": probe_uid, "service_account": TENANT,
                            "role": {"verbs": ["create"], "resource": "pods"}}
    persist()

    # Observe repeated bounded under-cap states. Do not infer atomic transitions after the cap update.
    live_job = _json(lab, "-n", NAMESPACE, "get", "jobs.batch.volcano.sh", JOB)
    task = live_job.get("spec", {}).get("tasks", [{}])[0]
    containers = task.get("template", {}).get("spec", {}).get("containers", [])
    worker_request = containers[0].get("resources", {}).get("requests", {}).get("cpu") if len(containers) == 1 else None
    job_demand_ok = (task.get("replicas") == 2 and worker_request == CPU
                     and live_job.get("spec", {}).get("minAvailable") == 2)
    min_resources = group.get("spec", {}).get("minResources")
    group_minresources_ok = (min_resources is None or min_resources.get("cpu") == "200m")
    pre_capacity = []
    for _ in range(5):
        live_group = _json_if_present(lab, "-n", NAMESPACE, "get",
                                      "podgroups.scheduling.volcano.sh", podgroup_name)
        if live_group is None:
            pre_capacity.append({"podgroup_missing": True, "members": [],
                                 "bound_members": 0, "ready_members": 0})
            time.sleep(1)
            continue
        members = _owned_pods(lab, job_uid)
        row = {"podgroup": live_group,
               "members": members,
               "bound_members": sum(bool(pod.get("spec", {}).get("nodeName")) for pod in members),
               "ready_members": sum(_ready(pod) for pod in members)}
        pre_capacity.append(row)
        time.sleep(1)
    pre_capacity_ok = all(row["bound_members"] == 0 and row["ready_members"] == 0
                          and not row.get("podgroup_missing")
                          and row["podgroup"].get("metadata", {}).get("uid") == group["metadata"]["uid"]
                          and row["podgroup"].get("spec", {}).get("minMember") == 2
                          and (row["podgroup"].get("spec", {}).get("minResources") is None
                               or row["podgroup"]["spec"]["minResources"].get("cpu") == "200m")
                          for row in pre_capacity)
    pre_capacity_ok = pre_capacity_ok and job_demand_ok and group_minresources_ok
    under_queue = _json(lab, "get", "queues.scheduling.volcano.sh", QUEUE)
    queue_cap_ok = (under_queue.get("status", {}).get("state") == "Open"
                    and under_queue.get("spec", {}).get("capability", {}).get("cpu") == CPU
                    and under_queue.get("spec", {}).get("deserved", {}).get("cpu") == CPU)
    pre_capacity_ok = pre_capacity_ok and queue_cap_ok
    raw["under_capacity"] = {"queue": under_queue,
                              "job": job, "podgroup_uid": group["metadata"]["uid"],
                              "snapshots": pre_capacity, "queue_cap_verified": queue_cap_ok,
                              "all_members_unbound_not_ready": pre_capacity_ok}
    persist()
    lab.check("red", "The 200m two-member setup remains unbound while the Volcano Queue cap is 100m",
              pre_capacity_ok,
              {"group_min_member_two": job_demand_ok,
               "group_minresources_cpu_200m_when_present": group_minresources_ok,
               "live_job_two_workers_at_100m": job_demand_ok,
               "queue_open_capability_and_deserved_100m": queue_cap_ok,
               "five_bounded_observations_unbound": pre_capacity_ok})
    if not pre_capacity_ok:
        lab.block("Volcano scheduled or readied a member while the 200m group exceeded its 100m Queue cap")

    # Snapshot protected objects immediately before authenticated dry-run mutations.
    before = {
        "queue": _json(lab, "get", "queues.scheduling.volcano.sh", QUEUE),
        "podgroup": _podgroup(lab, podgroup_name),
        "priorityclass": _json(lab, "get", "priorityclass", HIGH_PC),
        "normal_priorityclass": _json(lab, "get", "priorityclass", NORMAL_PC),
        "resourcequota": _json(lab, "-n", NAMESPACE, "get", "resourcequota", QUOTA),
    }
    raw["protected_before"] = {
        "queue": _view(before["queue"]),
        "podgroup": _view(before["podgroup"]),
        "priorityclass": _view(before["priorityclass"], ("value", "globalDefault", "preemptionPolicy")),
        "resourcequota": _view(before["resourcequota"]),
    }
    persist()
    probe_result = _probe_pod(lab, probe_uid)
    raw["tenant_api_results"] = probe_result
    persist()

    after = {
        "queue": _json(lab, "get", "queues.scheduling.volcano.sh", QUEUE),
        "podgroup": _podgroup(lab, podgroup_name),
        "priorityclass": _json(lab, "get", "priorityclass", HIGH_PC),
        "resourcequota": _json(lab, "-n", NAMESPACE, "get", "resourcequota", QUOTA),
    }
    raw["protected_after"] = {
        "queue": _view(after["queue"]),
        "podgroup": _view(after["podgroup"]),
        "priorityclass": _view(after["priorityclass"], ("value", "globalDefault", "preemptionPolicy")),
        "resourcequota": _view(after["resourcequota"]),
    }
    names = {
        "queue": ("queue_create", "queue_patch", "queue_delete"),
        "podgroup": ("podgroup_create", "podgroup_patch", "podgroup_delete"),
        "priorityclass": ("priorityclass_create", "priorityclass_patch", "priorityclass_delete"),
        "resourcequota": ("resourcequota_create", "resourcequota_patch", "resourcequota_delete"),
    }
    stability = {}
    principal = f'User "system:serviceaccount:{NAMESPACE}:{TENANT}"'
    create_probe_names = {
        "queue": ("queues.scheduling.volcano.sh", QUEUE + "-tenant-probe", None),
        "podgroup": ("podgroups.scheduling.volcano.sh", podgroup_name + "-tenant-probe", NAMESPACE),
        "priorityclass": ("priorityclasses.scheduling.k8s.io", HIGH_PC + "-tenant-probe", None),
        "resourcequota": ("resourcequotas", QUOTA + "-tenant-probe", NAMESPACE),
    }
    for kind in names:
        relevant_before, relevant_after = raw["protected_before"][kind], raw["protected_after"][kind]
        stability[kind] = (relevant_before == relevant_after)
        statuses_ok = all(
            probe_result.get(name, {}).get("status") == 403
            and probe_result.get(name, {}).get("reason") == "Forbidden"
            and "cannot " in probe_result.get(name, {}).get("message", "").lower()
            and principal in probe_result.get(name, {}).get("message", "")
            for name in names[kind])
        resource, probe_name, namespace = create_probe_names[kind]
        get_args = (["-n", namespace] if namespace else []) + [
            "get", resource, probe_name, "--ignore-not-found", "-o", "name",
        ]
        absent = _cmd(lab, *get_args, allow_failure=True)
        missing = absent.returncode == 0 and not absent.stdout.strip()
        lab.check("positive", f"Tenant cannot create, patch, or delete the protected {kind} fixture",
                  statuses_ok and stability[kind] and missing,
                  {"create_patch_delete_all_forbidden": statuses_ok,
                   "protected_uid_and_spec_unchanged": stability[kind],
                   "dry_run_create_left_no_probe_object": missing})

    positive = probe_result.get("tenant_positive_pod", {})
    positive_created = positive.get("status") == 201 and positive.get("returned_name") == POSITIVE_POD
    if not positive_created:
        lab.block("The narrowly authorized tenant Pod create did not return HTTP 201")
    positive_uid = positive.get("returned_uid")
    positive_live = _wait(lab, lambda: (
        obj if (obj := _json(lab, "-n", NAMESPACE, "get", "pod", POSITIVE_POD))
        and obj.get("metadata", {}).get("uid") == positive_uid and _ready(obj) else None
    ), "the exact tenant-created positive Pod to become Ready", seconds=60)
    raw["tenant_positive_pod"] = positive_live
    persist()
    lab.check("positive", "Tenant can create and run one fixed low-CPU Pod under its narrow pods:create Role",
              positive_created and _ready(positive_live),
              {"tenant_create_http_201": positive_created,
               "exact_created_pod_uid_ready": bool(positive_uid) and _ready(positive_live)})

    # Remove the temporary tenant-created Pod before opening Queue capacity.
    _cmd(lab, "-n", NAMESPACE, "delete", "pod", POSITIVE_POD, "--wait=true", "--timeout=30s", timeout=35)
    def positive_pod_retired():
        items = _json(lab, "-n", NAMESPACE, "get", "pods").get("items", [])
        return {"exact_positive_uid_absent": not any(
            item.get("metadata", {}).get("uid") == positive_uid for item in items)}

    def positive_pod_retired_when_true():
        state = positive_pod_retired()
        return state if state["exact_positive_uid_absent"] else None

    positive_cleanup = _wait(lab, positive_pod_retired_when_true,
                             "the exact tenant positive Pod UID to be removed", seconds=30)
    raw["tenant_positive_cleanup"] = positive_cleanup
    persist()
    lab.check("positive", "The tenant-created comparator Pod UID is retired before the group capacity change",
              positive_cleanup["exact_positive_uid_absent"], positive_cleanup)

    # Raise both declared capacity and deserved amount through the platform identity.
    _cmd(lab, "patch", "queue", QUEUE, "--type=merge",
         "-p", json.dumps({"spec": {"capability": {"cpu": "200m"},
                             "deserved": {"cpu": "200m"}}}))
    final = _wait(lab, lambda: (
        (lambda group_now, members: {"podgroup": group_now, "members": members}
         if group_now.get("metadata", {}).get("uid") == group["metadata"]["uid"]
         and group_now.get("status", {}).get("running") == 2
         and len(members) == 2
         and all(pod.get("spec", {}).get("nodeName") and _ready(pod) for pod in members)
         else None)(_podgroup(lab, podgroup_name), _owned_pods(lab, job_uid))
    ), "both exact Volcano gang members to be scheduled and Ready after Queue capacity increases",
        seconds=90)
    final_queue = _json(lab, "get", "queues.scheduling.volcano.sh", QUEUE)
    final_quota = _json(lab, "-n", NAMESPACE, "get", "resourcequota", QUOTA)
    final_ok = (final["podgroup"].get("spec", {}).get("minMember") == 2
                and final["podgroup"].get("spec", {}).get("queue") == QUEUE
                and final["podgroup"].get("status", {}).get("running") == 2
                and len(final["members"]) == 2
                and all(pod.get("spec", {}).get("schedulerName") == "volcano"
                        and pod.get("spec", {}).get("nodeName") and _ready(pod)
                        for pod in final["members"])
                and final_queue.get("status", {}).get("allocated", {}).get("cpu") == "200m"
                and final_quota.get("status", {}).get("hard", {}).get("requests.cpu") == "300m")
    raw["after_capacity"] = {"queue": final_queue, "resourcequota": final_quota,
                             "job": _json(lab, "-n", NAMESPACE, "get", "jobs.batch.volcano.sh", JOB),
                             "podgroup": final["podgroup"], "members": final["members"],
                             "final_state_valid": final_ok}
    persist()
    lab.check("green", "Both CPU-only Volcano group members become bound and Ready after capacity is raised to 200m",
              final_ok,
              {"two_job_owned_members": len(final["members"]) == 2,
               "podgroup_running_two": final["podgroup"].get("status", {}).get("running") == 2,
               "both_bound_and_ready": all(pod.get("spec", {}).get("nodeName") and _ready(pod)
                                            for pod in final["members"]),
               "queue_allocated_200m": final_queue.get("status", {}).get("allocated", {}).get("cpu") == "200m",
               "namespace_cpu_quota_300m": final_quota.get("status", {}).get("hard", {}).get("requests.cpu") == "300m"})

    # Delete by fixture-owned identities and wait for controller-owned children to disappear.
    _cmd(lab, "-n", NAMESPACE, "delete", "jobs.batch.volcano.sh", JOB,
         "--cascade=foreground", "--wait=true", "--timeout=45s", timeout=50)
    def children_retired():
        jobs = _json(lab, "-n", NAMESPACE, "get", "jobs.batch.volcano.sh").get("items", [])
        groups = _json(lab, "-n", NAMESPACE, "get", "podgroups.scheduling.volcano.sh").get("items", [])
        pods = _json(lab, "-n", NAMESPACE, "get", "pods").get("items", [])
        return {"job_uid_absent": not any(x.get("metadata", {}).get("uid") == job_uid for x in jobs),
                "podgroup_uid_absent": not any(x.get("metadata", {}).get("uid") == group["metadata"]["uid"]
                                                for x in groups),
                "owned_pods_absent": not any(any(owner.get("uid") == job_uid and owner.get("kind") == "Job"
                                                  for owner in x.get("metadata", {}).get("ownerReferences", []))
                                              for x in pods)}
    def retired_when_all():
        status = children_retired()
        return status if all(status.values()) else None

    retired = _wait(lab, retired_when_all,
                    "the exact VolcanoJob, PodGroup, and member Pods to be removed", seconds=50)
    raw["workload_cleanup"] = {"job_uid": job_uid, "podgroup_uid": group["metadata"]["uid"], **retired}
    persist()
    lab.check("positive", "Foreground cleanup removes the exact VolcanoJob, PodGroup and member Pods",
              all(retired.values()), retired)

    _cmd(lab, "delete", "queue", QUEUE, "--wait=true", "--timeout=30s", timeout=35)
    _cmd(lab, "delete", "priorityclass", NORMAL_PC, HIGH_PC, "--wait=true", "--timeout=30s", timeout=35)
    _cmd(lab, "delete", "namespace", NAMESPACE, "--wait=true", "--timeout=45s", timeout=50)
    def case_objects_retired():
        queues = _json(lab, "get", "queues.scheduling.volcano.sh").get("items", [])
        classes = _json(lab, "get", "priorityclasses.scheduling.k8s.io").get("items", [])
        namespaces = _json(lab, "get", "namespaces").get("items", [])
        class_uids = {before["priorityclass"].get("metadata", {}).get("uid"),
                      before["normal_priorityclass"].get("metadata", {}).get("uid")}
        return {"queue_uid_absent": not any(x.get("metadata", {}).get("uid") == before["queue"].get("metadata", {}).get("uid")
                                             for x in queues),
                "priorityclass_uids_absent": not any(x.get("metadata", {}).get("uid") in class_uids
                                                      for x in classes),
                "namespace_absent": not any(x.get("metadata", {}).get("name") == NAMESPACE for x in namespaces)}
    # Namespace deletion also retires its quota, probe identity, Role, and ConfigMap.
    def case_objects_retired_when_true():
        state = case_objects_retired()
        return state if all(state.values()) else None

    cleanup = _wait(lab, case_objects_retired_when_true,
                    "the case Queue, PriorityClasses and namespace to be removed", seconds=50)
    raw["case_cleanup"] = cleanup
    persist()
    lab.check("positive", "The case Queue, PriorityClasses and namespace are removed",
              all(cleanup.values()), cleanup)
