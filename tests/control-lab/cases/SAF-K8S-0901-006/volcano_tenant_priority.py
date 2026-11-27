"""Bounded tenant priority selection policy for case-owned VolcanoJobs."""
import json
import time


SUFFIX = "saf-0901-006-vjob-priority"
NAMESPACE = SUFFIX
TENANT = SUFFIX + "-tenant"
QUEUE = SUFFIX + "-queue"
POLICY = SUFFIX + "-priority-policy"
BINDING = SUFFIX + "-priority-binding"
NORMAL_PC = SUFFIX + "-normal"
RESERVED_PC = SUFFIX + "-reserved"
PROBE = SUFFIX + "-probe"
POSITIVE_JOB = SUFFIX + "-normal-job"
DENIED_JOB = SUFFIX + "-reserved-job"
DENIED_TASK_JOB = SUFFIX + "-task-override-job"
NAMESPACE_LABEL = "saf-k8s.example/fixture"
NAMESPACE_VALUE = SUFFIX
JOB_IMAGE = (
    "docker.io/library/busybox:1.37.0@"
    "sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
PROBE_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)

PROBE_PROGRAM = r'''"""Fixed tenant-authenticated VolcanoJob create requests."""
import json,ssl,urllib.error,urllib.request
API="https://kubernetes.default.svc"
TOKEN="/var/run/secrets/kubernetes.io/serviceaccount/token"
CA="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
JOBS=json.loads(__JOBS_JSON__)
def post(name,obj):
    url=API+"/apis/batch.volcano.sh/v1alpha1/namespaces/"+obj["metadata"]["namespace"]+"/jobs"
    headers={"Authorization":"Bearer "+open(TOKEN,encoding="utf-8").read().strip(),
             "Accept":"application/json","Content-Type":"application/json"}
    req=urllib.request.Request(url,data=json.dumps(obj).encode(),headers=headers,method="POST")
    try:
        with urllib.request.urlopen(req,context=ssl.create_default_context(cafile=CA),timeout=8) as r:
            status,raw=r.status,r.read()
    except urllib.error.HTTPError as e:
        status,raw=e.code,e.read()
    try: result=json.loads(raw)
    except (ValueError,UnicodeDecodeError): result={}
    meta=result.get("metadata",{})
    return {"status":status,"reason":result.get("reason"),"message":result.get("message", ""),
            "name":meta.get("name"),"uid":meta.get("uid")}
print(json.dumps({name:post(name,obj) for name,obj in JOBS.items()},sort_keys=True))
'''


def _cmd(lab, *args, timeout=45, allow_failure=False, payload=None):
    return lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
        f"kind-{lab.cluster}", f"--request-timeout={timeout - 5}s", *args,
        timeout=timeout, allow_failure=allow_failure, payload=payload)


def _json(lab, *args):
    return json.loads(_cmd(lab, *args, "-o", "json").stdout)


def _apply(lab, obj):
    _cmd(lab, "-n", NAMESPACE, "apply", "--server-side", "-f", "-",
         payload=json.dumps(obj, sort_keys=True))


def _priority_class(name, value):
    return {"apiVersion": "scheduling.k8s.io/v1", "kind": "PriorityClass",
        "metadata": {"name": name, "labels": {NAMESPACE_LABEL: NAMESPACE_VALUE}},
        "value": value, "globalDefault": False, "preemptionPolicy": "Never",
        "description": "Fixed inert Volcano tenant priority policy fixture"}


def _job(name, priority_class, task_priority=None):
    pod_spec = {"restartPolicy": "Never", "automountServiceAccountToken": False,
        "terminationGracePeriodSeconds": 1,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
            "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "worker", "image": JOB_IMAGE, "imagePullPolicy": "IfNotPresent",
            "command": ["/bin/sh", "-c", "sleep 30; printf '%s\\n' bounded-priority-fixture"],
            "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}},
            "securityContext": {"allowPrivilegeEscalation": False,
                "capabilities": {"drop": ["ALL"]}, "readOnlyRootFilesystem": True}}]}
    if task_priority is not None:
        pod_spec["priorityClassName"] = task_priority
    return {"apiVersion": "batch.volcano.sh/v1alpha1", "kind": "Job",
        "metadata": {"name": name, "namespace": NAMESPACE,
            "labels": {NAMESPACE_LABEL: NAMESPACE_VALUE}},
        "spec": {"schedulerName": "volcano", "queue": QUEUE, "minAvailable": 1,
            "priorityClassName": priority_class, "maxRetry": 0,
            "tasks": [{"name": "worker", "replicas": 1,
                "template": {"metadata": {"labels": {NAMESPACE_LABEL: NAMESPACE_VALUE}},
                    "spec": pod_spec}}]}}


def _pod_ready(pod):
    return any(c.get("type") == "Ready" and c.get("status") == "True"
               for c in pod.get("status", {}).get("conditions", []))


def _wait_positive(lab, job_uid, seconds=60):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        job = _json(lab, "-n", NAMESPACE, "get", "jobs.batch.volcano.sh", POSITIVE_JOB)
        pods = _json(lab, "-n", NAMESPACE, "get", "pods").get("items", [])
        owned = [p for p in pods if any(o.get("kind") == "Job" and
            o.get("apiVersion") == "batch.volcano.sh/v1alpha1" and
            o.get("uid") == job_uid and o.get("controller") is True
            for o in p.get("metadata", {}).get("ownerReferences", []))]
        ready = [p for p in owned if _pod_ready(p) and p.get("spec", {}).get("nodeName")
                 and p.get("spec", {}).get("schedulerName") == "volcano"]
        if len(ready) == 1:
            job_meta = job.get("metadata", {})
            job_uid = job_meta.get("uid")
            groups = _json(lab, "-n", NAMESPACE,
                "get", "podgroups.scheduling.volcano.sh").get("items", [])
            owned_groups = [group for group in groups if any(
                owner.get("apiVersion") == "batch.volcano.sh/v1alpha1"
                and owner.get("kind") == "Job" and owner.get("uid") == job_uid
                and owner.get("controller") is True
                for owner in group.get("metadata", {}).get("ownerReferences", []))]
            if len(owned_groups) != 1:
                lab.block(f"Expected exactly one Volcano PodGroup owned by VolcanoJob UID {job_uid}; found {len(owned_groups)}")
            pg = owned_groups[0]
            expected_name = f"{job_meta.get('name')}-{job_uid}"
            if pg.get("metadata", {}).get("name") != expected_name:
                lab.block(f"Owner-matched Volcano PodGroup name did not match pinned owner-qualified form {expected_name}")
            return job, ready[0], pg
        time.sleep(1)
    lab.block("Tenant VolcanoJob did not reach one exact Ready owned worker within 60 seconds")


def _probe_program(jobs):
    return PROBE_PROGRAM.replace("__JOBS_JSON__", repr(json.dumps(jobs, sort_keys=True)))


def _create_probe(lab, code):
    _apply(lab, {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": PROBE,
        "namespace": NAMESPACE, "labels": {NAMESPACE_LABEL: NAMESPACE_VALUE}},
        "immutable": True, "data": {"probe.py": code}})
    _apply(lab, {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": PROBE,
        "namespace": NAMESPACE, "labels": {NAMESPACE_LABEL: NAMESPACE_VALUE}},
        "spec": {"serviceAccountName": TENANT, "automountServiceAccountToken": True,
            "restartPolicy": "Never", "terminationGracePeriodSeconds": 1,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "probe", "image": PROBE_IMAGE,
                "imagePullPolicy": "IfNotPresent", "command": ["python", "-c", "import time; time.sleep(3600)"],
                "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                              "limits": {"cpu": "100m", "memory": "64Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}]}],
            "volumes": [{"name": "fixture", "configMap": {"name": PROBE}}]}})


def run(lab):
    # Namespace-scoped tenant Role allows only creation of the owned VolcanoJob CRD.
    _cmd(lab, "create", "namespace", NAMESPACE)
    _cmd(lab, "label", "namespace", NAMESPACE, f"{NAMESPACE_LABEL}={NAMESPACE_VALUE}")
    _apply(lab, {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {
        "name": TENANT, "namespace": NAMESPACE, "labels": {NAMESPACE_LABEL: NAMESPACE_VALUE}},
        "automountServiceAccountToken": True})
    _apply(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {
        "name": TENANT, "namespace": NAMESPACE, "labels": {NAMESPACE_LABEL: NAMESPACE_VALUE}},
        "rules": [{"apiGroups": ["batch.volcano.sh"], "resources": ["jobs"], "verbs": ["create"]}]})
    _apply(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {
        "name": TENANT, "namespace": NAMESPACE, "labels": {NAMESPACE_LABEL: NAMESPACE_VALUE}},
        "subjects": [{"kind": "ServiceAccount", "name": TENANT, "namespace": NAMESPACE}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": TENANT}})
    _apply(lab, {"apiVersion": "scheduling.volcano.sh/v1beta1", "kind": "Queue",
        "metadata": {"name": QUEUE, "labels": {NAMESPACE_LABEL: NAMESPACE_VALUE}},
        "spec": {"reclaimable": False, "capability": {"cpu": "100m"}, "deserved": {"cpu": "100m"}}})
    _cmd(lab, "create", "-f", "-", payload=json.dumps(_priority_class(NORMAL_PC, 10)))
    _cmd(lab, "create", "-f", "-", payload=json.dumps(_priority_class(RESERVED_PC, 500)))
    policy = {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY, "labels": {NAMESPACE_LABEL: NAMESPACE_VALUE}},
        "spec": {"failurePolicy": "Fail",
            "matchConstraints": {"matchPolicy": "Equivalent",
                "namespaceSelector": {"matchLabels": {NAMESPACE_LABEL: NAMESPACE_VALUE}},
                "resourceRules": [{"apiGroups": ["batch.volcano.sh"], "apiVersions": ["v1alpha1"],
                    "operations": ["CREATE", "UPDATE"], "resources": ["jobs"], "scope": "Namespaced"}]},
            "validations": [{"expression": "has(object.spec.priorityClassName) && object.spec.priorityClassName == '" + NORMAL_PC +
                "' && object.spec.tasks.all(t, !has(t.template.spec.priorityClassName) || t.template.spec.priorityClassName == '' || t.template.spec.priorityClassName == '" + NORMAL_PC +
                "')", "message": "Only the approved normal VolcanoJob priority is permitted for this tenant."}]}}
    binding = {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": BINDING, "labels": {NAMESPACE_LABEL: NAMESPACE_VALUE}},
        "spec": {"policyName": POLICY, "validationActions": ["Deny"]}}
    _cmd(lab, "create", "-f", "-", payload=json.dumps(policy))
    _cmd(lab, "create", "-f", "-", payload=json.dumps(binding))
    jobs = {"approved": _job(POSITIVE_JOB, NORMAL_PC),
            "reserved_job_field": _job(DENIED_JOB, RESERVED_PC),
            "reserved_task_override": _job(DENIED_TASK_JOB, NORMAL_PC, RESERVED_PC)}
    _create_probe(lab, _probe_program(jobs))
    _cmd(lab, "-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{PROBE}", "--timeout=60s", timeout=65)
    probe_output = _cmd(lab, "-n", NAMESPACE, "exec", PROBE, "--", "python", "/fixture/probe.py", timeout=30).stdout
    try:
        api_results = json.loads(probe_output)
    except json.JSONDecodeError:
        lab.block("Tenant priority probe did not return its bounded JSON record")
    positive = api_results.get("approved", {})
    if positive.get("status") != 201 or not positive.get("uid"):
        lab.block("The approved normal-priority VolcanoJob was not created by the tenant identity")
    positive_uid = positive["uid"]
    positive_job, positive_pod, positive_podgroup = _wait_positive(lab, positive_uid)
    positive_ok = (positive_job.get("metadata", {}).get("uid") == positive_uid
        and positive_job.get("spec", {}).get("priorityClassName") == NORMAL_PC
        and positive_job.get("spec", {}).get("queue") == QUEUE
        and positive_pod.get("metadata", {}).get("labels", {}).get(NAMESPACE_LABEL) == NAMESPACE_VALUE
        and positive_pod.get("spec", {}).get("priorityClassName") == NORMAL_PC
        and positive_podgroup.get("metadata", {}).get("name") == f"{POSITIVE_JOB}-{positive_uid}"
        and any(o.get("kind") == "Job" and o.get("uid") == positive_uid
                and o.get("controller") is True
                for o in positive_podgroup.get("metadata", {}).get("ownerReferences", []))
        and positive_podgroup.get("spec", {}).get("queue") == QUEUE)
    lab.check("positive", "Tenant creates an approved low-priority VolcanoJob that reaches one Ready owned worker",
        positive_ok, {"tenant_create_status_201": positive.get("status") == 201,
            "approved_priority_observed": positive_job.get("spec", {}).get("priorityClassName") == NORMAL_PC,
            "one_ready_volcano_scheduled_owned_worker": positive_ok})

    denied = api_results.get("reserved_job_field", {})
    denied_task = api_results.get("reserved_task_override", {})
    live_positive = _json(lab, "-n", NAMESPACE, "get", "jobs.batch.volcano.sh", POSITIVE_JOB)
    absent_denied = _cmd(lab, "-n", NAMESPACE, "get", "jobs.batch.volcano.sh", DENIED_JOB,
        "-o", "name", "--ignore-not-found").stdout.strip() == ""
    absent_task_denied = _cmd(lab, "-n", NAMESPACE, "get", "jobs.batch.volcano.sh", DENIED_TASK_JOB,
        "-o", "name", "--ignore-not-found").stdout.strip() == ""
    # With no custom reason, admission returns Invalid (HTTP 422).
    policy_denials = [
        response.get("status") == 422 and response.get("reason") == "Invalid"
        and POLICY in response.get("message", "") and BINDING in response.get("message", "")
        and "Only the approved normal" in response.get("message", "")
        for response in (denied, denied_task)
    ]
    denial_ok = (all(policy_denials) and absent_denied and absent_task_denied
        and live_positive.get("metadata", {}).get("uid") == positive["uid"])
    lab.check("green", "Declarative admission denies reserved job and task priority selection without persisting either Job",
        denial_ok, {"reserved_job_selection_denied": policy_denials[0],
            "reserved_task_override_denied": policy_denials[1],
            "both_denied_jobs_absent": absent_denied and absent_task_denied,
            "approved_job_uid_persists": live_positive.get("metadata", {}).get("uid") == positive["uid"]})
    raw = {"scope": "one tenant identity, one approved normal VolcanoJob, two denied reserved-priority requests, one exact namespace-scoped ValidatingAdmissionPolicy",
        "api_results": api_results, "policy": policy, "binding": binding,
        "positive_job": positive_job, "positive_ready_pod": positive_pod,
        "positive_podgroup": positive_podgroup, "positive_job_after_denials": live_positive,
        "denied_job_absence": absent_denied, "denied_task_job_absence": absent_task_denied,
        "observed": {"normal_job_admitted_and_ready": positive_ok, "reserved_requests_denied_and_absent": denial_ok},
        "reserved_priorityclass_preemption_policy": "Never",
        "no_high_priority_job_or_extra_replicas_created": True}
    (lab.evidence / "volcano-tenant-priority-raw.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    # Exact names and ownership label bound cleanup to this independent fixture.
    _cmd(lab, "-n", NAMESPACE, "delete", "pod", PROBE, "--wait=true", timeout=30)
    _cmd(lab, "-n", NAMESPACE, "delete", "jobs.batch.volcano.sh", POSITIVE_JOB,
         "--cascade=foreground", "--wait=true", timeout=45)
    _cmd(lab, "delete", "validatingadmissionpolicybinding", BINDING, timeout=30)
    _cmd(lab, "delete", "validatingadmissionpolicy", POLICY, timeout=30)
    _cmd(lab, "delete", "priorityclass", NORMAL_PC, RESERVED_PC, timeout=30)
    _cmd(lab, "delete", "queue.scheduling.volcano.sh", QUEUE, timeout=30)
    _cmd(lab, "delete", "namespace", NAMESPACE, "--wait=true", timeout=45)
    return raw
