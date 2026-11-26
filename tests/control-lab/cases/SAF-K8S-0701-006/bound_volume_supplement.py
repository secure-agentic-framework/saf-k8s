"""Add a mounted marker lifecycle behind the unchanged 0701-006 API gate."""
import json
import time

from fixtures import container, pod

NS = "saf-test"
PV = "synthetic-retained-volume"
PVC = "saf-retained-volume-claim"
LEDGER = "saf-retained-volume-approval"
SEED = "saf-retained-volume-seed"
JOB = "saf-approved-marker-removal"
SC = "saf-dual-retain"
MARKER = "saf-0701-006-synthetic-marker"
MARKER_CONTENT = "saf-0701-006 inert retained fixture data"
PROVISIONER = "rancher.io/local-path"
ADMISSION = "admissionregistration.k8s.io/v1"
RBAC_GROUP = "rbac.authorization.k8s.io"
RBAC = f"{RBAC_GROUP}/v1"
IMAGE = (
    "docker.io/library/busybox:1.37.0@sha256:"
    "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
)
WIPE_COMMAND = (
    "test -f /fixture/marker && rm -- /fixture/marker && "
    "test ! -e /fixture/marker && printf 'marker-removed\\n'"
)
VOTE_POLICY = "saf-0701-006-bound-vote"
DELETE_POLICY = "saf-0701-006-bound-delete"
WIPE_POLICY = "saf-0701-006-bound-wipe"
VOTE_ERROR = "each reviewer may approve only its own field"
DELETE_ERROR = "two independent approvals are required for this retained volume"
WIPE_ERROR = "the exact marker-removal job requires two independent approvals"


def spec(api, kind, name, **fields):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields}


def get(lab, resource, name):
    result = lab.kubectl("get", resource, name, "--ignore-not-found", "-o", "json")
    return json.loads(result.stdout) if result.stdout.strip() else None


def wait_phase(lab, resource, name, expected, seconds=90):
    deadline = time.monotonic() + seconds
    while True:
        item = get(lab, resource, name)
        phase = item.get("status", {}).get("phase") if item else "Absent"
        if phase == expected:
            return item
        if time.monotonic() >= deadline:
            lab.block(f"{resource}/{name} was {phase}, expected {expected}")
        time.sleep(0.5)


def marker_at_node(lab, path):
    result = lab.command(
        "docker", "exec", f"{lab.cluster}-control-plane", "sh", "-c",
        'if test -f "$1/marker"; then cat "$1/marker"; '
        'elif test -e "$1"; then printf "DIRECTORY_ONLY"; '
        'else printf "ABSENT"; fi', "saf-owned-volume-probe", path,
    )
    return result.stdout.strip()


def install(lab, name, resource, group, operation, expression, message, match, *, param=None):
    policy = {
        "failurePolicy": "Fail",
        "matchConstraints": {"resourceRules": [{
            "apiGroups": [group], "apiVersions": ["v1"],
            "operations": [operation], "resources": [resource],
        }]},
        "matchConditions": [{"name": "exact-owned-fixture", "expression": match}],
        "validations": [{"expression": expression, "message": message, "reason": "Forbidden"}],
    }
    binding = {"policyName": name, "validationActions": ["Deny"]}
    if param:
        policy["paramKind"] = {"apiVersion": "v1", "kind": "ConfigMap"}
        binding["paramRef"] = {"name": param, "namespace": NS, "parameterNotFoundAction": "Deny"}
    lab.create(spec(ADMISSION, "ValidatingAdmissionPolicy", name, spec=policy))
    lab.create(spec(ADMISSION, "ValidatingAdmissionPolicyBinding", name, spec=binding))


def expected_job_expression(user, target_uid):
    parts = [
        f"request.userInfo.username == '{user}'",
        f"object.metadata.name == '{JOB}'",
        "params != null",
        f"params.data['volumeUid'] == '{target_uid}'",
        "params.data['security'] == 'approved'",
        "params.data['dataOwner'] == 'approved'",
        "object.spec.backoffLimit == 0",
        "object.spec.activeDeadlineSeconds == 30",
        "object.spec.ttlSecondsAfterFinished == 300",
        "object.spec.template.spec.restartPolicy == 'Never'",
        "object.spec.template.spec.serviceAccountName == 'fixture-executor'",
        "object.spec.template.spec.automountServiceAccountToken == false",
        "object.spec.template.spec.securityContext.runAsNonRoot == true",
        "object.spec.template.spec.securityContext.runAsUser == 65534",
        "object.spec.template.spec.securityContext.seccompProfile.type == 'RuntimeDefault'",
        "object.spec.template.spec.containers.size() == 1",
        f"object.spec.template.spec.containers[0].image == '{IMAGE}'",
        "object.spec.template.spec.containers[0].command.size() == 3",
        "object.spec.template.spec.containers[0].command[0] == 'sh'",
        "object.spec.template.spec.containers[0].command[1] == '-ec'",
        f"object.spec.template.spec.containers[0].command[2] == {json.dumps(WIPE_COMMAND)}",
        "object.spec.template.spec.containers[0].volumeMounts.size() == 1",
        "object.spec.template.spec.containers[0].volumeMounts[0].name == 'retained-fixture'",
        "object.spec.template.spec.containers[0].volumeMounts[0].mountPath == '/fixture'",
        "(!has(object.spec.template.spec.containers[0].volumeMounts[0].readOnly) || object.spec.template.spec.containers[0].volumeMounts[0].readOnly != true)",
        "(!has(object.spec.template.spec.containers[0].volumeMounts[0].subPath) || object.spec.template.spec.containers[0].volumeMounts[0].subPath == '')",
        "(!has(object.spec.template.spec.containers[0].args) || object.spec.template.spec.containers[0].args.size() == 0)",
        "object.spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation == false",
        "object.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem == true",
        "object.spec.template.spec.containers[0].securityContext.runAsNonRoot == true",
        "object.spec.template.spec.containers[0].securityContext.runAsUser == 65534",
        "object.spec.template.spec.containers[0].securityContext.capabilities.drop == ['ALL']",
        "(!has(object.spec.template.spec.containers[0].securityContext.capabilities.add) || object.spec.template.spec.containers[0].securityContext.capabilities.add.size() == 0)",
        "quantity(string(object.spec.template.spec.containers[0].resources.requests['cpu'])) == quantity('5m')",
        "quantity(string(object.spec.template.spec.containers[0].resources.requests['memory'])) == quantity('8Mi')",
        "quantity(string(object.spec.template.spec.containers[0].resources.limits['cpu'])) == quantity('50m')",
        "quantity(string(object.spec.template.spec.containers[0].resources.limits['memory'])) == quantity('32Mi')",
        "object.spec.template.spec.volumes.size() == 1",
        "object.spec.template.spec.volumes[0].name == 'retained-fixture'",
        f"object.spec.template.spec.volumes[0].persistentVolumeClaim.claimName == '{PVC}'",
        "(!has(object.spec.template.spec.volumes[0].persistentVolumeClaim.readOnly) || object.spec.template.spec.volumes[0].persistentVolumeClaim.readOnly != true)",
        "(!has(object.spec.template.spec.hostNetwork) || object.spec.template.spec.hostNetwork != true)",
        "(!has(object.spec.template.spec.hostPID) || object.spec.template.spec.hostPID != true)",
        "(!has(object.spec.template.spec.initContainers) || object.spec.template.spec.initContainers.size() == 0)",
    ]
    return " && ".join(parts)


def run_supplement(lab):
    standard = get(lab, "storageclass", "standard")
    if not standard or standard.get("provisioner") != PROVISIONER:
        lab.block("The bundled kind local-path provisioner is required for this owned fixture")
    lab.create({
        "apiVersion": "storage.k8s.io/v1", "kind": "StorageClass",
        "metadata": {"name": SC}, "provisioner": PROVISIONER,
        "volumeBindingMode": "WaitForFirstConsumer", "reclaimPolicy": "Retain",
    })
    claim = spec("v1", "PersistentVolumeClaim", PVC, spec={
        "accessModes": ["ReadWriteOnce"], "storageClassName": SC,
        "resources": {"requests": {"storage": "1Mi"}},
    })
    lab.create(claim)
    seed = pod(SEED, [container(
        "write-one-marker", command=["sh", "-ec", f"printf '%s\\n' '{MARKER_CONTENT}' > /fixture/marker"],
        volumeMounts=[{"name": "retained-fixture", "mountPath": "/fixture"}],
    )], automountServiceAccountToken=False, volumes=[{
        "name": "retained-fixture", "persistentVolumeClaim": {"claimName": PVC},
    }])
    lab.create(seed)
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{SEED}",
                "--timeout=100s", timeout=110)
    claim_obj = wait_phase(lab, "pvc", PVC, "Bound")
    pv_obj = wait_phase(lab, "pv", claim_obj["spec"]["volumeName"], "Bound")
    pv_name = pv_obj["metadata"]["name"]
    target_uid = pv_obj["metadata"]["uid"]
    path = pv_obj.get("spec", {}).get("hostPath", {}).get("path")
    expected_path = f"/var/local-path-provisioner/{pv_name}_{NS}_{PVC}"
    seed_obj = get(lab, "pod", SEED)
    exact_owner = (pv_obj["spec"].get("claimRef", {}).get("uid") == claim_obj["metadata"]["uid"]
                   and claim_obj["spec"].get("volumeName") == pv_name
                   and seed_obj["spec"].get("nodeName") == f"{lab.cluster}-control-plane"
                   and path == expected_path
                   and pv_obj["spec"].get("persistentVolumeReclaimPolicy") == "Retain")
    if not exact_owner:
        lab.block("Bound PVC, PV UID, node, and local-path provisioner directory were not the exact owned fixture")
    marker = marker_at_node(lab, path)
    lab.check("positive", "A case-owned Retain PV/PVC binds and contains one inert marker",
              exact_owner and marker == MARKER_CONTENT,
              {"pv_pvc_uid_linked": exact_owner, "marker_present": marker == MARKER_CONTENT,
               "reclaim_policy": pv_obj["spec"].get("persistentVolumeReclaimPolicy")})
    lab.kubectl("delete", "pod", SEED, "--wait=true", "--timeout=30s")

    lab.create(spec("v1", "ConfigMap", LEDGER, data={
        "volumeUid": target_uid, "security": "pending", "dataOwner": "pending",
    }))
    # The first published run has already created these ServiceAccounts and Pods.
    # Reusing them preserves independent real API identities and the mounted probe.
    grant_vote = {
        "apiGroups": [""], "resources": ["configmaps"], "resourceNames": [LEDGER],
        "verbs": ["get", "patch"],
    }
    lab.create(spec(RBAC, "Role", "saf-bound-volume-vote", rules=[grant_vote]))
    lab.create(spec(RBAC, "RoleBinding", "saf-bound-volume-vote",
                    roleRef={"apiGroup": RBAC_GROUP, "kind": "Role", "name": "saf-bound-volume-vote"},
                    subjects=[{"kind": "ServiceAccount", "name": actor, "namespace": NS}
                              for actor in ("security-reviewer", "data-reviewer")]))
    lab.create(spec(RBAC, "ClusterRole", "saf-bound-volume-pv-executor", rules=[{
        "apiGroups": [""], "resources": ["persistentvolumes"], "resourceNames": [pv_name],
        "verbs": ["get", "delete"],
    }]))
    lab.create(spec(RBAC, "ClusterRoleBinding", "saf-bound-volume-pv-executor",
                    roleRef={"apiGroup": RBAC_GROUP, "kind": "ClusterRole", "name": "saf-bound-volume-pv-executor"},
                    subjects=[{"kind": "ServiceAccount", "name": "fixture-executor", "namespace": NS}]))
    lab.create(spec(RBAC, "Role", "saf-bound-volume-workflow", rules=[
        {"apiGroups": [""], "resources": ["persistentvolumeclaims"], "resourceNames": [PVC],
         "verbs": ["get", "delete"]},
        {"apiGroups": ["batch"], "resources": ["jobs"], "resourceNames": [JOB],
         "verbs": ["get", "delete"]},
        {"apiGroups": ["batch"], "resources": ["jobs"], "verbs": ["create"]},
    ]))
    lab.create(spec(RBAC, "RoleBinding", "saf-bound-volume-workflow",
                    roleRef={"apiGroup": RBAC_GROUP, "kind": "Role", "name": "saf-bound-volume-workflow"},
                    subjects=[{"kind": "ServiceAccount", "name": "fixture-executor", "namespace": NS}]))

    # Dry-run only: this identical request is admitted before the second gate,
    # while an independent node read confirms that it did not touch the marker.
    baseline = json.loads(lab.kubectl("exec", "fixture-executor", "--", "python", "/fixture/probe.py",
                                      "wipe-dry-run", pv_name, LEDGER).stdout)
    baseline_marker = marker_at_node(lab, path)
    baseline_job = get(lab, "job", JOB)
    lab.check("red", "Before the supplement gate, the exact wipe Job dry-run is admitted without changing data",
              baseline["code"] == 201 and baseline_marker == MARKER_CONTENT and baseline_job is None,
              {"dry_run_admitted": baseline["code"] == 201,
               "marker_unchanged": baseline_marker == MARKER_CONTENT, "no_job_created": baseline_job is None})

    # Policies match only this second ledger, this bound PV, and the one named Job.
    user = "system:serviceaccount:saf-test:fixture-executor"
    reviewers = ("system:serviceaccount:saf-test:security-reviewer",
                 "system:serviceaccount:saf-test:data-reviewer")
    install(lab, VOTE_POLICY, "configmaps", "", "UPDATE",
            f"object.data['volumeUid'] == oldObject.data['volumeUid'] && size(object.data) == 3 && "
            f"((request.userInfo.username == '{reviewers[0]}' && object.data['security'] == 'approved' "
            "&& object.data['dataOwner'] == oldObject.data['dataOwner']) || "
            f"(request.userInfo.username == '{reviewers[1]}' && object.data['dataOwner'] == 'approved' "
            "&& object.data['security'] == oldObject.data['security']))",
            VOTE_ERROR, f"request.namespace == '{NS}' && request.name == '{LEDGER}'")
    install(lab, DELETE_POLICY, "persistentvolumes", "", "DELETE",
            f"request.userInfo.username == '{user}' && params != null "
            "&& params.data['volumeUid'] == oldObject.metadata.uid "
            "&& params.data['security'] == 'approved' && params.data['dataOwner'] == 'approved'",
            DELETE_ERROR, f"request.name == '{pv_name}'", param=LEDGER)
    relevant_job = (
        f"request.namespace == '{NS}' && (request.userInfo.username == '{user}' || "
        f"object.metadata.name == '{JOB}' || "
        "(has(object.spec.template.spec.volumes) && object.spec.template.spec.volumes.exists(v, "
        f"has(v.persistentVolumeClaim) && v.persistentVolumeClaim.claimName == '{PVC}')))"
    )
    install(lab, WIPE_POLICY, "jobs", "batch", "CREATE",
            expected_job_expression(user, target_uid), WIPE_ERROR, relevant_job, param=LEDGER)

    # The named Job is server-dry-run denied before approvals; node read is an
    # independent data oracle and confirms no pre-approval storage mutation.
    deadline = time.monotonic() + 20
    while True:
        denied = json.loads(lab.kubectl("exec", "fixture-executor", "--", "python", "/fixture/probe.py",
                                        "wipe-dry-run", pv_name, LEDGER).stdout)
        if denied["code"] == 403 and WIPE_POLICY in denied["detail"]:
            break
        if time.monotonic() >= deadline:
            lab.block("The named Job admission guard did not become effective")
        time.sleep(0.4)
    marker_now = marker_at_node(lab, path)
    denied_job = get(lab, "job", JOB)
    ledger_data = json.loads(lab.kubectl("get", "configmap", LEDGER, "-o", "json").stdout)["data"]
    lab.check("green", "The exact marker-removal Job is denied with zero votes and leaves the bound marker intact",
              denied["code"] == 403 and WIPE_POLICY in denied["detail"] and marker_now == MARKER_CONTENT
              and denied_job is None
              and ledger_data == {"volumeUid": target_uid, "security": "pending", "dataOwner": "pending"},
              {"job_denied": denied["code"] == 403 and WIPE_POLICY in denied["detail"],
               "marker_unchanged": marker_now == MARKER_CONTENT, "job_absent": denied_job is None,
               "ledger_pending": True})

    first = json.loads(lab.kubectl("exec", "security-reviewer", "--", "python", "/fixture/probe.py",
                                   "security-vote", pv_name, LEDGER).stdout)
    still_denied = json.loads(lab.kubectl("exec", "fixture-executor", "--", "python", "/fixture/probe.py",
                                          "wipe-dry-run", pv_name, LEDGER).stdout)
    marker_after_one = marker_at_node(lab, path)
    one_vote_job = get(lab, "job", JOB)
    lab.check("green", "One distinct approval cannot launch the wipe Job or change its mounted data",
              first["code"] == 200 and still_denied["code"] == 403
              and WIPE_POLICY in still_denied["detail"] and marker_after_one == MARKER_CONTENT
              and one_vote_job is None,
              {"first_vote_accepted": first["code"] == 200,
               "job_still_denied": still_denied["code"] == 403 and WIPE_POLICY in still_denied["detail"],
               "marker_unchanged": marker_after_one == MARKER_CONTENT, "job_absent": one_vote_job is None})

    second = json.loads(lab.kubectl("exec", "data-reviewer", "--", "python", "/fixture/probe.py",
                                    "data-vote", pv_name, LEDGER).stdout)
    allowed = json.loads(lab.kubectl("exec", "fixture-executor", "--", "python", "/fixture/probe.py",
                                     "wipe-dry-run", pv_name, LEDGER).stdout)
    if second["code"] != 200 or allowed["code"] != 201:
        lab.block("Both independent votes did not admit the exact wipe request")
    create = json.loads(lab.kubectl("exec", "fixture-executor", "--", "python", "/fixture/probe.py",
                                    "wipe-create", pv_name, LEDGER).stdout)
    if create["code"] != 201:
        lab.block("The approved exact marker-removal Job was not created")
    lab.kubectl("wait", "--for=condition=Complete", f"job/{JOB}", "--timeout=45s", timeout=55)
    job_log = lab.kubectl("logs", f"job/{JOB}").stdout.strip()
    job_pods = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={JOB}", "-o", "json").stdout)
    job_node_exact = (len(job_pods.get("items", [])) == 1
                      and job_pods["items"][0].get("spec", {}).get("nodeName")
                      == f"{lab.cluster}-control-plane")
    after_wipe = marker_at_node(lab, path)
    ledger_after = json.loads(lab.kubectl("get", "configmap", LEDGER, "-o", "json").stdout)["data"]
    lab.check("positive", "Dual approval permits only the fixed marker unlink on the exact bound volume",
              job_log == "marker-removed" and job_node_exact and after_wipe == "DIRECTORY_ONLY"
              and ledger_after == {"volumeUid": target_uid, "security": "approved", "dataOwner": "approved"},
              {"both_votes_recorded": ledger_after.get("security") == "approved"
               and ledger_after.get("dataOwner") == "approved"
               and ledger_after.get("volumeUid") == target_uid,
               "job_completed_exact_marker_action": job_log == "marker-removed",
               "job_ran_on_exact_pv_node": job_node_exact,
               "independent_node_read_confirms_marker_absent": after_wipe == "DIRECTORY_ONLY"})

    # Owner cleanup deletes only the exact finished Job, claim, and PV; the
    # retained backing directory is left to disposable-cluster teardown.
    job_delete = json.loads(lab.kubectl("exec", "fixture-executor", "--", "python", "/fixture/probe.py",
                                        "job-delete", pv_name, LEDGER).stdout)
    pvc_delete = json.loads(lab.kubectl("exec", "fixture-executor", "--", "python", "/fixture/probe.py",
                                        "pvc-delete", pv_name, LEDGER).stdout)
    if job_delete["code"] not in (200, 202) or pvc_delete["code"] not in (200, 202):
        lab.block("The fixture executor could not remove the exact completed Job and owned PVC")
    wait_phase(lab, "pvc", PVC, "Absent", 30)
    wait_phase(lab, "pv", pv_name, "Released", 30)
    pv_delete = json.loads(lab.kubectl("exec", "fixture-executor", "--", "python", "/fixture/probe.py",
                                       "delete", pv_name, LEDGER).stdout)
    wait_phase(lab, "pv", pv_name, "Absent", 30)
    if get(lab, "job", JOB) is not None or get(lab, "pvc", PVC) is not None:
        lab.block("An exact owned workload or claim remained after fixture cleanup")
    final_marker = marker_at_node(lab, path)
    lab.check("positive", "Approved owner cleanup removes the exact Job, PVC, and PV while the marker stays absent",
              pv_delete["code"] == 200 and final_marker == "DIRECTORY_ONLY",
              {"job_absent": True, "pvc_absent": True, "pv_absent": True,
               "marker_absent_before_node_teardown": final_marker == "DIRECTORY_ONLY"})
