"""Device-level approved containment assertions for SAF-K8S-1005-023.

The supervisor calls ``run(lab)`` before the unchanged node-level case.  The
driver and DeviceClass are supplied by the pre-rendered upstream chart.  This
module creates only disposable case-owned workloads, Service/RBAC, and the
pre-created exact DeviceTaintRule, then removes those objects after preserving
the observations.  It never cordons or taints a Node.
"""
from copy import deepcopy
import json
from pathlib import Path
import time


NAMESPACE = "saf-test"
DRIVER = "gpu.example.com"
DEVICE_CLASS = "gpu.example.com"
RESOURCE = "saf.example.test/mock-gpu"
CASE_LABEL = "SAF-K8S-1005-023"
VICTIM = "saf-1005-023-device-victim"
SERVICE_POD = "saf-1005-023-device-service"
SERVICE = "saf-1005-023-device-http"
PROBE = "saf-1005-023-http-probe"
SERVICE_ACCOUNT_ORDINARY = "saf-1005-023-ordinary"
SERVICE_ACCOUNT_RESPONDER = "saf-1005-023-responder"
RESPONDER_ROLE = "saf-1005-023-device-rule-updater"
RESPONDER_BINDING = "saf-1005-023-device-rule-updater"
RULE = "saf-1005-023-device-quarantine"
TAINT_KEY = "saf-k8s.example/device-quarantine"
TAINT_VALUE = "SYNTHETIC-INCIDENT-001"
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
READY_TIMEOUT = 180
EVICTION_TIMEOUT = 90


def _json(lab, *args, timeout=30, impersonate=None, allow_failure=False):
    extra = []
    if impersonate:
        extra = ["--as", impersonate,
                 "--as-group", "system:serviceaccounts",
                 "--as-group", f"system:serviceaccounts:{NAMESPACE}",
                 "--as-group", "system:authenticated"]
    result = lab.kubectl(*extra, *args, "-o", "json", timeout=timeout,
                         allow_failure=allow_failure)
    if result.returncode:
        return result, None
    try:
        return result, json.loads(result.stdout)
    except json.JSONDecodeError:
        return result, None


def _wait(lab, fn, description, seconds=READY_TIMEOUT):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            value = fn()
            if value:
                return value
        except (KeyError, IndexError, TypeError, json.JSONDecodeError):
            pass
        time.sleep(1)
    lab.block(f"Timed out waiting for {description}")


def _ready(pod, node):
    return (pod.get("status", {}).get("phase") == "Running"
            and pod.get("spec", {}).get("nodeName") == node
            and any(c.get("type") == "Ready" and c.get("status") == "True"
                    for c in pod.get("status", {}).get("conditions", [])))


def _pod(name, node, command, port=None):
    role = "unaffected-service" if port else "device-victim"
    container = {
        "name": "synthetic-workload", "image": IMAGE,
        "imagePullPolicy": "IfNotPresent", "command": command,
        "resources": {
            "requests": {"cpu": "10m", "memory": "16Mi", RESOURCE: "1"},
            "limits": {"cpu": "100m", "memory": "48Mi", RESOURCE: "1"},
        },
        "securityContext": {
            "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True,
            "runAsUser": 65532, "seccompProfile": {"type": "RuntimeDefault"},
        },
    }
    if port:
        container["ports"] = [{"name": "http", "containerPort": port}]
        container["readinessProbe"] = {"httpGet": {"path": "/", "port": port}, "periodSeconds": 1}
        container["env"] = [{"name": "POD_MARKER", "valueFrom": {
            "fieldRef": {"fieldPath": "metadata.name"}}}]
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {
        "name": name, "namespace": NAMESPACE,
        "labels": {"saf-k8s.example/case": CASE_LABEL,
                    "saf-k8s.example/role": role}},
        "spec": {"nodeSelector": {"kubernetes.io/hostname": node}, "restartPolicy": "Never",
                  "automountServiceAccountToken": False,
                  "terminationGracePeriodSeconds": 2,
                  "containers": [container]}}


def _service_code():
    return ("import http.server,os; "
            "H=type('H',(http.server.BaseHTTPRequestHandler,),{"
            "'do_GET':lambda s:(s.send_response(200),s.end_headers(),"
            "s.wfile.write(os.environ['POD_MARKER'].encode())),'log_message':lambda *a:None}); "
            "http.server.HTTPServer(('0.0.0.0',8080),H).serve_forever()")


def _claim_name(pod):
    status = pod.get("status", {}).get("extendedResourceClaimStatus") or {}
    return status.get("resourceClaimName")


def _allocation(claim):
    results = (claim.get("status", {}).get("allocation", {})
               .get("devices", {}).get("results", []))
    exact = [r for r in results if r.get("driver") and r.get("pool") and r.get("device")]
    return exact[0] if len(exact) == 1 else None


def _read_allocation(lab, pod):
    claim_name = _claim_name(pod)
    if not claim_name:
        return None
    _, claim = _json(lab, "get", "resourceclaim", claim_name)
    if not claim:
        return None
    allocation = _allocation(claim)
    if not allocation:
        return None
    return {"claim_name": claim_name, "claim": claim, "allocation": allocation}


def _condition(rule, condition_type):
    return next((c for c in rule.get("status", {}).get("conditions", [])
                 if c.get("type") == condition_type), None)


def _start_probe(lab):
    probe = {"apiVersion": "v1", "kind": "Pod", "metadata": {
        "name": PROBE, "namespace": NAMESPACE},
        "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
            "terminationGracePeriodSeconds": 1, "containers": [{
                "name": "http-probe", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-c", "import time; time.sleep(3600)"],
                "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                              "limits": {"cpu": "50m", "memory": "32Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True,
                    "runAsUser": 65532, "seccompProfile": {"type": "RuntimeDefault"}}}]}}
    lab.create(probe)
    lab.kubectl("wait", f"pod/{PROBE}", "--for=condition=Ready", "--timeout=60s", timeout=70)


def _probe_service(lab, address):
    script = ("import sys,urllib.request; "
              "opener=urllib.request.build_opener(urllib.request.ProxyHandler({})); "
              "print(opener.open('http://' + sys.argv[1] + ':8080/', timeout=5).read().decode())")
    result = lab.kubectl("exec", PROBE, "--", "python", "-c", script, address,
                         timeout=15, allow_failure=True)
    return {"phase": "Succeeded" if result.returncode == 0 else "Failed",
            "exit_code": result.returncode, "marker": result.stdout.strip(),
            "error": result.stderr.strip()}


def _raw(lab, name, value):
    (lab.evidence / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                                     encoding="utf-8")


def run(lab):
    version_result = lab.kubectl("version", "-o", "json", timeout=20)
    version = json.loads(version_result.stdout)
    if version.get("serverVersion", {}).get("gitVersion") != "v1.37.2":
        lab.block("Device containment extension is restricted to the supervisor-verified v1.37.2 server")
    # Refuse collisions: this module must never adopt or mutate prior objects.
    for kind, name in (("pod", VICTIM), ("pod", SERVICE_POD), ("service", SERVICE),
                       ("serviceaccount", SERVICE_ACCOUNT_ORDINARY),
                       ("serviceaccount", SERVICE_ACCOUNT_RESPONDER),
                       ("devicetaintrule", RULE)):
        result = lab.kubectl("get", kind, name, allow_failure=True)
        if result.returncode == 0:
            lab.block(f"Case-owned name already exists; refusing to adopt {kind}/{name}")

    _, dc = _json(lab, "get", "deviceclass", DEVICE_CLASS)
    _, node_list = _json(lab, "get", "nodes")
    _, slices = _json(lab, "get", "resourceslices")
    if not dc or dc.get("spec", {}).get("extendedResourceName") != RESOURCE:
        lab.block("Fixture prerequisite failed: rendered DeviceClass extended resource mismatch")

    pools = {}
    for sl in (slices or {}).get("items", []):
        spec = sl.get("spec", {})
        pool = spec.get("pool", {}).get("name")
        if spec.get("driver") != DRIVER or not pool:
            continue
        names = {d.get("name") for d in spec.get("devices", []) if d.get("name")}
        if names:
            pools.setdefault((spec.get("nodeName"), pool), set()).update(names)
    candidates = [(node, pool, names) for (node, pool), names in pools.items()
                  if node and len(names) >= 2]
    if len(candidates) != 1:
        _raw(lab, "device-fixture-blocked.raw.json", {"device_class": dc,
             "nodes": node_list, "resource_slices": slices,
             "reason": "expected exactly one gpu.example.com node pool with two devices"})
        lab.block("Fixture provisioning blocked: expected one driver pool publishing at least two devices")
    node, pool, device_names = candidates[0]
    node_obj = next((n for n in node_list.get("items", [])
                     if n.get("metadata", {}).get("name") == node), {})
    capacity = node_obj.get("status", {}).get("capacity", {})
    allocatable = node_obj.get("status", {}).get("allocatable", {})
    if RESOURCE in capacity or RESOURCE in allocatable:
        lab.block("Fixture prerequisite failed: extended resource also appears as a node device-plugin resource")

    # No controller owns either Pod: the NoExecute result cannot be replaced.
    victim_command = ["python", "-c", "import time; time.sleep(3600)"]
    service_command = ["python", "-c", _service_code()]
    lab.create(_pod(VICTIM, node, victim_command))
    lab.create(_pod(SERVICE_POD, node, service_command, port=8080))
    service_object = lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {
        "name": SERVICE, "namespace": NAMESPACE,
        "labels": {"saf-k8s.example/case": CASE_LABEL}},
        "spec": {"selector": {"saf-k8s.example/role": "unaffected-service",
                              "saf-k8s.example/case": CASE_LABEL},
                 "ports": [{"name": "http", "port": 8080, "targetPort": 8080}]}})
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {
        "name": SERVICE_ACCOUNT_ORDINARY, "namespace": NAMESPACE,
        "labels": {"saf-k8s.example/case": CASE_LABEL}}})
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {
        "name": SERVICE_ACCOUNT_RESPONDER, "namespace": NAMESPACE,
        "labels": {"saf-k8s.example/case": CASE_LABEL}}})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
        "metadata": {"name": RESPONDER_ROLE,
                     "labels": {"saf-k8s.example/case": CASE_LABEL}},
        "rules": [{"apiGroups": ["resource.k8s.io"],
                   "resources": ["devicetaintrules"], "verbs": ["update"],
                   "resourceNames": [RULE]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
        "metadata": {"name": RESPONDER_BINDING,
                     "labels": {"saf-k8s.example/case": CASE_LABEL}},
        "subjects": [{"kind": "ServiceAccount", "name": SERVICE_ACCOUNT_RESPONDER,
                      "namespace": NAMESPACE}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                    "name": RESPONDER_ROLE}})
    _, ordinary_sa = _json(lab, "get", "serviceaccount", SERVICE_ACCOUNT_ORDINARY)
    _, responder_sa = _json(lab, "get", "serviceaccount", SERVICE_ACCOUNT_RESPONDER)
    _, responder_role = _json(lab, "get", "clusterrole", RESPONDER_ROLE)
    _, responder_binding = _json(lab, "get", "clusterrolebinding", RESPONDER_BINDING)

    def running_pod(name):
        return _wait(lab, lambda: (lambda x: x if x and _ready(x, node) else None)
                     (_json(lab, "get", "pod", name)[1]), f"{name} Ready on selected DRA node")
    victim = running_pod(VICTIM)
    service_pod = running_pod(SERVICE_POD)
    victim_alloc = _wait(lab, lambda: _read_allocation(lab, victim),
                         "victim extended-resource allocation")
    service_alloc = _wait(lab, lambda: _read_allocation(lab, service_pod),
                          "service extended-resource allocation")
    va, sa = victim_alloc["allocation"], service_alloc["allocation"]
    allocs_distinct = (va["driver"] == sa["driver"] == DRIVER
                       and va["pool"] == sa["pool"] == pool
                       and va["device"] != sa["device"]
                       and {va["device"], sa["device"]}.issubset(device_names))
    if not allocs_distinct:
        _raw(lab, "device-fixture-blocked.raw.json", {"victim": victim,
             "victim_claim": victim_alloc["claim"], "service": service_pod,
             "service_claim": service_alloc["claim"], "resource_slices": slices})
        lab.block("Fixture provisioning blocked: Pods lack distinct allocated devices in the selected driver pool")

    # Confirm each allocated device is present in a ResourceSlice with the
    # exact driver/pool/node identity read from the API, never guessed.
    def slice_has(allocation):
        return any(s.get("spec", {}).get("driver") == allocation["driver"]
            and s.get("spec", {}).get("pool", {}).get("name") == allocation["pool"]
            and s.get("spec", {}).get("nodeName") == node
            and any(d.get("name") == allocation["device"]
                    for d in s.get("spec", {}).get("devices", []))
            for s in slices.get("items", []))
    slices_match = slice_has(va) and slice_has(sa)
    if not slices_match:
        lab.block("Fixture provisioning blocked: allocated device missing from matching ResourceSlice")

    # Ensure the HTTP endpoint is ready and works before creating the rule.
    endpoints = _wait(lab, lambda: (lambda x: x if x and any(
        ep.get("targetRef", {}).get("uid") == service_pod["metadata"]["uid"]
        and ep.get("conditions", {}).get("ready") is True
        for es in x.get("items", []) for ep in es.get("endpoints", [])) else None)
        (_json(lab, "get", "endpointslices", "-l", f"kubernetes.io/service-name={SERVICE}")[1]),
        "ready Service endpoint for unaffected Pod")
    service_address = service_object["spec"]["clusterIP"]
    _start_probe(lab)
    http_before = _probe_service(lab, service_address)
    service_before_ok = (http_before["phase"] == "Succeeded" and http_before["exit_code"] == 0
                         and http_before["marker"] == SERVICE_POD)
    if not service_before_ok:
        _raw(lab, "device-service-blocked.raw.json", {"http": http_before, "endpoints": endpoints})
        lab.block("Fixture prerequisite failed: Service did not return the unaffected Pod marker before quarantine")

    victim_uid = victim["metadata"]["uid"]
    service_uid = service_pod["metadata"]["uid"]
    reserved = victim_alloc["claim"].get("status", {}).get("reservedFor", [])
    claim_uid_link = any(x.get("resource") == "pods" and x.get("name") == VICTIM
                         and x.get("uid") == victim_uid for x in reserved)
    if not claim_uid_link:
        lab.block("Fixture prerequisite failed: victim UID is not associated in its ResourceClaim status")

    # Exact selector, effect None first. Status message is the API's dry-run
    # report; the claim->UID and selected device linkage proves which Pod it is.
    rule = {"apiVersion": "resource.k8s.io/v1", "kind": "DeviceTaintRule",
        "metadata": {"name": RULE, "labels": {"saf-k8s.example/case": CASE_LABEL}},
        "spec": {"deviceSelector": {"driver": va["driver"], "pool": va["pool"],
                                     "device": va["device"]},
                 "taint": {"key": TAINT_KEY, "value": TAINT_VALUE, "effect": "None"}}}
    rule = lab.create(rule)
    dry_rule = _wait(lab, lambda: (lambda x: x if x and _condition(x, "EvictionInProgress")
        and x["metadata"].get("generation") == _condition(x, "EvictionInProgress").get("observedGeneration")
        else None)(_json(lab, "get", "devicetaintrule", RULE)[1]),
        "DeviceTaintRule dry-run status", seconds=45)
    dry_condition = _condition(dry_rule, "EvictionInProgress")
    dry_message = dry_condition.get("message", "")
    dry_run_ok = (rule.get("spec") == dry_rule.get("spec")
                  and dry_rule.get("spec", {}).get("deviceSelector") == {
                      "driver": va["driver"], "pool": va["pool"], "device": va["device"]}
                  and "1 allocated device selected" in dry_message
                  and "1 pod would be evicted" in dry_message)
    if not dry_run_ok:
        lab.block("Positive precheck failed: exact None rule did not select one allocated device and one Pod for eviction")

    before_pods = _json(lab, "get", "pods")[1]
    pre_uids = {p.get("metadata", {}).get("uid") for p in before_pods.get("items", [])}
    pre_uids.discard(None)

    # The denied request is made by the ordinary identity against the already
    # created exact rule. Save the raw API response, then prove no spec change.
    desired_rule = deepcopy(dry_rule)
    desired_rule.pop("status", None)
    desired_rule["spec"]["taint"]["effect"] = "NoExecute"
    resource = f"/apis/resource.k8s.io/v1/devicetaintrules/{RULE}"

    def update_as(identity):
        return lab.kubectl(
            "--as", identity, "--as-group", "system:serviceaccounts",
            "--as-group", f"system:serviceaccounts:{NAMESPACE}",
            "--as-group", "system:authenticated", "replace", "--raw", resource, "-f", "-",
            payload=json.dumps(desired_rule), allow_failure=True,
        )

    ordinary_user = f"system:serviceaccount:{NAMESPACE}:{SERVICE_ACCOUNT_ORDINARY}"
    denied = update_as(ordinary_user)
    denied_text = denied.stdout + denied.stderr
    denied_ok = denied.returncode != 0 and "(Forbidden)" in denied_text and "cannot update" in denied_text
    _, after_denied = _json(lab, "get", "devicetaintrule", RULE)
    denied_unchanged = bool(after_denied and after_denied.get("spec") == dry_rule.get("spec")
                            and after_denied.get("metadata", {}).get("generation")
                            == dry_rule.get("metadata", {}).get("generation"))
    (lab.evidence / "device-ordinary-authorization.raw.txt").write_text(
        denied_text + f"\n[exit {denied.returncode}]\n", encoding="utf-8")
    if not (denied_ok and denied_unchanged):
        lab.block("Authorization boundary failed: ordinary identity was not Forbidden with unchanged rule spec")

    responder_user = f"system:serviceaccount:{NAMESPACE}:{SERVICE_ACCOUNT_RESPONDER}"
    updated = update_as(responder_user)
    updated_rule = json.loads(updated.stdout) if updated.returncode == 0 else None
    update_response = updated.stdout + updated.stderr
    (lab.evidence / "device-responder-authorization.raw.txt").write_text(
        update_response + f"\n[exit {updated.returncode}]\n", encoding="utf-8")
    if updated.returncode != 0 or not updated_rule:
        lab.block("Authorization boundary failed: designated responder could not update the named rule")
    expected_selector = {"driver": va["driver"], "pool": va["pool"], "device": va["device"]}
    responder_update_ok = (updated_rule.get("spec", {}).get("deviceSelector") == expected_selector
        and updated_rule.get("spec", {}).get("taint", {}).get("key") == TAINT_KEY
        and updated_rule.get("spec", {}).get("taint", {}).get("value") == TAINT_VALUE
        and updated_rule.get("spec", {}).get("taint", {}).get("effect") == "NoExecute")
    if not responder_update_ok:
        lab.block("Responder update changed fields outside the approved effect or did not read back NoExecute")

    def eviction_done():
        _, current = _json(lab, "get", "devicetaintrule", RULE)
        condition = _condition(current or {}, "EvictionInProgress")
        return current if condition and condition.get("status") == "False" \
            and condition.get("observedGeneration") == current.get("metadata", {}).get("generation") else None
    final_rule = _wait(lab, eviction_done, "DeviceTaintRule EvictionInProgress=False",
                       seconds=EVICTION_TIMEOUT)

    def victim_gone_or_terminal():
        result, obj = _json(lab, "get", "pod", VICTIM, allow_failure=True)
        if result.returncode != 0:
            if "(NotFound)" not in result.stderr:
                lab.block(f"Unable to read the selected workload: {result.stderr.strip()}")
            return {"deleted": True, "pod": None}
        if obj and obj.get("metadata", {}).get("uid") == victim_uid and (
                obj.get("metadata", {}).get("deletionTimestamp")
                or obj.get("status", {}).get("phase") in ("Succeeded", "Failed")):
            return {"deleted": False, "pod": obj}
        return None
    victim_end = _wait(lab, victim_gone_or_terminal, "selected victim deletion or terminal status",
                       seconds=EVICTION_TIMEOUT)
    if victim_end["pod"]:
        victim_final = victim_end["pod"]
        victim_observed = bool(victim_final.get("metadata", {}).get("deletionTimestamp")
            or victim_final.get("status", {}).get("phase") in ("Succeeded", "Failed"))
    else:
        victim_final, victim_observed = None, True

    _, service_after = _json(lab, "get", "pod", SERVICE_POD)
    _, endpoints_after = _json(lab, "get", "endpointslices", "-l",
                               f"kubernetes.io/service-name={SERVICE}")
    http_after = _probe_service(lab, service_address)
    _, after_pods = _json(lab, "get", "pods")
    after_uids = {p.get("metadata", {}).get("uid") for p in after_pods.get("items", [])}
    after_uids.discard(None)
    unrelated_uids_unchanged = (pre_uids - {victim_uid}).issubset(after_uids)
    victim_uid_absent = victim_uid not in after_uids
    service_endpoint_ok = any(ep.get("targetRef", {}).get("uid") == service_uid
        and ep.get("conditions", {}).get("ready") is True
        for es in (endpoints_after or {}).get("items", []) for ep in es.get("endpoints", []))
    service_after_ok = (_ready(service_after or {}, node) and service_endpoint_ok
        and http_after["phase"] == "Succeeded" and http_after["exit_code"] == 0
        and http_after["marker"] == SERVICE_POD)
    effect_only = (final_rule.get("spec", {}).get("deviceSelector") == expected_selector
        and final_rule.get("spec", {}).get("taint", {}).get("key") == TAINT_KEY
        and final_rule.get("spec", {}).get("taint", {}).get("value") == TAINT_VALUE
        and final_rule.get("spec", {}).get("taint", {}).get("effect") == "NoExecute")
    eviction_positive = (_condition(final_rule, "EvictionInProgress") or {}).get("status") == "False"

    # Store identifiers only in raw evidence. The receipt has stable booleans
    # and counts for supervisor-to-supervisor comparison, never raw UIDs.
    raw = {"node": node_obj, "all_nodes": node_list, "victim_before": victim,
        "victim_after": victim_final, "service_pod_before": service_pod,
        "service_pod_after": service_after, "victim_claim": victim_alloc["claim"],
        "service_claim": service_alloc["claim"], "resource_slices": slices,
        "device_class": dc, "rule_none": dry_rule, "rule_after_denied": after_denied,
        "rule_noexecute": final_rule, "ordinary_forbidden_response": denied_text,
        "responder_update_response": update_response,
        "ordinary_service_account": ordinary_sa,
        "responder_service_account": responder_sa,
        "responder_role": responder_role, "role_binding": responder_binding,
        "endpoint_slices_before": endpoints, "endpoint_slices_after": endpoints_after,
        "http_before": http_before, "http_after": http_after,
        "pods_before": before_pods, "pods_after": after_pods,
        "allocated_device_names": {"victim": va["device"], "service": sa["device"]}}
    _raw(lab, "device-containment.raw.json", raw)
    receipt = {
        "case": CASE_LABEL, "phase": "device-containment",
        "kubernetes_version_expected": "v1.37.2",
        "fixture_device_class_extended_resource_matches": True,
        "two_distinct_devices_allocated_in_same_driver_pool": bool(allocs_distinct),
        "resource_slices_confirm_both_allocations": bool(slices_match),
        "victim_claim_associated_with_exact_pod_uid": bool(claim_uid_link),
        "exact_rule_none_selected_one_allocated_device_and_one_pod": bool(dry_run_ok),
        "ordinary_identity_received_forbidden": bool(denied_ok),
        "ordinary_forbidden_left_spec_and_generation_unchanged": bool(denied_unchanged),
        "responder_named_rule_update_succeeded": bool(updated.returncode == 0),
        "responder_changed_effect_only_to_noexecute": bool(responder_update_ok and effect_only),
        "selected_victim_deleted_or_terminal": bool(victim_observed),
        "victim_uid_absent_after_device_eviction": bool(victim_uid_absent),
        "eviction_controller_condition_false": bool(eviction_positive),
        "unaffected_service_pod_ready_and_endpoint_preserved": bool(service_after_ok),
        "service_http_marker_identified_unaffected_pod_before_and_after": bool(
            service_before_ok and service_after_ok),
        "no_unrelated_pod_uid_disappeared": bool(unrelated_uids_unchanged),
        "selected_devices_differ": bool(va["device"] != sa["device"]),
    }
    _raw(lab, "device-containment.receipt.json", receipt)
    lab.check("red", "DRA extended-resource baseline has two distinct allocated devices and a working service",
        bool(allocs_distinct and slices_match and claim_uid_link and service_before_ok),
        {"two_distinct_devices_allocated_in_same_driver_pool": bool(allocs_distinct),
         "resource_slices_confirm_both_allocations": bool(slices_match),
         "victim_claim_associated_with_exact_pod_uid": bool(claim_uid_link),
         "service_http_marker_identified_unaffected_pod_before_and_after": bool(service_before_ok)})
    lab.check("green", "Only the selected device is quarantined and its victim is evicted under approved identity",
        bool(dry_run_ok and denied_ok and denied_unchanged and updated.returncode == 0
             and responder_update_ok and victim_observed and victim_uid_absent and eviction_positive),
        {key: receipt[key] for key in ("exact_rule_none_selected_one_allocated_device_and_one_pod",
          "ordinary_identity_received_forbidden", "ordinary_forbidden_left_spec_and_generation_unchanged",
          "responder_named_rule_update_succeeded", "responder_changed_effect_only_to_noexecute",
          "selected_victim_deleted_or_terminal", "victim_uid_absent_after_device_eviction",
          "eviction_controller_condition_false")})
    lab.check("positive", "Unaffected Service remains Ready and serves through its distinct device after quarantine",
        bool(service_after_ok and unrelated_uids_unchanged and sa["device"] != va["device"]),
        {key: receipt[key] for key in ("unaffected_service_pod_ready_and_endpoint_preserved",
          "service_http_marker_identified_unaffected_pod_before_and_after",
          "no_unrelated_pod_uid_disappeared", "selected_devices_differ")})

    # Cleanup is restricted to names created above; retain all raw evidence.
    for kind, name in (("devicetaintrule", RULE), ("pod", VICTIM), ("pod", SERVICE_POD), ("pod", PROBE),
                       ("service", SERVICE), ("serviceaccount", SERVICE_ACCOUNT_ORDINARY),
                       ("serviceaccount", SERVICE_ACCOUNT_RESPONDER)):
        lab.kubectl("delete", kind, name, "--ignore-not-found=true", "--wait=true",
                    timeout=30, allow_failure=True)
    lab.kubectl("delete", "clusterrolebinding", RESPONDER_BINDING,
                "--ignore-not-found=true", "--wait=true", timeout=30, allow_failure=True)
    lab.kubectl("delete", "clusterrole", RESPONDER_ROLE,
                "--ignore-not-found=true", "--wait=true", timeout=30, allow_failure=True)
