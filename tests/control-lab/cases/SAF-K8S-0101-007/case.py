"""Check API Priority and Fairness classification for a synthetic identity."""
import json
from pathlib import Path
import hashlib
import re
import subprocess
import time


NAMESPACE = "saf-test"
SERVICE_ACCOUNT = "saf-apf-probe"
SYNTHETIC_USER = f"system:serviceaccount:{NAMESPACE}:{SERVICE_ACCOUNT}"
CUSTOM_FLOW_SCHEMA = "saf-apf-exact-subject"
CUSTOM_PRIORITY = "saf-apf-limited"
LOAD_CONFIGMAP = "saf-apf-inert-read"
LOAD_ROLE = "saf-apf-inert-read"
LOAD_BINDING = "saf-apf-inert-read"
LOAD_PRIORITY = "saf-apf-bounded-queue"
LOAD_FLOW_SCHEMA = "saf-apf-bounded-read"
MAX_PROBES_PER_BATCH = 4
PROBE_BUDGET = 8
PROBE_POD = "saf-apf-probe-reader"
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
LEASE_PATH = "/apis/coordination.k8s.io/v1/namespaces/kube-system/leases/kube-scheduler"

SCOPE = (
    "A local Kubernetes v1.36.1 kind API server only. Use four ordinary GET /version "
    "requests and two named kube-scheduler Lease requests in the original case, before and "
    "after a narrow FlowSchema. Capture only APF classification response headers "
    "and bounded response identity, plus passive seat and dispatch metrics. The "
    "scratch supplement adds at most two batches of four concurrent GETs to one "
    "case-owned inert ConfigMap. This does not assess production or managed control planes, traffic "
    "under representative load, tenant fairness, or provider defaults. A bounded passive log observer "
    "reports naturally occurring kubelet Lease updates and the real "
    "scheduler named-Lease request classification; raw API-server logs are discarded."
)


def kubectl_verbose(lab, raw_path, *, as_user=None, as_groups=()):
    """Run one bounded GET and return only result status and APF response headers."""
    command = [
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
        f"kind-{lab.cluster}", "--request-timeout=15s",
    ]
    if as_user:
        command.extend(["--as", as_user])
    for group in as_groups:
        command.extend(["--as-group", group])
    command.extend(["get", f"--raw={raw_path}", "-v=8"])
    try:
        result = subprocess.run(
            command, env=lab.env, text=True, capture_output=True,
            timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        lab.block(f"Could not complete bounded APF probe: {type(error).__name__}")
    identity = as_user or "runner-context"
    with (lab.evidence / "commands.log").open("a") as log:
        log.write(
            f"$ kubectl get --raw={raw_path} [identity={identity}; verbose output suppressed]\n"
            f"[exit {result.returncode}]\n\n"
        )
    if result.returncode:
        # Never include verbose client output, which can contain request details.
        lab.block(f"APF probe failed with kubectl exit code {result.returncode}")
    headers = {}
    for line in result.stderr.splitlines():
        match = re.search(
            r"(?i)(X-Kubernetes-PF-(?:PriorityLevel|FlowSchema)-UID):\s*([^\s,]+)",
            line,
        )
        if match:
            headers[match.group(1).lower()] = match.group(2)
    if set(headers) != {
        "x-kubernetes-pf-prioritylevel-uid", "x-kubernetes-pf-flowschema-uid",
    }:
        lab.block("APF response classification headers were not present in verbose response")
    try:
        body = json.loads(result.stdout)
    except json.JSONDecodeError:
        lab.block("The harmless /version response was not JSON")
    if raw_path == "/version" and body.get("gitVersion") != "v1.36.1":
        lab.block("The harmless /version response did not identify Kubernetes v1.36.1")
    if raw_path == LEASE_PATH and (
        body.get("kind") != "Lease" or body.get("metadata", {}).get("name") != "kube-scheduler"
    ):
        lab.block("The bounded kube-scheduler probe did not return its lease")
    return headers


def fixture_metrics(lab):
    """Return only the exact local fixture priority's passive metric samples."""
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
               f"kind-{lab.cluster}", "--request-timeout=12s", "get", "--raw=/metrics"]
    try:
        response = subprocess.run(command, env=lab.env, text=True, capture_output=True,
                                  timeout=17, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        lab.block(f"Could not collect the local APF metrics: {type(error).__name__}")
    if response.returncode:
        lab.block("The approved runner context could not collect local API server metrics")
    wanted = {
        "apiserver_flowcontrol_nominal_limit_seats": ("seats", None),
        "apiserver_flowcontrol_dispatched_requests_total": ("dispatched", CUSTOM_FLOW_SCHEMA),
        "apiserver_flowcontrol_request_wait_duration_seconds_count": ("wait_samples", CUSTOM_FLOW_SCHEMA),
    }
    values = {}
    for line in response.stdout.splitlines():
        metric, separator, sample = line.partition("{")
        if not separator or metric not in wanted:
            continue
        labels, _, number = sample.partition("}")
        fields = dict(re.findall(r'(\w+)="([^"]*)"', labels))
        key, schema = wanted[metric]
        if fields.get("priority_level") != CUSTOM_PRIORITY:
            continue
        if schema and fields.get("flow_schema") != schema:
            continue
        if key == "wait_samples" and fields.get("execute") != "true":
            continue
        if key in values:
            lab.block(f"The local APF exporter returned duplicate {metric} fixture samples")
        values[key] = int(float(number.split()[0]))
    return values


def object_by_uid(rows, uid):
    matches = [row for row in rows if row.get("metadata", {}).get("uid") == uid]
    return matches[0] if len(matches) == 1 else None


def classification(lab, *, as_user=None, as_groups=(), raw_path="/version"):
    headers = kubectl_verbose(
        lab, raw_path, as_user=as_user, as_groups=as_groups,
    )
    schemas = json.loads(lab.kubectl("get", "flowschemas", "-o", "json").stdout)["items"]
    levels = json.loads(
        lab.kubectl("get", "prioritylevelconfigurations", "-o", "json").stdout
    )["items"]
    schema = object_by_uid(schemas, headers["x-kubernetes-pf-flowschema-uid"])
    level = object_by_uid(levels, headers["x-kubernetes-pf-prioritylevel-uid"])
    if schema is None or level is None:
        lab.block("APF response UID did not resolve to a live FlowSchema and priority level")
    return {
        "flow_schema": schema["metadata"]["name"],
        "priority_level": level["metadata"]["name"],
    }


def apf_runtime_facts(lab):
    api = lab.kubectl(
        "get", "--raw=/apis/flowcontrol.apiserver.k8s.io/v1"
    ).stdout
    stable = json.loads(api)
    if stable.get("groupVersion") != "flowcontrol.apiserver.k8s.io/v1":
        lab.block("The stable FlowSchema API is not served")
    pod = json.loads(lab.kubectl(
        "-n", "kube-system", "get",
        f"pod/kube-apiserver-{lab.cluster}-control-plane", "-o", "json",
    ).stdout)
    containers = [item for item in pod["spec"]["containers"]
                  if item.get("name") == "kube-apiserver"]
    if len(containers) != 1:
        lab.block("Could not inspect the single kind kube-apiserver container")
    command = containers[0].get("command") or []
    flag_values = {}
    for flag in ("enable-priority-and-fairness", "max-requests-inflight",
                 "max-mutating-requests-inflight"):
        vals = []
        for index, arg in enumerate(command):
            if arg == f"--{flag}" and flag == "enable-priority-and-fairness":
                vals.append("true")
            elif arg == f"--{flag}" and index + 1 < len(command):
                vals.append(command[index + 1])
            elif arg.startswith(f"--{flag}="):
                vals.append(arg.split("=", 1)[1])
        if len(vals) > 1:
            lab.block(f"Duplicate kube-apiserver --{flag} values make the profile ambiguous")
        flag_values[flag] = vals[0] if vals else None
    if flag_values["enable-priority-and-fairness"] == "false":
        lab.block("The kube-apiserver explicitly disables API Priority and Fairness")
    readonly = int(
        400 if flag_values["max-requests-inflight"] is None
        else flag_values["max-requests-inflight"]
    )
    mutating = int(
        200 if flag_values["max-mutating-requests-inflight"] is None
        else flag_values["max-mutating-requests-inflight"]
    )
    if readonly < 0 or mutating < 0 or readonly + mutating <= 0:
        lab.block("The effective in-flight limits do not define a positive APF capacity")
    return {
        "flowcontrol_api_served": True,
        "enable_priority_and_fairness_flag": flag_values["enable-priority-and-fairness"],
        "apf_enabled_by_v1_36_default_when_flag_omitted":
            flag_values["enable-priority-and-fairness"] is None,
        "max_requests_inflight": readonly,
        "max_mutating_requests_inflight": mutating,
        "apf_total_concurrency_limit": readonly + mutating,
        "capacity_semantics": "summed under APF; separate limits only when APF is disabled",
    }


def run(lab):
    facts = apf_runtime_facts(lab)
    lab.check(
        "positive",
        "Kubernetes v1.36 serves the stable APF API; effective flags follow APF capacity semantics",
        facts["flowcontrol_api_served"] and facts["apf_total_concurrency_limit"] == 668,
        facts,
    )

    lab.kubectl(
        "create", "serviceaccount", SERVICE_ACCOUNT, "--namespace", NAMESPACE
    )
    before_policy = fixture_metrics(lab)
    lab.check("red", "Before the fixture policy the API server exports no metrics for the dedicated priority",
              not before_policy, {"fixture_series_present": bool(before_policy)})
    prior = classification(lab, as_user=SYNTHETIC_USER)
    lab.check(
        "red",
        "Before narrow configuration, the synthetic ServiceAccount follows the built-in broad service-accounts FlowSchema",
        prior == {"flow_schema": "service-accounts", "priority_level": "workload-low"},
        prior,
    )
    admin_before = classification(lab)
    lab.check(
        "positive",
        "The ordinary runner administrator request follows the built-in global default",
        admin_before == {"flow_schema": "global-default", "priority_level": "global-default"},
        admin_before,
    )
    scheduler_before = classification(
        lab, as_user="system:kube-scheduler", as_groups=("system:authenticated",),
        raw_path=LEASE_PATH,
    )
    lab.check(
        "positive",
        "An ordinary read of the scheduler lease keeps its leader-election priority",
        scheduler_before == {"flow_schema": "system-leader-election", "priority_level": "leader-election"},
        scheduler_before,
    )

    priority = {
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "PriorityLevelConfiguration",
        "metadata": {"name": CUSTOM_PRIORITY},
        "spec": {"type": "Limited", "limited": {
            "nominalConcurrencyShares": 10,
            "lendablePercent": 0,
            "borrowingLimitPercent": 0,
            "limitResponse": {"type": "Queue", "queuing": {
                "queues": 8, "handSize": 2, "queueLengthLimit": 5,
            }},
        }},
    }
    lab.create(priority)
    flow_schema = {
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "FlowSchema",
        "metadata": {"name": CUSTOM_FLOW_SCHEMA},
        "spec": {
            "matchingPrecedence": 8000,
            "distinguisherMethod": {"type": "ByUser"},
            "priorityLevelConfiguration": {"name": CUSTOM_PRIORITY},
            "rules": [{
                "subjects": [{
                    "kind": "ServiceAccount",
                    "serviceAccount": {"name": SERVICE_ACCOUNT, "namespace": NAMESPACE},
                }],
                "resourceRules": [],
                "nonResourceRules": [{"verbs": ["get"], "nonResourceURLs": ["/version"]}],
            }],
        },
    }
    lab.kubectl("apply", "-f", "-", payload=json.dumps(flow_schema))
    lab.kubectl("wait", "--for=condition=Dangling=false",
                f"flowschema/{CUSTOM_FLOW_SCHEMA}", "--timeout=25s", timeout=35)

    before_request = fixture_metrics(lab)
    after = classification(lab, as_user=SYNTHETIC_USER)
    lab.check(
        "green",
        "The exact ServiceAccount and GET /version request route to the dedicated limited priority",
        after == {"flow_schema": CUSTOM_FLOW_SCHEMA, "priority_level": CUSTOM_PRIORITY},
        after,
    )
    after_request = fixture_metrics(lab)
    live_level = json.loads(lab.kubectl(
        "get", "prioritylevelconfiguration", CUSTOM_PRIORITY, "-o", "json",
    ).stdout)["spec"]["limited"]
    dispatch_delta = after_request.get("dispatched", 0) - before_request.get("dispatched", 0)
    wait_delta = after_request.get("wait_samples", 0) - before_request.get("wait_samples", 0)
    seat_limit = after_request.get("seats", 0)
    limit_matches = live_level["limitResponse"] == priority["spec"]["limited"]["limitResponse"]
    lab.check(
        "green", "A bounded request increments the dedicated dispatch and wait histogram counters under the live queue configuration",
        limit_matches and 0 < seat_limit < facts["apf_total_concurrency_limit"]
        and dispatch_delta == 1 and wait_delta == 1,
        {"queue_configuration_matches": bool(limit_matches),
         "nominal_seat_limit_within_api_budget": bool(0 < seat_limit < facts["apf_total_concurrency_limit"]),
         "dispatch_counter_incremented_once": bool(dispatch_delta == 1),
         "executed_wait_sample_incremented_once": bool(wait_delta == 1)},
    )
    admin_after = classification(lab)
    lab.check(
        "positive",
        "The narrow identity rule leaves ordinary administrator classification unchanged",
        admin_after == admin_before,
        admin_after,
    )
    scheduler_after = classification(
        lab, as_user="system:kube-scheduler", as_groups=("system:authenticated",),
        raw_path=LEASE_PATH,
    )
    lab.check(
        "positive",
        "The exact synthetic-subject schema does not change kube-scheduler leader-election routing",
        scheduler_after == scheduler_before,
        scheduler_after,
    )
    observe_natural_critical_flows(lab)
    original_metrics = {"before_policy": before_policy,
                        "before_request": before_request,
                        "after_request": after_request}
    bounded_queue_and_rejection(lab, facts, original_metrics)


def bounded_probe_metrics(lab):
    """Scrape only exact fixture APF counters; never retain the raw metrics body."""
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
               f"kind-{lab.cluster}", "--request-timeout=12s", "get", "--raw=/metrics"]
    try:
        result = subprocess.run(command, env=lab.env, text=True, capture_output=True,
                                timeout=17, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        lab.block(f"Could not collect bounded APF comparison metrics: {type(error).__name__}")
    if result.returncode:
        lab.block("The local API server did not provide APF comparison metrics")
    selected = {
        "seats": None,
        "wait_count": 0.0,
        "wait_sum": 0.0,
        "concurrency_rejections": 0.0,
    }
    metric_names = {
        "apiserver_flowcontrol_nominal_limit_seats": "seats",
        "apiserver_flowcontrol_request_wait_duration_seconds_count": "wait_count",
        "apiserver_flowcontrol_request_wait_duration_seconds_sum": "wait_sum",
        "apiserver_flowcontrol_rejected_requests_total": "concurrency_rejections",
    }
    for line in result.stdout.splitlines():
        name, separator, sample = line.partition("{")
        if not separator or name not in metric_names:
            continue
        labels, closing, value = sample.partition("}")
        if not closing:
            continue
        fields = dict(re.findall(r'(\w+)="((?:[^"\\]|\\.)*)"', labels))
        if fields.get("priority_level") != LOAD_PRIORITY:
            continue
        if name != "apiserver_flowcontrol_nominal_limit_seats":
            if fields.get("flow_schema") != LOAD_FLOW_SCHEMA:
                continue
        if name.startswith("apiserver_flowcontrol_request_wait_duration_seconds"):
            if fields.get("execute") != "true":
                continue
        if name == "apiserver_flowcontrol_rejected_requests_total":
            if fields.get("reason") != "concurrency-limit":
                continue
        key = metric_names[name]
        try:
            number = float(value.split()[0])
        except (IndexError, ValueError):
            lab.block("APF comparison metric had an invalid sample value")
        if key == "seats":
            if selected[key] is not None:
                lab.block("APF metrics contained duplicate fixture seat samples")
            selected[key] = number
        else:
            selected[key] += number
    return selected


def probe_identity_uids(lab):
    schemas = json.loads(lab.kubectl("get", "flowschemas", "-o", "json").stdout)["items"]
    levels = json.loads(lab.kubectl(
        "get", "prioritylevelconfigurations", "-o", "json").stdout)["items"]
    matches = [item for item in schemas if item.get("metadata", {}).get("name") == LOAD_FLOW_SCHEMA]
    priorities = [item for item in levels if item.get("metadata", {}).get("name") == LOAD_PRIORITY]
    if len(matches) != 1 or len(priorities) != 1:
        lab.block("Could not identify the unique owned APF comparison objects")
    return (matches[0]["metadata"]["uid"], priorities[0]["metadata"]["uid"])


def probe_identity_hashes(lab):
    """Return one-way hashes for in-Pod response-header matching."""
    flow_uid, priority_uid = probe_identity_uids(lab)
    return (hashlib.sha256(flow_uid.encode()).hexdigest(),
            hashlib.sha256(priority_uid.encode()).hexdigest())


def run_pod_probe(lab, mode):
    """Trigger one fixed four-request batch inside the case-owned reader Pod."""
    if mode not in ("queue", "reject"):
        lab.block("Invalid bounded in-Pod probe mode")
    result = lab.kubectl("exec", PROBE_POD, "--", "python", "-B",
                         "/fixture/probe.py", mode, timeout=25)
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        lab.block("The owned in-Pod HTTPS probe returned no stable verdict")
    expected = {
        "projection_available", "tls_verified_for_all",
        "all_responses_classified_to_fixture",
        "all_reads_succeeded_with_exact_fixture",
        "has_expected_rejection", "only_expected_statuses",
    }
    if set(report) != expected or any(type(value) is not bool for value in report.values()):
        lab.block("The owned in-Pod HTTPS probe returned an unexpected evidence schema")
    return report


def set_load_priority_mode(lab, mode):
    if mode not in ("Queue", "Reject"):
        lab.block("Invalid bounded APF comparison mode")
    response = {"type": mode}
    if mode == "Queue":
        response["queuing"] = {
            "queues": 1, "handSize": 1, "queueLengthLimit": MAX_PROBES_PER_BATCH,
        }
    patch = [{"op": "replace", "path": "/spec/limited/limitResponse",
              "value": response}]
    lab.kubectl("patch", "prioritylevelconfiguration", LOAD_PRIORITY,
                "--type=json", "-p", json.dumps(patch), timeout=15)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        live = json.loads(lab.kubectl(
            "get", "prioritylevelconfiguration", LOAD_PRIORITY, "-o", "json",
            timeout=12,
        ).stdout)
        observed = live.get("spec", {}).get("limited", {}).get("limitResponse", {}).get("type")
        if observed == mode:
            return
        time.sleep(0.5)
    lab.block("The bounded APF fixture priority did not converge to its requested mode")


def bounded_queue_and_rejection(lab, facts, original_metrics):
    """Supplement the sequential checks with one bounded queue and reject batch."""
    if PROBE_BUDGET != 2 * MAX_PROBES_PER_BATCH:
        lab.block("The fixed two-arm read budget does not match its compiled call count")
    config_map = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": LOAD_CONFIGMAP, "namespace": NAMESPACE},
        "data": {"marker": "A" * 65536,
                 "probe.py": Path(__file__).with_name("apf_probe.py").read_text(encoding="utf-8")},
    }
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": LOAD_ROLE, "namespace": NAMESPACE},
        "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                    "resourceNames": [LOAD_CONFIGMAP], "verbs": ["get"]}],
    }
    binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": LOAD_BINDING, "namespace": NAMESPACE},
        "subjects": [{"kind": "ServiceAccount", "name": SERVICE_ACCOUNT,
                      "namespace": NAMESPACE}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                    "name": LOAD_ROLE},
    }
    runner_pod = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": PROBE_POD, "namespace": NAMESPACE,
                     "labels": {"app": "saf-apf-bounded-probe"}},
        "spec": {
            "serviceAccountName": SERVICE_ACCOUNT,
            "automountServiceAccountToken": True,
            "activeDeadlineSeconds": 180,
            "restartPolicy": "Never",
            "terminationGracePeriodSeconds": 1,
            "securityContext": {
                "runAsNonRoot": True, "runAsUser": 65534,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [{
                "name": "probe", "image": PYTHON_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "-c", "import time; time.sleep(180)"],
                "env": [],
                "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                              "limits": {"cpu": "100m", "memory": "96Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False,
                                     "readOnlyRootFilesystem": True,
                                     "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [{"name": "fixture", "mountPath": "/fixture",
                                  "readOnly": True}],
            }],
            "volumes": [{"name": "fixture", "configMap": {
                "name": LOAD_CONFIGMAP,
                "items": [{"key": "probe.py", "path": "probe.py"}],
            }}],
        },
    }
    priority = {
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1",
        "kind": "PriorityLevelConfiguration",
        "metadata": {"name": LOAD_PRIORITY},
        "spec": {"type": "Limited", "limited": {
            "nominalConcurrencyShares": 1, "lendablePercent": 0,
            "borrowingLimitPercent": 0,
            "limitResponse": {"type": "Queue", "queuing": {
                "queues": 1, "handSize": 1,
                "queueLengthLimit": MAX_PROBES_PER_BATCH,
            }},
        }},
    }
    flow_schema = {
        "apiVersion": "flowcontrol.apiserver.k8s.io/v1", "kind": "FlowSchema",
        "metadata": {"name": LOAD_FLOW_SCHEMA},
        "spec": {
            "matchingPrecedence": 700,
            "distinguisherMethod": {"type": "ByUser"},
            "priorityLevelConfiguration": {"name": LOAD_PRIORITY},
            "rules": [{
                "subjects": [{"kind": "ServiceAccount",
                              "serviceAccount": {"name": SERVICE_ACCOUNT,
                                                  "namespace": NAMESPACE}}],
                "resourceRules": [{"verbs": ["get"], "apiGroups": [""],
                                   "resources": ["configmaps"],
                                   "namespaces": [NAMESPACE]}],
                "nonResourceRules": [],
            }],
        },
    }
    owned = [
        ("pod", PROBE_POD),
        ("flowschema", LOAD_FLOW_SCHEMA),
        ("prioritylevelconfiguration", LOAD_PRIORITY),
        ("rolebinding", LOAD_BINDING), ("role", LOAD_ROLE),
        ("configmap", LOAD_CONFIGMAP),
        ("serviceaccount", SERVICE_ACCOUNT),
    ]
    for kind, name in owned:
        if kind == "serviceaccount":
            continue  # Created and owned by the original 11-check fixture.
        existing = lab.kubectl("get", kind, name, "-o", "name", allow_failure=True)
        if existing.returncode == 0 and existing.stdout.strip():
            lab.block("Refusing to replace a pre-existing APF comparison fixture object")
    cleanup_ok = False
    metrics_evidence = {
        "scope": "only selected APF metrics for the owned FlowSchema/priority; serial snapshots",
        "probe_budget": PROBE_BUDGET,
        "requests_per_arm": MAX_PROBES_PER_BATCH,
        "original_case": original_metrics,
    }
    try:
        for obj in (config_map, role, binding, priority):
            lab.create(obj)
        lab.kubectl("apply", "-f", "-", payload=json.dumps(flow_schema), timeout=15)
        lab.kubectl("wait", "--for=condition=Dangling=false",
                    f"flowschema/{LOAD_FLOW_SCHEMA}", "--timeout=20s", timeout=28)
        ids = probe_identity_hashes(lab)
        runner_pod["spec"]["containers"][0]["env"] = [
            {"name": "EXPECTED_FLOW_UID_SHA256", "value": ids[0]},
            {"name": "EXPECTED_PRIORITY_UID_SHA256", "value": ids[1]},
        ]
        lab.create(runner_pod)
        lab.kubectl("wait", "--for=condition=Ready", f"pod/{PROBE_POD}",
                    "--timeout=45s", timeout=53)
        pod_info = json.loads(lab.kubectl("get", "pod", PROBE_POD, "-o", "json").stdout)
        pod_spec = pod_info.get("spec", {})
        pod_container = pod_spec.get("containers", [{}])[0]
        projection = any(
            any("serviceAccountToken" in source for source in volume.get("projected", {}).get("sources", []))
            for volume in pod_spec.get("volumes", [])
        )
        mounts = {item.get("mountPath") for item in pod_container.get("volumeMounts", [])}
        context = pod_spec.get("securityContext", {})
        container_security = pod_container.get("securityContext", {})
        probe_role_ok = (role["rules"] == [{"apiGroups": [""], "resources": ["configmaps"],
                                               "resourceNames": [LOAD_CONFIGMAP], "verbs": ["get"]}]
                         and binding["subjects"] == [{"kind": "ServiceAccount", "name": SERVICE_ACCOUNT,
                                                       "namespace": NAMESPACE}]
                         and binding["roleRef"] == {"apiGroup": "rbac.authorization.k8s.io",
                                                     "kind": "Role", "name": LOAD_ROLE})
        pod_profile_ok = (
            pod_spec.get("serviceAccountName") == SERVICE_ACCOUNT
            and pod_spec.get("automountServiceAccountToken") is True
            and projection
            and "/var/run/secrets/kubernetes.io/serviceaccount" in mounts
            and "/fixture" in mounts
            and context.get("runAsNonRoot") is True
            and context.get("runAsUser") == 65534
            and container_security.get("runAsNonRoot", context.get("runAsNonRoot")) is True
            and container_security.get("runAsUser", context.get("runAsUser")) == 65534
            and pod_container.get("image") == PYTHON_IMAGE
            and container_security.get("allowPrivilegeEscalation") is False
            and container_security.get("readOnlyRootFilesystem") is True
            and container_security.get("capabilities", {}).get("drop") == ["ALL"]
            and context.get("seccompProfile", {}).get("type") == "RuntimeDefault"
        )
        before_queue = bounded_probe_metrics(lab)
        seats = before_queue["seats"]
        seat_guard = seats is not None and 0 < seats <= 3 and seats < facts["apf_total_concurrency_limit"]
        fixture_ready = seat_guard and pod_profile_ok and probe_role_ok
        lab.check("positive", "The bounded APF reader has a small seat budget, exact GET scope, and projected nonroot identity",
                  fixture_ready, {"seat_budget_in_range": bool(seat_guard),
                                  "reader_pod_profile_valid": bool(pod_profile_ok),
                                  "role_binding_scope_exact": bool(probe_role_ok),
                                  "batch_cap": MAX_PROBES_PER_BATCH})
        queue_result = run_pod_probe(lab, "queue")
        after_queue = bounded_probe_metrics(lab)
        queue_wait_count = after_queue["wait_count"] - before_queue["wait_count"]
        queue_wait_sum = after_queue["wait_sum"] - before_queue["wait_sum"]
        metrics_evidence["queue"] = {
            "before": before_queue, "after": after_queue,
            "wait_count_delta": queue_wait_count,
            "wait_sum_seconds_delta": queue_wait_sum,
        }
        queue_ok = (
            queue_result["projection_available"]
            and queue_result["tls_verified_for_all"]
            and queue_result["all_responses_classified_to_fixture"]
            and queue_result["all_reads_succeeded_with_exact_fixture"]
            and queue_result["only_expected_statuses"]
            and queue_wait_count > 0 and queue_wait_sum > 0
        )
        lab.check("green", "Four bounded named inert reads complete through the owned APF queue with positive measured wait",
                  queue_ok, {"projected_identity_available": queue_result["projection_available"],
                             "trusted_tls_for_all_reads": queue_result["tls_verified_for_all"],
                             "all_reads_classified_to_owned_flow": queue_result["all_responses_classified_to_fixture"],
                             "all_reads_returned_exact_fixture": queue_result["all_reads_succeeded_with_exact_fixture"],
                             "positive_executed_wait_count_and_sum": bool(queue_wait_count > 0 and queue_wait_sum > 0),
                             "only_expected_http_statuses": queue_result["only_expected_statuses"]})

        set_load_priority_mode(lab, "Reject")
        before_reject = bounded_probe_metrics(lab)
        reject_result = run_pod_probe(lab, "reject")
        after_reject = bounded_probe_metrics(lab)
        reject_delta = (after_reject["concurrency_rejections"]
                        - before_reject["concurrency_rejections"])
        metrics_evidence["reject"] = {
            "before": before_reject, "after": after_reject,
            "concurrency_rejection_delta": reject_delta,
        }
        reject_ok = (
            reject_result["projection_available"]
            and reject_result["tls_verified_for_all"]
            and reject_result["all_responses_classified_to_fixture"]
            and reject_result["has_expected_rejection"]
            and reject_result["only_expected_statuses"]
            and reject_delta >= 1
        )
        lab.check("green", "A bounded owned read batch receives an APF concurrency-limit rejection",
                  reject_ok, {"projected_identity_available": reject_result["projection_available"],
                              "trusted_tls_for_all_reads": reject_result["tls_verified_for_all"],
                              "all_reads_classified_to_owned_flow": reject_result["all_responses_classified_to_fixture"],
                              "native_concurrency_rejection_observed": reject_result["has_expected_rejection"],
                              "native_rejection_counter_increased": bool(reject_delta >= 1),
                              "only_expected_http_statuses": reject_result["only_expected_statuses"]})
    finally:
        # Restore the disposable priority before removing its FlowSchema, then
        # delete only these exact names. Every operation has a short deadline.
        try:
            set_load_priority_mode(lab, "Queue")
        except Exception:
            pass
        for kind, name in owned:
            lab.kubectl("delete", kind, name, "--ignore-not-found=true",
                        timeout=12, allow_failure=True)
        absent = True
        for kind, name in owned:
            result = lab.kubectl("get", kind, name, "-o", "name",
                                 timeout=12, allow_failure=True)
            absent = absent and result.returncode != 0 and "NotFound" in result.stderr
        cleanup_ok = absent
        (lab.evidence / "apf-bounded-metrics.json").write_text(
            json.dumps(metrics_evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    lab.check("positive", "The bounded APF comparison restores and removes only its exact fixture objects",
              cleanup_ok, {"fixture_objects_absent": cleanup_ok,
                           "owned_object_count": len(owned)})


def observe_natural_critical_flows(lab):
    """Verify classifications for successful Lease writes from the fixture controllers."""
    node = f"{lab.cluster}-control-plane"
    leases = {
        "kubelet": (f"/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases/{node}",
                    ("system-node-high", "node-high")),
        "kube-scheduler": (LEASE_PATH, ("system-leader-election", "leader-election")),
    }
    command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
               f"kind-{lab.cluster}", "-n", "kube-system", "logs",
               f"pod/kube-apiserver-{node}", "-c", "kube-apiserver",
               "--since=45s", "--tail=450", "--limit-bytes=1400000"]
    matched = {name: set() for name in leases}
    metadata_shapes = set()
    deadline = time.monotonic() + 55
    while time.monotonic() < deadline:
        try:
            result = subprocess.run(command, env=lab.env, text=True, capture_output=True,
                                    timeout=12, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            lab.block(f"Could not read bounded local API request logs: {type(error).__name__}")
        if result.returncode:
            lab.block("Could not read bounded local API request logs")
        for line in result.stdout.splitlines():
            if '"HTTP"' not in line or "apf_fs=" not in line:
                continue
            fields = {
                k: quoted if quoted else bare
                for k, quoted, bare in re.findall(
                    r'(?:^|\s)(verb|URI|userAgent|resp|apf_fs|apf_pl)=(?:"((?:[^"\\]|\\.)*)"|(\S+))',
                    line,
                )
            }
            path = fields.get("URI", "").split("?", 1)[0]
            if path in {values[0] for values in leases.values()} or (
                path == "/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases"
                and fields.get("userAgent", "").startswith("kubelet/")
            ):
                metadata_shapes.add((fields.get("verb", ""), fields.get("resp", ""),
                                     fields.get("userAgent", "").split("/", 1)[0]))
            if fields.get("verb") not in ("PUT", "PATCH", "UPDATE") or fields.get("resp") != "200":
                continue
            for name, (expected_path, _) in leases.items():
                if path == expected_path and fields.get("userAgent", "").startswith(name + "/"):
                    matched[name].add((fields.get("apf_fs"), fields.get("apf_pl")))
        if all(matched.values()):
            break
        time.sleep(2)
    for name, (_, expected) in leases.items():
        observed = matched[name]
        if observed != {expected}:
            print(f"Lease log methods, statuses and client families: {sorted(metadata_shapes)}")
            print(f"{name} observed FlowSchema and priority pairs: {sorted(observed, key=repr)}")
            if name == "kubelet":
                lease = lab.kubectl(
                    "-n", "kube-node-lease", "get", "lease", node,
                    "-o", "jsonpath={.spec.renewTime}", allow_failure=True,
                )
                print(f"Fixture node Lease exists and has a renewal time: {lease.returncode == 0 and bool(lease.stdout)}")
        lab.check("positive", f"Completed native {name} Lease writes use the expected APF priority",
                  observed == {expected}, {"lease_write_observed": bool(observed),
                                           "flow_schema": expected[0], "priority": expected[1],
                                           "classification_matches": observed == {expected}})
