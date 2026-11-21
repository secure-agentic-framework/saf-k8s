"""Check API Priority and Fairness classification for a synthetic identity."""
import json
import re
import subprocess


NAMESPACE = "saf-test"
SERVICE_ACCOUNT = "saf-apf-probe"
SYNTHETIC_USER = f"system:serviceaccount:{NAMESPACE}:{SERVICE_ACCOUNT}"
CUSTOM_FLOW_SCHEMA = "saf-apf-exact-subject"
CUSTOM_PRIORITY = "saf-apf-limited"
LEASE_PATH = "/apis/coordination.k8s.io/v1/namespaces/kube-system/leases/kube-scheduler"

SCOPE = (
    "A local Kubernetes v1.36.1 kind API server only. Use four ordinary GET /version "
    "requests and two named kube-scheduler Lease requests total, before and "
    "after a narrow FlowSchema. Capture only APF classification response headers "
    "and bounded response identity. No contention, load, rejection, or queue behavior "
    "is induced. This does not assess production or managed control planes, traffic "
    "under load, tenant fairness, or provider defaults."
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
            "limitResponse": {"type": "Reject"},
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

    after = classification(lab, as_user=SYNTHETIC_USER)
    lab.check(
        "green",
        "The exact ServiceAccount and GET /version request route to the dedicated limited priority",
        after == {"flow_schema": CUSTOM_FLOW_SCHEMA, "priority_level": CUSTOM_PRIORITY},
        after,
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
