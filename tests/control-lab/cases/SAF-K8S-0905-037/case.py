"""Exercise a governed manual halt and retain scoped forensic evidence."""
from hashlib import sha256
import json
import time

from fixtures import container

NS = "saf-test"
VAULT = "saf-halt-evidence"
WORKLOAD = "fixture-model"
BYSTANDER = "unrelated-model"
OPERATOR = "halt-responder"
INVESTIGATOR = "halt-investigator"
RECORD = "fixture-halt-record"
MARKER = "inert-emergency-fixture: event=health-review model=fixture"
MAX_SECONDS = 45
SCOPE = (
    "A fresh Kubernetes v1.36.1 Kind cluster runs two case-owned lightweight Deployments. "
    "A narrow role permits a named responder to read the intended Pod and logs and to scale "
    "only the designated Deployment. The responder retains hash-bound evidence in an "
    "immutable ConfigMap in a dedicated namespace before initiating the halt. An authorized "
    "investigator verifies it after the target Pod is removed. The measured bound is a lab "
    "fixture requirement. Real on-call response, incident evidence systems and long-term "
    "retention remain open."
)


def _identity(name):
    return f"--as=system:serviceaccount:{NS}:{name}"


def _json(lab, *args, **kwargs):
    return json.loads(lab.kubectl(*args, "-o", "json", **kwargs).stdout)


def _resource(lab, namespace, obj, *auth):
    return _json(lab, "-n", namespace, "create", "-f", "-", *auth, payload=json.dumps(obj))


def _setup_workload(lab, name):
    labels = {"app": name}
    workload = container("inert", command=["sh", "-ec", f"printf '%s\\n' '{MARKER}'; exec sleep 900"],
                         resources={"requests": {"cpu": "5m", "memory": "8Mi"},
                                    "limits": {"cpu": "80m", "memory": "32Mi"}})
    return lab.create({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name},
                       "spec": {"replicas": 1, "selector": {"matchLabels": labels},
                                "template": {"metadata": {"labels": labels},
                                             "spec": {"automountServiceAccountToken": False,
                                                      "terminationGracePeriodSeconds": 1, "containers": [workload]}}}})


def _ready_pod(lab, workload):
    lab.kubectl("rollout", "status", "deployment/" + workload, "--timeout=70s", timeout=75)
    items = _json(lab, "get", "pods", "-l", "app=" + workload)["items"]
    if len(items) != 1:
        lab.block("Expected one case-owned ready Pod")
    return items[0]


def _role(lab, namespace, identity, rules):
    api = "rbac.authorization.k8s.io/v1"
    _resource(lab, namespace, {"apiVersion": api, "kind": "Role", "metadata": {"name": identity}, "rules": rules})
    _resource(lab, namespace, {"apiVersion": api, "kind": "RoleBinding", "metadata": {"name": identity},
                               "subjects": [{"kind": "ServiceAccount", "name": identity, "namespace": NS}],
                               "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": identity}})


def _rule(group, resource, verbs, name=None):
    rule = {"apiGroups": [group], "resources": [resource], "verbs": verbs}
    if name is not None:
        rule["resourceNames"] = [name]
    return rule


def _setup_authority(lab, target):
    for name in (OPERATOR, INVESTIGATOR):
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": name}})
    _role(lab, NS, OPERATOR, [
        _rule("apps", "deployments", ["get"], WORKLOAD),
        _rule("apps", "deployments/scale", ["get", "patch", "update"], WORKLOAD),
        _rule("", "pods", ["get"], target),
        _rule("", "pods/log", ["get"], target),
    ])
    lab.kubectl("create", "namespace", VAULT)
    _role(lab, VAULT, OPERATOR, [_rule("", "configmaps", ["create"])])
    _role(lab, VAULT, INVESTIGATOR, [_rule("", "configmaps", ["get"], RECORD)])


def _halt(lab, name, actor, *, allow_failure=False):
    return lab.kubectl("scale", "deployment/" + name, "--replicas=0", _identity(actor),
                       allow_failure=allow_failure)


def _record(lab, target, request_stamp):
    manifest = _json(lab, "get", "deployment/" + WORKLOAD, _identity(OPERATOR))
    live = _json(lab, "get", "pod/" + target, _identity(OPERATOR))
    logs = lab.kubectl("logs", "pod/" + target, _identity(OPERATOR)).stdout
    exact = {"incident": "fixture-halt-001", "workload": WORKLOAD,
             "responder": OPERATOR, "capture_time_utc": request_stamp,
             "deployment_uid": manifest["metadata"]["uid"], "pod_uid": live["metadata"]["uid"],
             "pod_name": target, "before_replicas": manifest["spec"]["replicas"],
             "phase": live["status"]["phase"], "pod_template": manifest["spec"]["template"],
             "fixture_logs": logs}
    if exact["before_replicas"] != 1 or exact["phase"] != "Running" or logs.strip() != MARKER:
        lab.block("Incidence evidence did not describe the expected live fixture")
    raw = json.dumps(exact, sort_keys=True, separators=(",", ":"))
    checksum = sha256(raw.encode()).hexdigest()
    stored = _resource(lab, VAULT, {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": RECORD},
                                    "immutable": True, "data": {"evidence.json": raw, "sha256": checksum}},
                       _identity(OPERATOR))
    if stored.get("immutable") is not True or stored["data"]["sha256"] != checksum:
        lab.block("Evidence record did not persist before containment")
    return raw, checksum


def _await_halt(lab, end):
    while time.monotonic() < end:
        pods = _json(lab, "get", "pods", "-l", "app=" + WORKLOAD)["items"]
        deployment = _json(lab, "get", "deployment/" + WORKLOAD)
        if not pods and deployment["spec"]["replicas"] == 0 and deployment.get("status", {}).get("replicas", 0) == 0:
            return True
        time.sleep(0.45)
    return False


def run(lab):
    _setup_workload(lab, WORKLOAD)
    _setup_workload(lab, BYSTANDER)
    target = _ready_pod(lab, WORKLOAD)
    other = _ready_pod(lab, BYSTANDER)
    name = target["metadata"]["name"]
    _setup_authority(lab, name)

    ordinary = _halt(lab, WORKLOAD, "default", allow_failure=True)
    still_running = _ready_pod(lab, WORKLOAD)["metadata"]["uid"] == target["metadata"]["uid"]
    lab.check("red", "An unprivileged manual halt is forbidden and the exact target remains active",
              ordinary.returncode != 0 and "forbidden" in ordinary.stderr.lower() and still_running,
              {"forbidden": "forbidden" in ordinary.stderr.lower(), "same_pod_running": still_running})
    collateral = _halt(lab, BYSTANDER, OPERATOR, allow_failure=True)
    lab.check("green", "The responder cannot scale the unrelated Deployment",
              collateral.returncode != 0 and "forbidden" in collateral.stderr.lower(),
              {"forbidden": "forbidden" in collateral.stderr.lower()})

    start = time.monotonic()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    raw, checksum = _record(lab, name, stamp)
    _halt(lab, WORKLOAD, OPERATOR)
    halted = _await_halt(lab, start + MAX_SECONDS)
    elapsed = time.monotonic() - start
    lab.check("green", "Authorized manual invocation removes the workload Pods within the fixture response budget",
              halted and elapsed <= MAX_SECONDS,
              {"pods_absent_and_zero_replicas": halted, "within_response_bound": elapsed <= MAX_SECONDS,
               "maximum_seconds": MAX_SECONDS})

    stored = _json(lab, "-n", VAULT, "get", "configmap/" + RECORD, _identity(INVESTIGATOR))
    retained = stored["immutable"] and stored["data"]["sha256"] == checksum
    retained = retained and stored["data"]["evidence.json"] == raw and sha256(raw.encode()).hexdigest() == checksum
    forbidden = lab.kubectl("-n", VAULT, "get", "configmap/" + RECORD, _identity("default"), allow_failure=True)
    same_bystander = _ready_pod(lab, BYSTANDER)["metadata"]["uid"] == other["metadata"]["uid"]
    lab.check("positive", "The investigator reads matching pre-halt evidence and the unrelated workload stays active",
              retained and same_bystander and forbidden.returncode != 0 and "forbidden" in forbidden.stderr.lower(),
              {"evidence_digest_verified": retained, "unrelated_pod_unchanged": same_bystander,
               "default_identity_access_denied": "forbidden" in forbidden.stderr.lower()})
    (lab.evidence / "manual-halt.json").write_text(json.dumps(
        {"evidence": json.loads(raw), "sha256": checksum, "observed_seconds": elapsed,
         "maximum_seconds": MAX_SECONDS, "checks": lab.checks}, indent=2) + "\n")
