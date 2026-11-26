"""Read exact owned CoreDNS logs with one named, narrowly scoped Pod identity.

This source-only candidate is called after the original nine checks. It does not
emit log rows or ServiceAccount token material; the in-Pod consumer reports only
bounded booleans and a fixed count.
"""
import json
from pathlib import Path

from fixtures import container, pod

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
SA_NAME = "dns-log-collector"
ROLE_NAME = "dns-log-collector"
RB_NAME = "dns-log-collector"
CONFIG_NAME = "dns-log-collector"
JOB_NAME = "dns-log-collector"
OTHER_POD = "dns-observer"
LABELS = {"saf-lab.example/control": "SAF-K8S-0503-005",
          "saf-lab.example/fixture": "true"}
COLLECTOR_LABELS = {**LABELS, "saf-lab.example/component": "api-log-collector"}
PYTHON_IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)


def _apply(lab, obj):
    lab.kubectl("apply", "-f", "-", payload=json.dumps(obj))


def _resource(name, kind, **fields):
    return {"apiVersion": "v1", "kind": kind,
            "metadata": {"name": name, "namespace": NAMESPACE, "labels": LABELS}, **fields}


def _collector_script():
    return r'''import collections
import json
from pathlib import Path
import ssl
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://kubernetes.default.svc"
TOKEN_FILE = Path("/var/run/saf-api/token")
CA_FILE = "/var/run/saf-api/ca.crt"
MAX_LOG_BYTES = 65536
MAX_LINE_BYTES = 2048
EXPECTED_KEYS = {"qname", "qtype", "qclass", "proto", "rcode"}


def api_get(path, *, limit=16384):
    token = TOKEN_FILE.read_text(encoding="ascii").strip()
    request = urllib.request.Request(
        BASE + path, headers={"Authorization": "Bearer " + token,
                              "Accept": "application/json, text/plain"})
    context = ssl.create_default_context(cafile=CA_FILE)
    with urllib.request.urlopen(request, context=context, timeout=4) as response:
        if response.status != 200:
            return response.status, b""
        body = response.read(limit + 1)
        return response.status, body


def metadata(pod_name):
    escaped = urllib.parse.quote(pod_name, safe="")
    path = "/api/v1/namespaces/saf-test/pods/" + escaped
    status, body = api_get(path)
    if status != 200 or len(body) > 16384:
        return None
    obj = json.loads(body)
    meta = obj.get("metadata", {})
    return {"name": meta.get("name"), "namespace": meta.get("namespace"),
            "uid": meta.get("uid"), "labels": meta.get("labels", {}),
            "phase": obj.get("status", {}).get("phase")}


def logs(pod_name):
    escaped = urllib.parse.quote(pod_name, safe="")
    query = urllib.parse.urlencode({"container": "coredns", "timestamps": "true"})
    path = "/api/v1/namespaces/saf-test/pods/" + escaped + "/log?" + query
    status, body = api_get(path, limit=MAX_LOG_BYTES)
    if status != 200 or len(body) > MAX_LOG_BYTES:
        return status, []
    rows = []
    for line in body.decode("utf-8", errors="strict").splitlines():
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            return 413, []
        start = line.find("{")
        if start < 0:
            continue
        try:
            item = json.loads(line[start:])
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict) or not EXPECTED_KEYS <= item.keys():
            continue
        if set(item) != EXPECTED_KEYS:
            return 422, []
        row = {key: item[key] for key in sorted(EXPECTED_KEYS)}
        if not all(isinstance(value, str) for value in row.values()):
            return 422, []
        rows.append(row)
        if len(rows) > 32:
            return 413, []
    return status, rows


def denied_log_status(pod_name):
    escaped = urllib.parse.quote(pod_name, safe="")
    query = urllib.parse.urlencode({"container": "client", "timestamps": "true"})
    path = "/api/v1/namespaces/saf-test/pods/" + escaped + "/log?" + query
    token = TOKEN_FILE.read_text(encoding="ascii").strip()
    request = urllib.request.Request(
        BASE + path, headers={"Authorization": "Bearer " + token,
                               "Accept": "text/plain"})
    context = ssl.create_default_context(cafile=CA_FILE)
    try:
        response = urllib.request.urlopen(request, context=context, timeout=4)
    except urllib.error.HTTPError as error:
        # Do not read the denial body; report only its status.
        code = error.code
        error.close()
        return code
    else:
        # Unexpected authorization: close without reading or exposing any logs.
        response.close()
        return response.status


def parse_expected():
    obj = json.loads(Path("/fixture/expected.json").read_text(encoding="utf-8"))
    return collections.Counter(tuple(sorted(row.items())) for row in obj)


def main():
    expected = json.loads(Path("/fixture/targets.json").read_text(encoding="utf-8"))
    target = expected["coredns"]
    other = expected["other"]
    before = metadata(target["name"])
    other_before = metadata(other["name"])
    target_identity_ok = bool(
        before and before["name"] == target["name"]
        and before["namespace"] == "saf-test"
        and before["labels"].get("app") == "saf-dns-fixture"
        and before["phase"] == "Running"
        and before["uid"]
        and other_before and other_before["name"] == other["name"]
        and other_before["namespace"] == "saf-test" and other_before["uid"]
    )
    status, rows = logs(target["name"])
    after = metadata(target["name"])
    identity_stable = bool(target_identity_ok and after and after["uid"] == before["uid"]
                           and after["labels"].get("app") == "saf-dns-fixture")
    exact_rows = status == 200 and collections.Counter(
        tuple(sorted(row.items())) for row in rows
    ) == parse_expected()
    denied_status = denied_log_status(other["name"])
    result = {
        "collector_completed": True,
        "named_target_identity_valid": target_identity_ok,
        "target_identity_stable_during_read": identity_stable,
        "target_log_api_status_200": status == 200,
        "exact_case_fixture_rows": exact_rows,
        "observed_fixture_row_count": len(rows),
        "unrelated_owned_pod_log_status_403": denied_status == 403,
        "unrelated_status_class": denied_status,
    }
    print(json.dumps(result, sort_keys=True))


try:
    main()
except Exception:
    # Never print exception text, response bodies, API paths, token, or log rows.
    print(json.dumps({"collector_completed": False}, sort_keys=True))
'''


def _row(qname, qtype="A", rcode="NOERROR"):
    return {"qname": qname, "qtype": qtype, "qclass": "IN",
            "proto": "udp", "rcode": rcode}


def _expected_rows(extension):
    return [
        _row("signal.fixture.test."),
        _row("health.fixture.test."),
        _row(extension.QNAME_CONTROL, rcode="NXDOMAIN"),
        _row(extension.QNAME_CONTROL, rcode="NXDOMAIN"),
        _row(extension.QNAME_BURST, rcode="NXDOMAIN"),
        _row(extension.QNAME_BURST, rcode="NXDOMAIN"),
        _row(extension.QNAME_BURST, rcode="NXDOMAIN"),
        _row(extension.QNAME_LONG, rcode="NXDOMAIN"),
        _row(extension.QNAME_ENTROPY, rcode="NXDOMAIN"),
        _row(extension.QNAME_QTYPE, "TXT", rcode="NXDOMAIN"),
    ]


def run_api_log_collector(lab, core_pod, extension):
    """Execute one bounded API reader and return sanitized, fixed-predicate data."""
    core_name = core_pod["metadata"]["name"]
    expected = _expected_rows(extension)
    _apply(lab, {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": CONFIG_NAME, "namespace": NAMESPACE, "labels": LABELS},
        "data": {"collector.py": _collector_script(),
                 "expected.json": json.dumps(expected, sort_keys=True),
                 "targets.json": json.dumps({
                     "coredns": {"name": core_name},
                     "other": {"name": OTHER_POD},
                 }, sort_keys=True)},
    })
    _apply(lab, _resource(SA_NAME, "ServiceAccount"))
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": ROLE_NAME, "namespace": NAMESPACE, "labels": LABELS},
        "rules": [
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get"],
             "resourceNames": [core_name, OTHER_POD]},
            {"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"],
             "resourceNames": [core_name]},
        ],
    }
    _apply(lab, role)
    binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"name": RB_NAME, "namespace": NAMESPACE, "labels": LABELS},
        "subjects": [{"kind": "ServiceAccount", "name": SA_NAME, "namespace": NAMESPACE}],
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": ROLE_NAME},
    }
    _apply(lab, binding)
    role_observed = json.loads(lab.kubectl("get", "role", ROLE_NAME, "-o", "json").stdout)
    binding_observed = json.loads(lab.kubectl("get", "rolebinding", RB_NAME, "-o", "json").stdout)
    observed_subjects = [
        {key: subject.get(key) for key in ("kind", "name", "namespace")}
        for subject in binding_observed.get("subjects", [])
    ]
    policy_exact = role_observed.get("rules") == role["rules"] and (
        observed_subjects == [{"kind": "ServiceAccount", "name": SA_NAME,
                               "namespace": NAMESPACE}]
        and binding_observed.get("roleRef") == binding["roleRef"]
    )

    workload = pod(JOB_NAME, [container(
        "collector", image=PYTHON_IMAGE, command=["python", "/fixture/collector.py"],
        volumeMounts=[
            {"name": "fixture", "mountPath": "/fixture", "readOnly": True},
            {"name": "api-access", "mountPath": "/var/run/saf-api", "readOnly": True},
        ],
        resources={"requests": {"cpu": "10m", "memory": "32Mi"},
                   "limits": {"cpu": "100m", "memory": "64Mi"}},
    )],
        serviceAccountName=SA_NAME,
        automountServiceAccountToken=False,
        activeDeadlineSeconds=35,
        volumes=[
            {"name": "fixture", "configMap": {"name": CONFIG_NAME}},
            {"name": "api-access", "projected": {"sources": [
                {"serviceAccountToken": {"path": "token", "expirationSeconds": 600}},
                {"configMap": {"name": "kube-root-ca.crt",
                               "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
            ]}},
        ])
    _apply(lab, {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": JOB_NAME, "namespace": NAMESPACE, "labels": COLLECTOR_LABELS},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 35,
                 "template": {"metadata": {"labels": COLLECTOR_LABELS}, "spec": workload["spec"]}},
    })
    try:
        lab.kubectl("wait", "--for=condition=Complete", f"job/{JOB_NAME}",
                    "--timeout=45s", timeout=55)
        observed = json.loads(lab.kubectl("logs", f"job/{JOB_NAME}", "-c", "collector").stdout)
        actual_service_account = lab.kubectl(
            "get", "pods", "-l", "saf-lab.example/component=api-log-collector",
            "-o", "jsonpath={.items[0].spec.serviceAccountName}",
        ).stdout.strip()
    finally:
        # Deleting the Job removes its Pod and invalidates its bound token before
        # the RBAC identity and mounted fixture ConfigMap are discarded.
        for kind, name in (("job", JOB_NAME), ("rolebinding", RB_NAME),
                           ("role", ROLE_NAME), ("serviceaccount", SA_NAME),
                           ("configmap", CONFIG_NAME)):
            cleanup = lab.kubectl("delete", kind, name, "--ignore-not-found=true", "--wait=true",
                                  "--timeout=5s", timeout=10, allow_failure=True)
            if cleanup.returncode:
                lab.block(f"Could not confirm cleanup of case-owned {kind}/{name}")
    observed["exact_named_rbac_policy"] = policy_exact
    observed["named_service_account"] = actual_service_account == SA_NAME
    # Only bounded sanitized fields leave the API-reading Pod; never retain raw
    # DNS logs, token content, API response text, or per-run UIDs.
    (lab.evidence / "dns-api-log-collector-evidence.json").write_text(
        json.dumps(observed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return observed
