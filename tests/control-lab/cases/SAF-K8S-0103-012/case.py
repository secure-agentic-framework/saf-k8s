"""Exercise a controller permissions matrix on public infrastructure markers."""

import json
import time

SCOPE = "Real Kubernetes authorization for separate synthetic service, route and storage responsibility records."
RBAC = "rbac.authorization.k8s.io"
CLOUD = "fixture-cloud-service-controller"
STORAGE = "fixture-separate-storage-driver"
SERVICE = "fixture-approved-service"
ROUTE = "fixture-disabled-route"
DISK = "fixture-storage-driver-disk"
UNRELATED = "fixture-unrelated-service"


def resources(names, verbs):
    return [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": names, "verbs": verbs}]


def install(lab, subject, names, verbs):
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "Role", "metadata": {"name": subject},
                "rules": resources(names, verbs)})
    lab.create({"apiVersion": f"{RBAC}/v1", "kind": "RoleBinding", "metadata": {"name": subject},
                "roleRef": {"apiGroup": RBAC, "kind": "Role", "name": subject},
                "subjects": [{"apiGroup": RBAC, "kind": "User", "name": subject}]})


def call(lab, subject, verb, name=None, *arguments):
    command = ["--as", subject, verb, "configmaps"]
    if name is not None:
        command.append(name)
    result = lab.kubectl(*command, *arguments, allow_failure=True)
    if result.returncode == 0:
        return "allowed"
    if "Forbidden" in result.stderr:
        return "denied"
    lab.block("A fixture permissions request produced an unexpected API result")


def patch_marker(lab, subject, name, marker):
    return call(lab, subject, "patch", name, "--type=merge", "-p",
                json.dumps({"data": {"marker": marker}}))


def read_marker(lab, name):
    return json.loads(lab.kubectl("get", "configmap", name, "-o", "json").stdout)["data"]["marker"]


def run(lab):
    for name in (SERVICE, ROUTE, DISK, UNRELATED):
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                    "data": {"marker": "pending"}})
    install(lab, CLOUD, [SERVICE, ROUTE, DISK, UNRELATED], ["get", "patch", "delete"])
    install(lab, STORAGE, [DISK], ["get", "patch"])
    baseline = {"unneeded_route": call(lab, CLOUD, "get", ROUTE),
                "storage_owned_elsewhere": call(lab, CLOUD, "get", DISK),
                "unneeded_delete": call(lab, CLOUD, "delete", SERVICE, "--dry-run=server")}
    lab.check("red", "The broad modeled grant permits disabled, separately owned and unneeded operations",
              set(baseline.values()) == {"allowed"}, baseline)

    lab.kubectl("patch", "role", CLOUD, "--type=merge", "-p",
                json.dumps({"rules": resources([SERVICE], ["get", "patch"])}))
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if call(lab, CLOUD, "get", ROUTE) == "denied":
            break
        time.sleep(0.4)
    else:
        lab.block("Narrowed policy did not converge to the expected authorization")
    denied = {"disabled_route": call(lab, CLOUD, "get", ROUTE),
              "other_service": call(lab, CLOUD, "get", UNRELATED),
              "storage_owned_elsewhere": call(lab, CLOUD, "get", DISK),
              "unneeded_delete": call(lab, CLOUD, "delete", SERVICE, "--dry-run=server"),
              "namespace_inventory": call(lab, CLOUD, "get")}
    lab.check("green", "Effective policy denies disabled duties, unrelated records and unnecessary actions",
              set(denied.values()) == {"denied"}, denied)

    intended = {"service_update": patch_marker(lab, CLOUD, SERVICE, "service-reviewed"),
                "storage_update": patch_marker(lab, STORAGE, DISK, "storage-reviewed"),
                "storage_service_read": call(lab, STORAGE, "get", SERVICE)}
    retained = read_marker(lab, SERVICE) == "service-reviewed" and read_marker(lab, DISK) == "storage-reviewed"
    lab.check("positive", "The separate identities still perform their own enabled actions",
              intended == {"service_update": "allowed", "storage_update": "allowed", "storage_service_read": "denied"} and retained,
              {**intended, "owned_updates_retained": retained})
    (lab.evidence / "controller-permissions-observations.json").write_text(json.dumps({
        "broad_grant": baseline, "reviewed_denials": denied, "reviewed_duties": intended,
        "cloud_iam_tested": False,
    }, indent=2) + "\n")
