"""Exercise least-privilege native RBAC on synthetic ConfigMaps."""
from pathlib import Path

HERE = Path(__file__).parent
NAMESPACE = "saf-0401-001"
OTHER_NAMESPACE = "saf-0401-001-outside"
SERVICE_ACCOUNT = "saf-0401-001-reader"
SUBJECT = f"system:serviceaccount:{NAMESPACE}:{SERVICE_ACCOUNT}"
TARGET = "saf-0401-001-required-config"
OTHER = "saf-0401-001-unneeded-config"
OUTSIDE = "saf-0401-001-outside-config"

SCOPE = (
    "Kubernetes v1.36.1 native RBAC for one synthetic ServiceAccount and three "
    "case-owned ConfigMaps. A broad namespace Role/RoleBinding baseline permits "
    "get, list, watch, update, patch and delete on every ConfigMap in its namespace. "
    "The corrected Role permits only get on the exact required ConfigMap in "
    f"{NAMESPACE}. Ordinary API requests are issued as the synthetic subject. "
    "No built-in role is edited. ClusterRoles, ClusterRoleBindings, other subjects, "
    "admission policies, production identities and real data are outside this case."
)


def request(lab, *args, namespace=NAMESPACE, **kwargs):
    return lab.kubectl("--as", SUBJECT, "-n", namespace, *args,
                       allow_failure=True, **kwargs)


def forbidden(result):
    return result.returncode != 0 and "(Forbidden)" in result.stderr


def read(lab, name, namespace=NAMESPACE):
    return request(lab, "get", "configmap", name,
                   "-o", "jsonpath={.data.marker}", namespace=namespace)


def run(lab):
    # All fixtures and permissions belong to this disposable case.
    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("create", "namespace", OTHER_NAMESPACE)
    lab.kubectl("-n", NAMESPACE, "apply", "-f", str(HERE / "resources.yaml"))
    lab.kubectl("-n", OTHER_NAMESPACE, "apply", "-f", str(HERE / "outside.yaml"))

    # The red baseline is broad only over ConfigMaps in this case namespace.
    lab.kubectl("-n", NAMESPACE, "apply", "-f", str(HERE / "broad-baseline.yaml"))
    broad_other = read(lab, OTHER)
    broad_list = request(lab, "get", "configmaps", "-o", "name")
    broad_patch = request(
        lab, "patch", "configmap", TARGET, "--type=merge",
        "-p", '{"metadata":{"annotations":{"saf-k8s.example/case":"red"}}}',
        "--dry-run=server", "-o", "name",
    )
    lab.check(
        "red",
        "The broad baseline authorizes an unrelated read, collection list, and unneeded patch on the required ConfigMap",
        broad_other.returncode == 0 and broad_list.returncode == 0
        and broad_patch.returncode == 0,
        {"unneeded_named_get": broad_other.returncode == 0,
         "unfiltered_list": broad_list.returncode == 0,
         "unneeded_named_patch_dry_run": broad_patch.returncode == 0},
    )

    lab.kubectl("-n", NAMESPACE, "apply", "-f", str(HERE / "least-privilege.yaml"))
    extra = read(lab, OTHER)
    lab.check("red", "A narrow binding cannot remove access still granted by another binding",
              extra.returncode == 0 and extra.stdout == OTHER,
              {"unneeded_access_retained_while_both_bindings_exist": extra.returncode == 0})

    # Remove the broad grant to make the narrower effective policy take effect.
    lab.kubectl("-n", NAMESPACE, "delete", "rolebinding", "saf-0401-001-broad")
    lab.kubectl("-n", NAMESPACE, "delete", "role", "saf-0401-001-broad")

    target = read(lab, TARGET)
    other_get = read(lab, OTHER)
    outside_get = read(lab, OUTSIDE, namespace=OTHER_NAMESPACE)
    list_all = request(lab, "get", "configmaps", "-o", "name")
    patch_other = request(
        lab, "patch", "configmap", TARGET, "--type=merge",
        "-p", '{"metadata":{"annotations":{"saf-k8s.example/case":"green"}}}',
        "--dry-run=server", "-o", "name",
    )
    lab.check(
        "green",
        "The corrected Role permits only the named get in its namespace and denies other names, namespaces, list, and patch",
        target.returncode == 0 and target.stdout == TARGET
        and forbidden(other_get) and forbidden(outside_get)
        and forbidden(list_all) and forbidden(patch_other)
        and "cannot patch resource" in patch_other.stderr,
        {"required_named_get": target.returncode == 0 and target.stdout == TARGET,
         "unneeded_named_get_forbidden": forbidden(other_get),
         "other_namespace_get_forbidden": forbidden(outside_get),
         "collection_list_forbidden": forbidden(list_all),
         "unneeded_named_patch_forbidden": forbidden(patch_other)},
    )

    # This exact ordinary GET is the required permitted operation after correction.
    permitted = read(lab, TARGET)
    lab.check(
        "positive",
        "The synthetic reader can still read its exact required ConfigMap",
        permitted.returncode == 0 and permitted.stdout == TARGET,
        {"namespace": NAMESPACE, "verb": "get", "resource": "configmaps",
         "name": TARGET, "marker_matches": permitted.stdout == TARGET},
    )
