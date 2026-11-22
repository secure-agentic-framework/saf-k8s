"""Check namespace-scoped RBAC against case-owned synthetic custom resources."""
import json
from pathlib import Path


HERE = Path(__file__).parent
NAMESPACE = "saf-0401-004"
OTHER_NAMESPACE = "saf-0401-004-outside"
GROUP = "saf-0401-004.example"
ML = f"system:serviceaccount:{NAMESPACE}:saf-0401-004-ml"
ADMIN = f"system:serviceaccount:{NAMESPACE}:saf-0401-004-admin"
SCOPE = (
    "Kubernetes v1.36.1 native RBAC on two case-owned namespaced CRDs in one synthetic API group. "
    "The ML service account receives create/get/list/watch/update/patch/delete only on modelruns "
    "in saf-0401-004; trainingruns, modelruns/status, and modelruns in another namespace are "
    "outside that grant. A distinct synthetic admin actor has an explicit namespaced role for "
    "both fixture resources. No operator controller, real AI CRD, admission policy, workload, "
    "or production identity mapping is present."
)


def request(lab, actor, *args, payload=None):
    return lab.kubectl(f"--as={actor}", *args, payload=payload, allow_failure=True)


def resource(kind, name, marker):
    return {
        "apiVersion": f"{GROUP}/v1",
        "kind": kind,
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {"marker": marker},
    }


def create(lab, actor, obj, *, dry_run=False):
    args = ["-n", obj["metadata"]["namespace"], "create", "-f", "-", "-o", "json"]
    if dry_run:
        args.append("--dry-run=server")
    return request(lab, actor, *args, payload=json.dumps(obj))


def get(lab, actor, kind, name, namespace=NAMESPACE):
    result = request(lab, actor, "-n", namespace, "get", kind, name, "-o", "json")
    return json.loads(result.stdout) if result.returncode == 0 else None


def replace(lab, actor, obj, *, dry_run=False):
    args = ["-n", obj["metadata"]["namespace"], "replace", "-f", "-", "-o", "json"]
    if dry_run:
        args.append("--dry-run=server")
    return request(lab, actor, *args, payload=json.dumps(obj))


def delete(lab, actor, kind, name, namespace=NAMESPACE, *, dry_run=False):
    # Make the DELETE request itself, with server-side dry run for the fixture.
    query = "?dryRun=All" if dry_run else ""
    url = f"/apis/{GROUP}/v1/namespaces/{namespace}/{kind}s/{name}{query}"
    return request(lab, actor, "delete", "--raw", url)


def forbidden(result):
    return result.returncode != 0 and "(Forbidden)" in result.stderr


def update_existing(lab, actor, kind, name, namespace=NAMESPACE, *, dry_run=False):
    obj = get(lab, actor, kind, name, namespace)
    if obj is None:
        return None
    return update_object(lab, actor, obj, dry_run=dry_run)


def update_object(lab, actor, obj, *, dry_run=False):
    obj.setdefault("spec", {})["marker"] = "updated-by-routine-fixture-operation"
    return replace(lab, actor, obj, dry_run=dry_run)


def run(lab):
    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("create", "namespace", OTHER_NAMESPACE)
    lab.kubectl("-n", NAMESPACE, "apply", "-f", str(HERE / "resources.yaml"))
    for crd in ("modelruns.saf-0401-004.example", "trainingruns.saf-0401-004.example"):
        lab.kubectl("wait", "--for=condition=Established", f"crd/{crd}", "--timeout=30s",
                    timeout=40)

    # Insecure baseline is intentionally limited to the synthetic API group and case namespace.
    red_create = create(lab, ML, resource("TrainingRun", "admin-trainingrun", "red"))
    red_update = update_existing(lab, ML, "trainingrun", "admin-trainingrun", dry_run=True)
    red_delete = delete(lab, ML, "trainingrun", "admin-trainingrun", dry_run=True)
    lab.check(
        "red",
        "The broad fixture grant allows create, update and delete on the second custom resource",
        red_create.returncode == 0 and red_update is not None and red_update.returncode == 0
        and red_delete.returncode == 0,
        {"create_live": red_create.returncode == 0,
         "update_server_dry_run": bool(red_update and red_update.returncode == 0),
         "delete_server_dry_run": red_delete.returncode == 0},
    )

    # Remove the additive broad grant before creating the narrow native Role/RoleBinding.
    lab.kubectl("-n", NAMESPACE, "delete", "rolebinding", "saf-0401-004-baseline")
    lab.kubectl("-n", NAMESPACE, "delete", "role", "saf-0401-004-baseline")
    lab.kubectl("-n", NAMESPACE, "apply", "-f", str(HERE / "policy.yaml"))

    allowed_create = create(lab, ML, resource("ModelRun", "allowed-modelrun", "allowed"))
    allowed_update = update_existing(lab, ML, "modelrun", "allowed-modelrun")
    allowed_delete = delete(lab, ML, "modelrun", "allowed-modelrun", dry_run=True)
    lab.check(
        "green",
        "The exact namespaced Role permits the ML actor to create, update, and delete the granted synthetic resource",
        allowed_create.returncode == 0 and allowed_update is not None
        and allowed_update.returncode == 0 and allowed_delete.returncode == 0
        and json.loads(allowed_update.stdout)["spec"]["marker"] == "updated-by-routine-fixture-operation",
        {"resource": "modelruns", "create_live": allowed_create.returncode == 0,
         "update_live": bool(allowed_update and allowed_update.returncode == 0),
         "delete_dry_run": allowed_delete.returncode == 0},
    )

    # The other synthetic resource and namespace-scoped endpoint are real existing objects,
    # so a denial cannot be attributed to missing CRDs or fixtures.
    admin_training = create(lab, ADMIN, resource("TrainingRun", "admin-positive", "admin"))
    outside_obj = resource("ModelRun", "outside-modelrun", "outside")
    outside_obj["metadata"]["namespace"] = OTHER_NAMESPACE
    outside_create = lab.kubectl("-n", OTHER_NAMESPACE, "create", "-f", "-", "-o", "json",
                                 payload=json.dumps(outside_obj))
    if admin_training.returncode != 0:
        lab.block("The distinct fixture administrator could not create the training resource")

    denied_create = create(lab, ML, resource("TrainingRun", "denied-trainingrun", "denied"))
    admin_training_obj = get(lab, ADMIN, "trainingrun", "admin-trainingrun")
    denied_update = update_object(lab, ML, admin_training_obj) if admin_training_obj else None
    denied_delete = delete(lab, ML, "trainingrun", "admin-trainingrun", dry_run=True)
    outside_fixture = json.loads(lab.kubectl(
        "-n", OTHER_NAMESPACE, "get", "modelrun", "outside-modelrun", "-o", "json"
    ).stdout)
    denied_outside_update = update_object(lab, ML, outside_fixture) if outside_fixture else None
    status_patch = request(
        lab, ML, "-n", NAMESPACE, "patch", "modelrun", "allowed-modelrun",
        "--subresource=status", "--type=merge", "-p", '{"status":{"phase":"forbidden"}}',
        "--dry-run=server", "-o", "json",
    )
    status_access = request(lab, ML, "-n", NAMESPACE, "auth", "can-i", "patch",
                            f"modelruns.{GROUP}/allowed-modelrun", "--subresource=status")
    can_patch_status = status_access.stdout.strip() == "yes"
    denied_boundaries = (
        forbidden(denied_create) and denied_update is not None and forbidden(denied_update)
        and forbidden(denied_delete) and "cannot delete resource" in denied_delete.stderr
        and denied_outside_update is not None
        and forbidden(denied_outside_update) and forbidden(status_patch)
        and status_access.returncode == 1 and status_access.stdout.strip() == "no"
    )
    lab.check(
        "green",
        "The same actor is forbidden from create, update, and delete on the other CRD, from update in another namespace, and from writing the status subresource",
        denied_boundaries,
        {"trainingruns_create": denied_create.stderr.strip(),
         "trainingruns_update": denied_update.stderr.strip() if denied_update else "fixture unavailable",
         "trainingruns_delete": denied_delete.stderr.strip(),
         "other_namespace_update": denied_outside_update.stderr.strip() if denied_outside_update else "fixture unavailable",
         "modelruns_status_attempt": status_patch.stderr.strip(),
         "modelruns_status_patch_authorized": can_patch_status},
    )

    crd_access = request(lab, ML, "auth", "can-i", "update",
                         "customresourcedefinitions.apiextensions.k8s.io/modelruns.saf-0401-004.example")
    lab.check("green", "The custom resource instance Role grants no CRD definition administration",
              crd_access.returncode == 1 and crd_access.stdout.strip() == "no",
              {"crd_definition_update_authorized": crd_access.stdout.strip() == "yes"})

    # The separate administrator has only a synthetic, namespace Role, and its positive
    # status-subresource operation proves that the denied endpoint is served and writable.
    admin_status = request(
        lab, ADMIN, "-n", NAMESPACE, "patch", "modelrun", "allowed-modelrun",
        "--subresource=status", "--type=merge", "-p", '{"status":{"phase":"admin-set"}}',
        "--dry-run=server", "-o", "json",
    )
    lab.check(
        "positive",
        "A distinct synthetic admin actor can use its explicit bounded status permission while the ML actor remains denied",
        admin_training.returncode == 0 and admin_status.returncode == 0,
        {"admin_create_trainingrun": admin_training.returncode == 0,
         "admin_status_server_dry_run": admin_status.returncode == 0,
         "ml_status_forbidden": forbidden(status_patch)},
    )
