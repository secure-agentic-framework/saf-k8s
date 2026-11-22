"""Verify native DRA administrative request admission in a disposable cluster."""
import json


LABEL = "resource.kubernetes.io/admin-access"
ORDINARY = "saf-0801-ordinary"
MAINTENANCE = "saf-0801-maintenance"
USERS = {name: f"saf-k8s:0801:{name}" for name in ("ordinary", "maintenance", "platform")}
RESOURCES = ("resourceclaims", "resourceclaimtemplates")
SCOPE = (
    "Kubernetes v1.36.1 DRA adminAccess admission and namespace-label authorization. "
    "Only fixed isolated case namespaces and synthetic roles are created. Claims, claim "
    "templates and label-change probes use server dry-run. Actual GPU allocation, driver "
    "execution and legacy plugin controls remain separate."
)


def grant(lab, subject, rules, namespace=None):
    name = f"saf-0801-{subject}"
    prefix = "" if namespace else "Cluster"
    namespace_args = ("-n", namespace) if namespace else ()
    metadata = {"name": name}
    if namespace:
        metadata["namespace"] = namespace
    binding = {"roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": prefix + "Role", "name": name},
               "subjects": [{"kind": "User", "name": USERS[subject], "apiGroup": "rbac.authorization.k8s.io"}]}
    for kind, values in (("Role", {"rules": rules}), ("RoleBinding", binding)):
        body = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": prefix + kind,
                "metadata": metadata, **values}
        lab.kubectl(*namespace_args, "create", "-f", "-", payload=json.dumps(body))


def as_user(lab, subject, *args, payload=None):
    return lab.kubectl("--as", USERS[subject], "--as-group", "system:authenticated", *args,
                       payload=payload, allow_failure=True)


def request(kind, namespace, admin_access):
    device_request = {"name": "synthetic-request", "exactly": {
        "deviceClassName": "saf-0801-001.example.invalid", "adminAccess": admin_access}}
    claim_spec = {"devices": {"requests": [device_request]}}
    spec = claim_spec if kind == "ResourceClaim" else {"spec": claim_spec}
    return {"apiVersion": "resource.k8s.io/v1", "kind": kind,
            "metadata": {"name": "saf-0801-fixture", "namespace": namespace}, "spec": spec}


def create_dry_run(lab, subject, namespace, kind, admin_access):
    body = request(kind, namespace, admin_access)
    return as_user(lab, subject, "-n", namespace, "create", "-f", "-", "--dry-run=server",
                   "-o", "json", payload=json.dumps(body))


def label_patch(lab, subject, namespace, value):
    patch = json.dumps({"metadata": {"labels": {LABEL: value}}})
    return as_user(lab, subject, "patch", "namespace", namespace, "--type=merge", "--patch", patch,
                   "--dry-run=server", "-o", "json")


def namespace_label(lab, namespace):
    body = json.loads(lab.kubectl("get", "namespace", namespace, "-o", "json").stdout)
    return body["metadata"].get("labels", {}).get(LABEL)


def run(lab):
    for namespace in (ORDINARY, MAINTENANCE):
        lab.kubectl("create", "namespace", namespace)
    lab.kubectl("label", "namespace", MAINTENANCE, f"{LABEL}=true")
    permission = {"apiGroups": ["resource.k8s.io"], "resources": list(RESOURCES), "verbs": ["create"]}
    grant(lab, "ordinary", [permission], ORDINARY)
    grant(lab, "maintenance", [permission], MAINTENANCE)
    grant(lab, "platform", [{"apiGroups": [""], "resources": ["namespaces"],
                             "resourceNames": [ORDINARY, MAINTENANCE], "verbs": ["get", "patch"]}])

    for kind in ("ResourceClaim", "ResourceClaimTemplate"):
        ordinary = create_dry_run(lab, "ordinary", ORDINARY, kind, False)
        lab.check("positive", f"Ordinary namespace admits a non-admin {kind}", ordinary.returncode == 0,
                  {"admitted": ordinary.returncode == 0})
        denied = create_dry_run(lab, "ordinary", ORDINARY, kind, True)
        diagnostic = denied.stderr.lower()
        blocked_by_field = denied.returncode != 0 and "adminaccess" in diagnostic and "namespace" in diagnostic
        lab.check("red", f"Unapproved namespace rejects adminAccess for {kind}", blocked_by_field,
                  {"namespace_admission_denial": blocked_by_field})
        cross = create_dry_run(lab, "ordinary", MAINTENANCE, kind, True)
        forbidden = cross.returncode != 0 and "forbidden" in cross.stderr.lower()
        lab.check("green", f"Ordinary principal cannot create {kind} in the approved namespace", forbidden,
                  {"rbac_denied": forbidden})
        allowed = create_dry_run(lab, "maintenance", MAINTENANCE, kind, True)
        stored = json.loads(allowed.stdout) if allowed.returncode == 0 else {}
        spec = stored.get("spec", {})
        if kind == "ResourceClaimTemplate":
            spec = spec.get("spec", {})
        requests = spec.get("devices", {}).get("requests", [])
        admin_field = len(requests) == 1 and requests[0].get("exactly", {}).get("adminAccess") is True
        lab.check("green", f"The authorized maintenance dry run keeps adminAccess for {kind}", admin_field,
                  {"admitted": allowed.returncode == 0, "admin_access_preserved": admin_field})

    for namespace, value in ((ORDINARY, "true"), (MAINTENANCE, None)):
        denied = label_patch(lab, "ordinary", namespace, value)
        forbidden = denied.returncode != 0 and "forbidden" in denied.stderr.lower()
        lab.check("green", f"Ordinary identity cannot change the admin label in {namespace}", forbidden,
                  {"rbac_denied": forbidden})
        authorized = label_patch(lab, "platform", namespace, value)
        proposed = json.loads(authorized.stdout).get("metadata", {}).get("labels", {}) if authorized.returncode == 0 else {}
        lab.check("positive", f"Platform identity can propose the label change in {namespace}",
                  authorized.returncode == 0 and proposed.get(LABEL) == value,
                  {"admitted": authorized.returncode == 0, "proposed_label": proposed.get(LABEL)})

    actual_labels = {name: namespace_label(lab, name) for name in (ORDINARY, MAINTENANCE)}
    persisted = {name: len(json.loads(lab.kubectl("-n", name, "get", ",".join(RESOURCES),
                                                 "-o", "json").stdout)["items"])
                 for name in (ORDINARY, MAINTENANCE)}
    lab.check("positive", "Claim and Namespace dry runs leave the fixture state intact",
              actual_labels == {ORDINARY: None, MAINTENANCE: "true"} and not any(persisted.values()),
              {"live_labels": actual_labels, "persisted_claims_or_templates": persisted})
