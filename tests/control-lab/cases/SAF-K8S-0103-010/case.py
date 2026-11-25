"""Validate kubeadm leader leases and harmless, name-scoped Lease RBAC probes."""
import base64
from datetime import datetime, timezone
import json
import re
import subprocess
import time
import uuid
from pathlib import Path


SCOPE = (
    "Pinned Kubernetes v1.36.1 single-node kind fixture: verify enabled leader "
    "election flags, effective timing relationships, and changing renewTime values "
    "for kube-controller-manager and kube-scheduler without modifying either real "
    "leader Lease. Inspect kubeadm client certificate subjects and their bootstrap "
    "RBAC bindings. Synthetic service accounts exercise get/update against only "
    "three run-unique case-owned Leases in kube-system. A synthetic create rule "
    "demonstrates RBAC resourceNames cannot constrain top-level create. Cloud "
    "controller-manager, HA failover timing, and exempt administrator identities "
    "are outside this fixture."
)

SYSTEM_NAMESPACE = "kube-system"
PROBE_NAMESPACE = "saf-test"
LEASE_API_GROUP = "coordination.k8s.io"
COMPONENTS = {
    "kube-controller-manager": {
        "pod": "kube-controller-manager",
        "kubeconfig": "controller-manager.conf",
        "subject": "system:kube-controller-manager",
        "binding": "system:kube-controller-manager",
        "role": "system:kube-controller-manager",
        "lease": "kube-controller-manager",
    },
    "kube-scheduler": {
        "pod": "kube-scheduler",
        "kubeconfig": "scheduler.conf",
        "subject": "system:kube-scheduler",
        "binding": "system:kube-scheduler",
        "role": "system:kube-scheduler",
        "lease": "kube-scheduler",
    },
}
LEASE_TIMING_FLAGS = {
    "leader-elect-lease-duration": ("lease", "15s"),
    "leader-elect-renew-deadline": ("renew", "10s"),
    "leader-elect-retry-period": ("retry", "2s"),
}
LEASE_SUFFIX = uuid.uuid4().hex[:10]
LEASES = {
    "kube-controller-manager": f"saf-0103-cm-{LEASE_SUFFIX}",
    "kube-scheduler": f"saf-0103-sched-{LEASE_SUFFIX}",
    "create-unlisted": f"saf-0103-create-{LEASE_SUFFIX}",
}
IDENTITIES = {
    "kube-controller-manager": "saf-0103-controller-probe",
    "kube-scheduler": "saf-0103-scheduler-probe",
    "create-unlisted": "saf-0103-create-probe",
}


def kubectl(lab, *args, timeout=45, payload=None, allow_failure=False):
    return lab.command(
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
        f"kind-{lab.cluster}", f"--request-timeout={timeout - 5}s", *args,
        timeout=timeout, payload=payload, allow_failure=allow_failure,
    )


def duration_seconds(value):
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)", value)
    if not match:
        return None
    amount = float(match.group(1))
    multiplier = {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[match.group(2)]
    return amount * multiplier


def component_command(lab, component):
    pod = f"{COMPONENTS[component]['pod']}-{lab.cluster}-control-plane"
    result = kubectl(lab, "-n", SYSTEM_NAMESPACE, "get", f"pod/{pod}", "-o", "json")
    try:
        containers = json.loads(result.stdout)["spec"]["containers"]
        matches = [row for row in containers if row.get("name") == component]
        if len(matches) != 1:
            raise ValueError("container count")
        row = matches[0]
        command = row.get("command", [])
        argv = command + row.get("args", [])
    except (ValueError, KeyError, TypeError):
        lab.block(f"Could not inspect the {component} mirror Pod command")
    if not command or Path(command[0]).name != component:
        lab.block(f"Unexpected {component} process command")
    return argv


def flags(argv):
    found = {}
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg.startswith("--"):
            name, separator, value = arg[2:].partition("=")
            if name in ("leader-elect", *LEASE_TIMING_FLAGS.keys(), "leader-elect-resource-name"):
                if separator:
                    found.setdefault(name, []).append(value)
                elif i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                    found.setdefault(name, []).append(argv[i + 1])
                    i += 1
                else:
                    found.setdefault(name, []).append("true")
        i += 1
    return found


def cert_identity(lab, component):
    """Derive the public certificate CN and organizations, never exporting a key."""
    node = f"{lab.cluster}-control-plane"
    path = f"/etc/kubernetes/{COMPONENTS[component]['kubeconfig']}"
    result = subprocess.run(
        ["docker", "exec", node, "awk", '$1 == "client-certificate-data:" {print $2}', path],
        env=lab.env, capture_output=True, timeout=15,
    )
    if result.returncode:
        lab.block(f"Could not read the public certificate for {component}")
    try:
        cert = base64.b64decode(result.stdout.strip(), validate=True)
    except ValueError:
        lab.block(f"Invalid public certificate encoding for {component}")
    subject = subprocess.run(
        ["openssl", "x509", "-noout", "-subject", "-nameopt", "RFC2253"],
        env=lab.env, input=cert, capture_output=True, timeout=10,
    )
    if subject.returncode:
        lab.block(f"Could not verify the certificate subject for {component}")
    rendered = subject.stdout.decode("utf-8", errors="strict").strip()
    if rendered.startswith("subject="):
        rendered = rendered[len("subject="):]
    attributes = {}
    for field in rendered.split(","):
        key, separator, value = field.partition("=")
        if separator:
            attributes.setdefault(key.strip(), []).append(value.strip())
    common_names = attributes.get("CN", [])
    if len(common_names) != 1 or not re.fullmatch(r"system:[\w-]+", common_names[0]):
        lab.block(f"Could not verify the certificate subject for {component}")
    groups = sorted(set(attributes.get("O", [])) | {"system:authenticated"})
    return common_names[0], groups


def subject_access_review(lab, username, groups, verb, name=None):
    """Ask the local API authorizer about a resource request for a real subject."""
    attributes = {"namespace": SYSTEM_NAMESPACE, "verb": verb,
                  "group": LEASE_API_GROUP, "resource": "leases"}
    if name is not None:
        attributes["name"] = name
    review = {"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview",
              "spec": {"user": username, "groups": groups, "resourceAttributes": attributes}}
    result = kubectl(lab, "create", "-f", "-", "-o", "json", payload=json.dumps(review))
    status = json.loads(result.stdout).get("status", {})
    if status.get("evaluationError") or not isinstance(status.get("allowed"), bool):
        lab.block(f"SubjectAccessReview did not return an authorization decision for {verb}")
    return status["allowed"], status.get("reason", "")


def check_real_subject_effective_policy(lab):
    for component, spec in COMPONENTS.items():
        subject, groups = cert_identity(lab, component)
        other_name = next(row["lease"] for name, row in COMPONENTS.items() if name != component)
        roles = f"system::leader-locking-{component}"
        comparisons = {
            "own_get": ("get", spec["lease"]), "own_update": ("update", spec["lease"]),
            "other_get": ("get", other_name), "other_update": ("update", other_name),
            "collection_list": ("list", None), "collection_watch": ("watch", None),
            "top_level_create": ("create", None),
        }
        decisions = {label: subject_access_review(lab, subject, groups, verb, resource_name)
                     for label, (verb, resource_name) in comparisons.items()}
        attributed = all(f'Role "{roles}"' in decisions[label][1]
                         for label in ("other_get", "other_update"))
        allowed = {label: status for label, (status, _) in decisions.items()}
        lab.check("red", f"Stock {component} has broader effective access than its named lease rule",
                  subject == spec["subject"] and all(allowed.values()) and attributed,
                  {"certificate_subject_matches_expected": subject == spec["subject"],
                   "kube_system_lease_decisions": allowed,
                   "other_named_grant_from_builtin_namespace_role": attributed})


def has_rule(role, verbs, resource_names):
    for rule in role.get("rules", []):
        if (LEASE_API_GROUP in rule.get("apiGroups", [])
                and "leases" in rule.get("resources", [])
                and all(verb in rule.get("verbs", []) for verb in verbs)
                and rule.get("resourceNames", []) == resource_names):
            return True
    return False


def check_kubeadm_rbac(lab):
    for component, spec in COMPONENTS.items():
        subject, _groups = cert_identity(lab, component)
        binding = json.loads(kubectl(
            lab, "get", f"clusterrolebinding/{spec['binding']}", "-o", "json").stdout)
        role = json.loads(kubectl(
            lab, "get", f"clusterrole/{spec['role']}", "-o", "json").stdout)
        subjects = binding.get("subjects", [])
        subject_bound = any(
            row.get("kind") == "User" and row.get("name") == subject
            for row in subjects
        )
        expected = spec["subject"]
        role_ref = binding.get("roleRef", {})
        correct_binding = (role_ref.get("kind") == "ClusterRole"
                           and role_ref.get("name") == spec["role"] and subject_bound)
        lab.check(
            "green", f"{component} kubeadm certificate subject is bound to its bootstrap role",
            subject == expected and correct_binding,
            {"subject_matches_expected": subject == expected, "role_binding_matches_subject": correct_binding},
        )
        create_unscoped = has_rule(role, ["create"], [])
        get_update_scoped = has_rule(role, ["get", "update"], [spec["lease"]])
        lab.check(
            "green", f"{component} bootstrap role scopes Lease get/update to its lock name",
            get_update_scoped and create_unscoped,
            {"get_update_exact_name": get_update_scoped,
             "create_rule_unscoped": create_unscoped},
        )


def lease_json(name, holder):
    return {
        "apiVersion": "coordination.k8s.io/v1",
        "kind": "Lease",
        "metadata": {
            "name": name,
            "namespace": SYSTEM_NAMESPACE,
            "labels": {"saf-k8s-control": "SAF-K8S-0103-010", "saf-case-owned": "true"},
        },
        "spec": {
            "holderIdentity": holder,
            "leaseDurationSeconds": 30,
            "leaseTransitions": 0,
        },
    }


def scoped_role(name, verbs, names):
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": name, "namespace": SYSTEM_NAMESPACE},
        "rules": [{
            "apiGroups": [LEASE_API_GROUP], "resources": ["leases"],
            "verbs": verbs, "resourceNames": names,
        }],
    }


def role_binding(name, role_name, service_account):
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {"name": name, "namespace": SYSTEM_NAMESPACE},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": role_name},
        "subjects": [{"kind": "ServiceAccount", "name": service_account, "namespace": PROBE_NAMESPACE}],
    }


def create_service_account(lab, name):
    kubectl(lab, "-n", PROBE_NAMESPACE, "create", "serviceaccount", name)
    role_name = f"{name}-role"
    binding_name = f"{name}-binding"
    if name == IDENTITIES["create-unlisted"]:
        role = scoped_role(role_name, ["create"], [f"saf-0103-create-allowed-{LEASE_SUFFIX}"])
    else:
        owned = LEASES["kube-controller-manager" if "controller" in name else "kube-scheduler"]
        role = scoped_role(role_name, ["get", "update"], [owned])
    for resource in (role, role_binding(binding_name, role_name, name)):
        kubectl(lab, "create", "-f", "-", payload=json.dumps(resource))


def synthetic_kubectl(lab, identity, *args, allow_failure=False, payload=None):
    return kubectl(
        lab, "--as", f"system:serviceaccount:{PROBE_NAMESPACE}:{identity}",
        "--as-group=system:serviceaccounts", f"--as-group=system:serviceaccounts:{PROBE_NAMESPACE}",
        "--as-group=system:authenticated", *args, timeout=15,
        allow_failure=allow_failure, payload=payload,
    )


def prepare_synthetic_fixtures(lab):
    for key, name in list(LEASES.items())[:2]:
        kubectl(lab, "create", "-f", "-", payload=json.dumps(lease_json(name, f"fixture-{key}")))
    for identity in IDENTITIES.values():
        create_service_account(lab, identity)


def check_scoped_requests(lab):
    try:
        # Each component can read and update exactly its own synthetic Lease.
        for component in COMPONENTS:
            own = LEASES[component]
            other_component = "kube-scheduler" if component == "kube-controller-manager" else "kube-controller-manager"
            other = LEASES[other_component]
            client = IDENTITIES[component]
            got = synthetic_kubectl(lab, client, "-n", SYSTEM_NAMESPACE, "get", f"lease/{own}", "-o", "json")
            fixture = json.loads(got.stdout)
            fixture.setdefault("metadata", {}).setdefault("annotations", {})[
                "saf-k8s-control/renewed-by-probe"] = component
            updated = synthetic_kubectl(lab, client, "-n", SYSTEM_NAMESPACE, "replace", "-f", "-",
                                       payload=json.dumps(fixture))
            cross_get = synthetic_kubectl(lab, client, "-n", SYSTEM_NAMESPACE, "get", f"lease/{other}",
                                          "-o", "name", allow_failure=True)
            cross_obj = json.loads(kubectl(lab, "-n", SYSTEM_NAMESPACE, "get", f"lease/{other}", "-o", "json").stdout)
            cross_update_obj = dict(cross_obj)
            cross_update_obj.setdefault("metadata", {}).setdefault("annotations", {})[
                "saf-k8s-control/unauthorized-attempt"] = component
            cross_update = synthetic_kubectl(lab, client, "-n", SYSTEM_NAMESPACE, "replace", "-f", "-",
                                            payload=json.dumps(cross_update_obj), allow_failure=True)
            lab.check(
                "positive", f"{component} synthetic identity can get/update its exact case-owned Lease",
                bool(got.stdout) and updated.returncode == 0,
                {"own_get_succeeded": bool(got.stdout), "own_update_succeeded": updated.returncode == 0},
            )
            lab.check(
                "green", f"{component} synthetic identity is denied get/update on the other case-owned Lease",
                cross_get.returncode != 0 and cross_update.returncode != 0
                and all("Forbidden" in result.stderr for result in (cross_get, cross_update)),
                {"cross_name_get_denied": cross_get.returncode != 0,
                 "cross_name_update_denied": cross_update.returncode != 0,
                 "denial_is_forbidden": all("Forbidden" in result.stderr for result in (cross_get, cross_update))},
            )

        allowed_name = f"saf-0103-create-allowed-{LEASE_SUFFIX}"
        unlisted_name = LEASES["create-unlisted"]
        identity = IDENTITIES["create-unlisted"]

        def attempts():
            return [
                synthetic_kubectl(
                    lab, identity, "-n", SYSTEM_NAMESPACE, "create", "-f", "-", "--dry-run=server",
                    payload=json.dumps(lease_json(name, "synthetic-create-probe")), allow_failure=True,
                )
                for name in (allowed_name, unlisted_name)
            ]

        restricted = attempts()
        denied = all(item.returncode != 0 and "Forbidden" in item.stderr for item in restricted)
        lab.check("green", "A name-scoped create rule cannot authorize top-level Lease creation",
                  denied, {"listed_and_unlisted_names_denied": denied})

        create_role = scoped_role(f"{identity}-role", ["create"], [])
        kubectl(lab, "apply", "-f", "-", payload=json.dumps(create_role))
        unrestricted = attempts()
        allowed = all(item.returncode == 0 for item in unrestricted)
        lab.check("red", "Collection-scoped Lease create applies to both fixture names",
                  allowed, {"both_synthetic_dry_run_requests_allowed": allowed})
    finally:
        cleanup_synthetic(lab)


def cleanup_synthetic(lab):
    failures = []
    for name in LEASES.values():
        result = kubectl(lab, "-n", SYSTEM_NAMESPACE, "delete", f"lease/{name}",
                               "--ignore-not-found=true", allow_failure=True)
        failures.append(result.returncode == 0)
    for name in IDENTITIES.values():
        result = kubectl(lab, "-n", SYSTEM_NAMESPACE, "delete", f"rolebinding/{name}-binding",
                               "--ignore-not-found=true", allow_failure=True)
        failures.append(result.returncode == 0)
        result = kubectl(lab, "-n", SYSTEM_NAMESPACE, "delete", f"role/{name}-role",
                               "--ignore-not-found=true", allow_failure=True)
        failures.append(result.returncode == 0)
        result = kubectl(lab, "-n", PROBE_NAMESPACE, "delete", f"serviceaccount/{name}",
                               "--ignore-not-found=true", allow_failure=True)
        failures.append(result.returncode == 0)
    if not all(failures):
        lab.block("Could not confirm cleanup of case-owned Lease RBAC fixtures")


def observed_renew_time(lab, component):
    result = kubectl(
        lab, "-n", SYSTEM_NAMESPACE, "get", f"lease/{COMPONENTS[component]['lease']}",
        "-o", "jsonpath={.spec.renewTime}",
    )
    value = result.stdout.strip()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        lab.block(f"{component} leader Lease has no parseable renewTime")
    return parsed


def check_component_election_and_renewal(lab):
    timings = {}
    initial = {}
    for component, spec in COMPONENTS.items():
        parsed = flags(component_command(lab, component))
        leader_flags = parsed.get("leader-elect", [])
        elected = leader_flags in ([], ["true"])
        lock_name = parsed.get("leader-elect-resource-name", [spec["lease"]])
        values = {}
        for flag, (key, default) in LEASE_TIMING_FLAGS.items():
            entries = parsed.get(flag, [default])
            values[key] = duration_seconds(entries[0]) if len(entries) == 1 else None
        valid_timing = all(value is not None and value > 0 for value in values.values())
        valid_timing = valid_timing and values["retry"] < values["renew"] < values["lease"]
        lab.check(
            "green", f"{component} has enabled leader election and ordered positive lease timings",
            elected and lock_name == [spec["lease"]] and valid_timing,
            {"leader_election_enabled": elected, "expected_lock_name": lock_name == [spec["lease"]],
             "positive_retry_renew_lease_order": valid_timing,
             "effective_timing_seconds": values},
        )
        timings[component] = values
        initial[component] = observed_renew_time(lab, component)

    deadline = time.monotonic() + 24
    changed = {component: False for component in COMPONENTS}
    latest = dict(initial)
    while time.monotonic() < deadline and not all(changed.values()):
        time.sleep(2)
        for component in COMPONENTS:
            current = observed_renew_time(lab, component)
            if current != initial[component]:
                changed[component] = True
                latest[component] = current
    now = datetime.now(timezone.utc)
    for component, spec in COMPONENTS.items():
        age = (now - latest[component]).total_seconds()
        valid = changed[component] and 0 <= age < timings[component]["lease"]
        lab.check(
            "green", f"{component} leader Lease renewTime advances while the component is running",
            valid,
            {"renew_time_advanced": changed[component], "renew_time_is_within_lease_duration":
             0 <= age < timings[component]["lease"]},
        )


def run(lab):
    check_kubeadm_rbac(lab)
    check_real_subject_effective_policy(lab)
    check_component_election_and_renewal(lab)
    prepare_synthetic_fixtures(lab)
    check_scoped_requests(lab)
