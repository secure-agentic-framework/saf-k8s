"""Demonstrate admission of declared cross-environment static Secret fixtures."""

import json
import time


NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
KIND_VERSION = "v0.32.0"
KUBERNETES_VERSION = "v1.36.1"
POLICY = "saf-0402-011-static-cross-environment-secret"
BINDING = "saf-0402-011-static-cross-environment-secret-binding"
PROFILE_LABEL = "saf.example/environment-profile"
CLASS_LABEL = "saf.example/credential-scope"
STATIC_TYPE = "saf.example/static-credential"
CASE_LABEL = "saf.example/case-fixture"

PROFILES = {
    "training-local": "training-local",
    "inference-east": "inference-east",
    "inference-west": "inference-west",
}
TARGET_PROFILES = ("inference-east", "inference-west")

SCOPE = (
    "Fresh local Kind cluster on Kubernetes v1.36.1, using the digest-pinned official "
    "kindest/node image and Kind CLI v0.32.0. Three case-owned namespaces receive "
    "administrator-set profile labels: training-local, inference-east, and inference-west. "
    "A native ValidatingAdmissionPolicy rejects Secret CREATE and UPDATE requests in those "
    "namespaces when the Secret declares type saf.example/static-credential and label "
    "saf.example/credential-scope=cross-environment. Red probes show the same declared "
    "fixtures accepted before policy installation. Green probes show create denial with "
    "no object persistence and update denial with the original local Secret state preserved. "
    "A data-free local training Secret is permitted. Type, labels, and namespace profiles "
    "are explicit policy inputs, not proof of credential contents or provenance. This local "
    "case does not inventory other clusters or clouds, establish production label governance, "
    "or validate federation, issuance, or revocation. The fixture independently inventories "
    "declared case-owned records and compares their authorized removal with preserved local ones."
)


def kube(lab, namespace, *args, payload=None, allow_failure=False):
    """Run kubectl against only the framework-owned Kind context and chosen fixture ns."""
    return lab.command(
        "kubectl",
        "--kubeconfig",
        str(lab.kubeconfig),
        "--context",
        f"kind-{lab.cluster}",
        "--namespace",
        namespace,
        "--request-timeout=35s",
        *args,
        payload=payload,
        allow_failure=allow_failure,
    )


def secret(name, *, secret_type="Opaque", labels=None):
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": name, "labels": labels or {}},
        "type": secret_type,
    }


def declared_static_fixture(name, profile):
    return secret(
        name,
        secret_type=STATIC_TYPE,
        labels={
            CLASS_LABEL: "cross-environment",
            CASE_LABEL: "SAF-K8S-0402-011",
            "saf.example/source-profile": "training-local",
            "saf.example/target-profile": profile,
        },
    )


def namespace_profile(lab, namespace):
    result = kube(lab, "default", "get", "namespace", namespace, "-o", "json")
    document = json.loads(result.stdout)
    return document["metadata"]["labels"][PROFILE_LABEL]


def secret_version_uid(lab, namespace, name):
    result = kube(
        lab,
        namespace,
        "get",
        "secret",
        name,
        "-o",
        "go-template={{.metadata.resourceVersion}}/{{.metadata.uid}}",
    )
    return result.stdout.split("/", 1)


def secret_public_state(lab, namespace, name, label_key):
    """Read only Secret type and one metadata label; never request data/stringData."""
    template = ('go-template={{.type}}|{{with .metadata.labels}}'
                '{{with index . "' + label_key + '"}}{{.}}{{end}}{{end}}')
    result = kube(lab, namespace, "get", "secret", name, "-o", template)
    return result.stdout.split("|", 1)


def policy_denial(result):
    diagnostic = result.stdout + result.stderr
    return (result.returncode != 0 and POLICY in diagnostic
            and "declared cross-environment static Secret is prohibited" in diagnostic)


def run(lab):
    seed_records = {}
    local_seeds = {}
    kind_output = lab.command("kind", "version").stdout.strip()
    kind_pinned = kind_output.startswith(f"kind {KIND_VERSION} ")
    lab.check(
        "positive",
        f"Kind CLI is pinned to official {KIND_VERSION}",
        kind_pinned,
        {"kind_version_matches": kind_pinned},
    )
    server = json.loads(lab.kubectl("version", "-o", "json").stdout)
    server_pinned = server.get("serverVersion", {}).get("gitVersion") == KUBERNETES_VERSION
    lab.check(
        "positive",
        f"Kind API server is Kubernetes {KUBERNETES_VERSION}",
        server_pinned,
        {"kubernetes_version_matches": server_pinned},
    )

    # The framework supplies a fresh cluster. Keep profile labels under this fixture's
    # administrator setup, rather than trusting labels on Secret objects to select scope.
    for namespace, profile in PROFILES.items():
        lab.kubectl("create", "namespace", namespace)
        lab.kubectl("label", "namespace", namespace, f"{PROFILE_LABEL}={profile}")

    for namespace, profile in PROFILES.items():
        actual = namespace_profile(lab, namespace)
        lab.check(
            "positive",
            f"Case administrator assigns the {profile} namespace profile",
            actual == profile,
            {"profile_label_matches": actual == profile},
        )

    # Red: exact prohibited declarations are accepted before admission is installed.
    for namespace in TARGET_PROFILES:
        name = f"red-static-{namespace.removeprefix('inference-')}"
        result = kube(
            lab,
            namespace,
            "create",
            "-f",
            "-",
            "-o",
            "name",
            payload=json.dumps(declared_static_fixture(name, namespace)),
            allow_failure=True,
        )
        if result.returncode == 0:
            seed_records[(namespace, name)] = secret_metadata(lab, namespace, name)
        lab.check(
            "red",
            f"Declared cross-environment static Secret is accepted in {namespace} before policy",
            result.returncode == 0 and result.stdout.strip() == f"secret/{name}",
            {"pre_policy_create_accepted": result.returncode == 0},
        )

    red_update = declared_static_fixture("red-local-update", TARGET_PROFILES[0])
    kube(lab, TARGET_PROFILES[0], "create", "-f", "-", "-o", "name",
         payload=json.dumps(secret("red-local-update", secret_type=STATIC_TYPE)))
    original_version, _ = secret_version_uid(lab, TARGET_PROFILES[0], "red-local-update")
    red_update["metadata"]["resourceVersion"] = original_version
    changed = kube(lab, TARGET_PROFILES[0], "replace", "-f", "-", "-o", "name",
                   payload=json.dumps(red_update))
    _, stored_scope = secret_public_state(lab, TARGET_PROFILES[0], "red-local-update", CLASS_LABEL)
    seed_records[(TARGET_PROFILES[0], "red-local-update")] = secret_metadata(
        lab, TARGET_PROFILES[0], "red-local-update")
    lab.check("red", "The same label transition is accepted before policy",
              changed.returncode == 0 and stored_scope == "cross-environment",
              {"pre_policy_update_accepted": changed.returncode == 0})

    # Seed ordinary local Secrets for post-policy UPDATE challenges. They carry no data.
    for namespace in TARGET_PROFILES:
        name = f"update-local-{namespace.removeprefix('inference-')}"
        result = kube(
            lab,
            namespace,
            "create",
            "-f",
            "-",
            "-o",
            "name",
            payload=json.dumps(secret(name, secret_type=STATIC_TYPE)),
        )
        if result.returncode == 0:
            local_seeds[(namespace, name)] = secret_metadata(lab, namespace, name)
        lab.check(
            "positive",
            f"Data-free local Secret fixture is seeded in {namespace}",
            result.returncode == 0 and result.stdout.strip() == f"secret/{name}",
            {"local_secret_seeded": result.returncode == 0},
        )

    policy = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY},
        "spec": {
            "failurePolicy": "Fail",
            "matchConstraints": {
                "namespaceSelector": {
                    "matchExpressions": [
                        {
                            "key": PROFILE_LABEL,
                            "operator": "In",
                            "values": list(PROFILES.values()),
                        }
                    ]
                },
                "resourceRules": [
                    {
                        "apiGroups": [""],
                        "apiVersions": ["v1"],
                        "operations": ["CREATE", "UPDATE"],
                        "resources": ["secrets"],
                    }
                ],
            },
            "validations": [
                {
                    "expression": (
                        "object.type != 'saf.example/static-credential' || "
                        "!has(object.metadata.labels) || "
                        "!('saf.example/credential-scope' in object.metadata.labels) || "
                        "object.metadata.labels['saf.example/credential-scope'] != "
                        "'cross-environment'"
                    ),
                    "message": "declared cross-environment static Secret is prohibited",
                    "reason": "Forbidden",
                }
            ],
        },
    }
    binding = {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": BINDING},
        "spec": {"policyName": POLICY, "validationActions": ["Deny"]},
    }
    lab.create(policy)
    lab.create(binding)

    deadline = time.monotonic() + 30
    while True:
        readiness = kube(lab, TARGET_PROFILES[0], "create", "-f", "-", "-o", "name",
                         "--dry-run=server", payload=json.dumps(
                             declared_static_fixture("policy-readiness", TARGET_PROFILES[0])),
                         allow_failure=True)
        if policy_denial(readiness):
            break
        if readiness.returncode != 0:
            lab.block("Admission readiness failed for a reason other than the named policy")
        if time.monotonic() >= deadline:
            lab.block("The reviewed validating policy did not become effective")
        time.sleep(0.5)

    # Green CREATE: admission must name this policy and the rejected object must be absent.
    for namespace in TARGET_PROFILES:
        name = f"green-create-{namespace.removeprefix('inference-')}"
        result = kube(
            lab,
            namespace,
            "create",
            "-f",
            "-",
            "-o",
            "name",
            payload=json.dumps(declared_static_fixture(name, namespace)),
            allow_failure=True,
        )
        absent = kube(
            lab, namespace, "get", "secret", name, "-o", "name", "--ignore-not-found"
        )
        object_absent = absent.returncode == 0 and not absent.stdout.strip()
        denied_and_absent = policy_denial(result) and object_absent
        lab.check(
            "green",
            f"Admission denies declared static cross-environment Secret CREATE in {namespace}",
            denied_and_absent,
            {"named_policy_denial": policy_denial(result), "object_absent": object_absent},
        )

    # Green UPDATE: changing an allowed local Secret into a declared cross-environment
    # static Secret is rejected, and the pre-update type/labels remain stored.
    for namespace in TARGET_PROFILES:
        name = f"update-local-{namespace.removeprefix('inference-')}"
        resource_version, uid = secret_version_uid(lab, namespace, name)
        attempted = declared_static_fixture(name, namespace)
        attempted["metadata"]["resourceVersion"] = resource_version
        attempted["metadata"]["uid"] = uid
        result = kube(
            lab,
            namespace,
            "replace",
            "-f",
            "-",
            "-o",
            "name",
            payload=json.dumps(attempted),
            allow_failure=True,
        )
        after_type, after_scope = secret_public_state(lab, namespace, name, CLASS_LABEL)
        after_version, after_uid = secret_version_uid(lab, namespace, name)
        preserved = (after_type == STATIC_TYPE and after_scope == ""
                     and (after_version, after_uid) == (resource_version, uid))
        denied_and_preserved = policy_denial(result) and preserved
        lab.check(
            "green",
            f"Admission denies declared static cross-environment Secret UPDATE in {namespace}",
            denied_and_preserved,
            {
                "named_policy_denial": policy_denial(result),
                "original_local_state_preserved": preserved,
            },
        )

    # Positive: an unrelated, data-free local training Secret remains permitted.
    local_name = "positive-local-training-secret"
    local = secret(local_name, labels={"saf.example/environment": "training-local"})
    result = kube(
        lab,
        "training-local",
        "create",
        "-f",
        "-",
        "-o",
        "name",
        payload=json.dumps(local),
    )
    stored_type, stored_environment = secret_public_state(
        lab, "training-local", local_name, "saf.example/environment"
    )
    local_allowed = (
        result.returncode == 0
        and result.stdout.strip() == f"secret/{local_name}"
        and stored_type == "Opaque"
        and stored_environment == "training-local"
    )
    lab.check(
        "positive",
        "Unrelated data-free local training Secret remains permitted",
        local_allowed,
        {"local_secret_created_and_read_back": local_allowed},
    )


    run_inventory_supplement(lab, seed_records, local_seeds)


METADATA_KEYS = ("name", "uid", "type", "scope", "case_marker", "source_profile", "target_profile")
METADATA_COLUMNS = "|".join([
    "{{.metadata.name}}", "{{.metadata.uid}}", "{{.type}}",
    *('{{with .metadata.labels}}{{with index . "' + label + '"}}{{.}}{{end}}{{end}}' for label in
      (CLASS_LABEL, CASE_LABEL, "saf.example/source-profile", "saf.example/target-profile")),
])


def parse_metadata(lab, line):
    fields = line.split("|")
    if len(fields) != len(METADATA_KEYS):
        lab.block("Secret inventory rendered an unexpected metadata shape")
    return dict(zip(METADATA_KEYS, fields))


def secret_metadata(lab, namespace, name):
    output = kube(lab, namespace, "get", "secret", name,
                  "-o", "go-template=" + METADATA_COLUMNS).stdout.strip()
    return parse_metadata(lab, output)


def metadata_inventory(lab):
    template = "go-template={{range .items}}" + METADATA_COLUMNS + r'{{"\n"}}{{end}}'
    found = []
    for namespace in PROFILES:
        result = kube(lab, namespace, "get", "secrets", "-o", template)
        for line in result.stdout.splitlines():
            row = parse_metadata(lab, line)
            if row["type"] == STATIC_TYPE and row["scope"] == "cross-environment":
                found.append({"namespace": namespace, **row})
    return found


def run_inventory_supplement(lab, seed_records, local_seeds):
    expected_keys = {
        ("inference-east", "red-static-east"),
        ("inference-west", "red-static-west"),
        ("inference-east", "red-local-update"),
    }
    seeded_exact = set(seed_records) == expected_keys
    scanned = metadata_inventory(lab)
    by_key = {(row["namespace"], row["name"]): row for row in scanned}
    visible = (
        seeded_exact and set(by_key) == expected_keys
        and all(by_key[key]["uid"] == seed_records[key]["uid"]
                and by_key[key]["case_marker"] == "SAF-K8S-0402-011"
                and by_key[key]["source_profile"] == "training-local"
                and by_key[key]["target_profile"] == key[0]
                for key in expected_keys)
    )
    lab.check(
        "positive", "Metadata-only inventory still sees all three pre-policy fixture records after admission is active",
        visible,
        {"case_owned_namespaces_scanned": len(PROFILES),
         "seeded_records_visible": visible,
         "declared_static_records_found": len(scanned),
         "record_names": sorted(row["name"] for row in scanned),
         "data_fields_rendered": False},
    )

    # Delete only records whose namespace/name/UID and explicit case marker
    # still match the provenance captured before the policy was installed.
    provenance_valid = seeded_exact
    if provenance_valid:
        for key in sorted(expected_keys):
            current = secret_metadata(lab, key[0], key[1])
            seeded = seed_records[key]
            provenance_valid = provenance_valid and (
                current["uid"] == seeded["uid"]
                and current["case_marker"] == "SAF-K8S-0402-011"
                and current["type"] == STATIC_TYPE
                and current["scope"] == "cross-environment"
                and current["source_profile"] == "training-local"
                and current["target_profile"] == key[0]
            )
    if not provenance_valid:
        lab.block("Refusing fixture cleanup because exact metadata provenance changed")
    deleted = True
    for namespace, name in sorted(expected_keys):
        result = kube(lab, namespace, "delete", "secret", name,
                      "--wait=true", "--timeout=20s", allow_failure=True)
        deleted = deleted and result.returncode == 0
    lab.check(
        "positive", "Cleanup deletes only the three exact case-provenance records",
        deleted,
        {"owned_records_deleted": deleted, "deleted_record_count": len(expected_keys),
         "exact_names": sorted(name for _, name in expected_keys)},
    )

    remaining = metadata_inventory(lab)
    local_fixtures = []
    for key, seeded in local_seeds.items():
        current = secret_metadata(lab, key[0], key[1])
        local_fixtures.append(current["uid"] == seeded["uid"]
                              and current["type"] == "saf.example/static-credential"
                              and current["scope"] == "")
    training = secret_metadata(lab, "training-local", "positive-local-training-secret")
    training_type, training_profile = secret_public_state(
        lab, "training-local", "positive-local-training-secret", "saf.example/environment")
    local_fixtures.append(training_type == "Opaque" and training_profile == "training-local"
                          and training["case_marker"] == "")
    clear_with_permitted = not remaining and all(local_fixtures)
    lab.check(
        "positive", "Inventory is clear while approved local fixtures remain present",
        clear_with_permitted,
        {"prohibited_metadata_records_remaining": len(remaining),
         "approved_local_fixtures_present": all(local_fixtures),
         "data_fields_rendered": False},
    )
