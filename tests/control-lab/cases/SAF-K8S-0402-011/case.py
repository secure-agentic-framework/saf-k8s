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
    "or validate federation, issuance, or revocation."
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
