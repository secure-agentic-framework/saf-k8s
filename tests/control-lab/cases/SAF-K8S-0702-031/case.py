"""Exercise scoped Kubernetes admission for synthetic promotion metadata."""
import hashlib
import json
from pathlib import Path
import time

from fixtures import container


HERE = Path(__file__).parent
NAMESPACE = "saf-0702-031-production"
OUTSIDE_NAMESPACE = "saf-0702-031-unenrolled"
POLICY = "saf-k8s-0702-031-promotion-classification"
BINDING = POLICY
CLASSIFICATION = "saf-k8s.example/data-classification"
STAGE = "saf-k8s.example/lifecycle-stage"
VALIDATED_FOR = "saf-k8s.example/classification-validated-for"
POLICY_VERSION = "saf-k8s.example/classification-policy-version"
ARTIFACT_DIGEST = "saf-k8s.example/approved-artifact-digest"
EXPECTED_CLASSIFICATION = "synthetic-confidential"
EXPECTED_POLICY_VERSION = "fixture-classification-v1.2.0"
APPROVED_DIGEST = "sha256:" + hashlib.sha256(b"saf-0702-031 approved synthetic artifact\n").hexdigest()
OTHER_DIGEST = "sha256:" + hashlib.sha256(b"saf-0702-031 other synthetic artifact\n").hexdigest()
DENIAL = "promotion metadata must match the target classification policy version"
APP_LABEL = "saf-k8s.example/case"
APP_VALUE = "saf-k8s-0702-031"
SCOPE = (
    "Kubernetes v1.36.1 ValidatingAdmissionPolicy CREATE and UPDATE checks for synthetic "
    "Deployments in a case-owned namespace. The admission decision compares classification, "
    "target, policy version and artifact digest claims with a separate administrator-supplied "
    "ConfigMap for one synthetic release. The digest is computed from an inert fixture. Actual "
    "production model registry integrity, signers, promotion pipelines and organization-wide "
    "policy enrollment require production evidence."
)


def deployment(name, *, classification=EXPECTED_CLASSIFICATION,
               validated_for="production", policy_version=EXPECTED_POLICY_VERSION,
               digest=APPROVED_DIGEST):
    labels = {APP_LABEL: APP_VALUE, STAGE: "production"}
    if classification is not None:
        labels[CLASSIFICATION] = classification
    annotations = {}
    if validated_for is not None:
        annotations[VALIDATED_FOR] = validated_for
    if policy_version is not None:
        annotations[POLICY_VERSION] = policy_version
    if digest is not None:
        annotations[ARTIFACT_DIGEST] = digest
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "labels": labels,
            "annotations": annotations,
        },
        "spec": {
            "replicas": 0,
            "selector": {"matchLabels": {APP_LABEL: APP_VALUE}},
            "template": {
                "metadata": {"labels": {APP_LABEL: APP_VALUE}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "containers": [container("inert-fixture")],
                },
            },
        },
    }


def server_create(lab, resource, namespace=NAMESPACE):
    return lab.kubectl(
        "create", "-f", "-", "-n", namespace, "--dry-run=server", "-o", "json",
        payload=json.dumps(resource), allow_failure=True,
    )


def admitted(result):
    return result.returncode == 0


def denied_by_policy(result):
    detail = result.stderr
    return (
        result.returncode != 0
        and "(Forbidden)" in detail
        and f"ValidatingAdmissionPolicy '{POLICY}'" in detail
        and f"binding '{BINDING}'" in detail
        and DENIAL in detail
    )


def observe(variant, result):
    return {
        "variant": variant,
        "admitted": admitted(result),
        "denied_by_expected_policy": denied_by_policy(result),
        "detail": result.stderr.strip(),
    }


def run(lab):
    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("label", "namespace", NAMESPACE,
                "saf-k8s.example/promotion-gate=required")
    lab.kubectl("create", "namespace", OUTSIDE_NAMESPACE)
    lab.kubectl("-n", NAMESPACE, "create", "configmap", "approved-synthetic-promotion",
                f"--from-literal=classification={EXPECTED_CLASSIFICATION}",
                "--from-literal=target=production",
                f"--from-literal=policyVersion={EXPECTED_POLICY_VERSION}",
                f"--from-literal=artifactDigest={APPROVED_DIGEST}")

    probes = [
        ("absent-classification", deployment("probe-absent", classification=None)),
        # A Kubernetes-valid label string with the wrong governed value reaches CEL admission.
        ("malformed-classification", deployment("probe-malformed", classification="Confidential")),
        ("outdated-policy-version", deployment(
            "probe-outdated", policy_version="fixture-classification-v1.1.0")),
        ("unapproved-target", deployment("probe-unapproved-stage", validated_for="staging")),
        ("unapproved-artifact", deployment("probe-unapproved-artifact", digest=OTHER_DIGEST)),
    ]
    red = [(variant, server_create(lab, resource)) for variant, resource in probes]
    lab.check(
        "red", "Without the case policy, all invalid promotion metadata probes reach the API",
        all(admitted(result) for _, result in red),
        [observe(variant, result) for variant, result in red],
    )

    lab.apply(HERE / "admission-policy.yaml")
    deadline = time.monotonic() + 20
    while True:
        green = [(variant, server_create(lab, resource)) for variant, resource in probes]
        if all(denied_by_policy(result) for _, result in green) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    lab.check(
        "green", "Enrolled promotion admission rejects invalid claims and unapproved artifact or target",
        all(denied_by_policy(result) for _, result in green),
        [observe(variant, result) for variant, result in green],
    )

    resource = deployment("permitted-promotion")
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(resource))
    saved = json.loads(lab.kubectl("-n", NAMESPACE, "get", "deployment", "permitted-promotion",
                                   "-o", "json").stdout)
    expected = resource["metadata"]["annotations"]
    recorded = saved["metadata"]["annotations"]
    lab.check("positive", "The API persists the Deployment for the independently approved fixture",
              all(recorded.get(key) == value for key, value in expected.items()),
              {"policy_version": recorded.get(POLICY_VERSION), "approved_digest": recorded.get(ARTIFACT_DIGEST)})

    tampered = lab.kubectl("-n", NAMESPACE, "patch", "deployment", "permitted-promotion",
                          "--type=merge", "-p", json.dumps({"metadata": {"annotations": {VALIDATED_FOR: None}}}),
                          allow_failure=True)
    lab.check("green", "The same deployment cannot remove its target validation on UPDATE",
              denied_by_policy(tampered), {"denied_by_expected_policy": denied_by_policy(tampered)})

    outside = deployment("unenrolled-invalid", classification="Confidential")
    outside["metadata"]["namespace"] = OUTSIDE_NAMESPACE
    outside_result = server_create(lab, outside, namespace=OUTSIDE_NAMESPACE)
    lab.check(
        "positive", "Namespace selector leaves the same malformed fixture outside the enrolled scope",
        admitted(outside_result), outside_result.stderr.strip() or "unenrolled namespace request admitted",
    )
