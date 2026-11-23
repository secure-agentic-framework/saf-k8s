"""Bind AI workload classification claims to a named registry record at admission."""
import hashlib
import json
from pathlib import Path
import time

from fixtures import container


HERE = Path(__file__).resolve().parent
REGISTRY_FIXTURE = HERE / "fixtures.json"
NAMESPACE = "saf-test"
REGISTRY_NAME = "saf-0905-001-classification-registry-v1"
POLICY = "saf-0905-001-registry-classification"
BINDING = POLICY
GROUP = "classification.saf-lab.example"
VERSION = "v1"
PLURAL = "aisystemclassifications"
KIND = "AISystemClassificationRegistry"
AI_MARKER = "saf-lab.example/ai-workload"
CLASS_LABEL = "ai.kais.io/update-model"
REGISTRY_ANNOTATION = "ai.saf.example/registry-record"
SYSTEM_ANNOTATION = "ai.saf.example/system-id"
PROFILE_ANNOTATION = "ai.saf.example/control-profile"
DENIAL = "AI deployment classification and profile must match the named registry record"
REGISTRY_FIXTURE_DATA = json.loads(REGISTRY_FIXTURE.read_text(encoding="utf-8"))
RECORDS = REGISTRY_FIXTURE_DATA["systems"]
SCOPE = (
    "Kubernetes v1.36.1 native ValidatingAdmissionPolicy CREATE and UPDATE checks for Deployments in "
    "the runner's saf-test namespace. A case-owned cluster-scoped "
    "classification.saf-lab.example/v1 AISystemClassificationRegistry named "
    f"{REGISTRY_NAME} is the policy parameter and maps two synthetic system IDs to the "
    "standard lifecycle classifications and profile IDs. Admission compares the workload's "
    "classification label and explicit registry, system, and profile annotations with that "
    "stored record. One fixed incomplete AI Deployment is stored and dry-run admitted before "
    "policy, then the identical request is denied after policy; matching train-verify-lock and "
    "continuous-learning Deployments and an unscoped benign Deployment are stored. Human "
    "classification quality, real registry authority and change control, organization-wide "
    "policy enrollment, and efficacy of the assigned profiles are outside this fixture."
)


def registry_crd():
    return {
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {"name": f"{PLURAL}.{GROUP}"},
        "spec": {
            "group": GROUP,
            "scope": "Cluster",
            "names": {"plural": PLURAL, "singular": "aisystemclassification",
                      "kind": KIND, "shortNames": ["aiscr"]},
            "versions": [{
                "name": VERSION, "served": True, "storage": True,
                "schema": {"openAPIV3Schema": {
                    "type": "object",
                    "required": ["spec"],
                    "properties": {"spec": {
                        "type": "object",
                        "required": ["registryVersion", "systems"],
                        "properties": {
                            "registryVersion": {"type": "string", "minLength": 1},
                            "systems": {
                                "type": "object", "minProperties": 1,
                                "additionalProperties": {
                                    "type": "object",
                                    "required": ["classification", "profile"],
                                    "properties": {
                                        "classification": {"type": "string", "minLength": 1},
                                        "profile": {"type": "string", "minLength": 1},
                                    },
                                },
                            },
                        },
                    }},
                }},
            }],
        },
    }


def registry_object():
    return {
        "apiVersion": f"{GROUP}/{VERSION}", "kind": KIND,
        "metadata": {"name": REGISTRY_NAME,
                     "labels": {"saf-lab.example/control": "SAF-K8S-0905-001"}},
        "spec": {"registryVersion": REGISTRY_FIXTURE_DATA["registry_version"],
                 "systems": RECORDS},
    }


def deployment(name, *, system_id=None, classification=None, profile=None,
               registry=REGISTRY_NAME, ai=True):
    labels = {"app.kubernetes.io/name": name}
    annotations = {}
    if ai:
        labels[AI_MARKER] = "true"
        if classification is not None:
            labels[CLASS_LABEL] = classification
        for key, value in ((REGISTRY_ANNOTATION, registry),
                           (SYSTEM_ANNOTATION, system_id),
                           (PROFILE_ANNOTATION, profile)):
            if value is not None:
                annotations[key] = value
    return {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": labels, "annotations": annotations},
        "spec": {
            "replicas": 0,
            "selector": {"matchLabels": {"app.kubernetes.io/name": name}},
            "template": {"metadata": {"labels": labels},
                         "spec": {"automountServiceAccountToken": False,
                                  "containers": [container("inert-fixture")]}},
        },
    }


def policy_object():
    # CEL first proves each map key exists, so later indexed access is defined.
    annotations = "object.metadata.annotations"
    labels = "object.metadata.labels"
    system = f'{annotations}["{SYSTEM_ANNOTATION}"]'
    profile = f'{annotations}["{PROFILE_ANNOTATION}"]'
    expression = " && ".join([
        "params != null",
        f'has({labels}) && "{AI_MARKER}" in {labels} && {labels}["{AI_MARKER}"] == "true"',
        f'has({annotations}) && "{REGISTRY_ANNOTATION}" in {annotations}',
        f'"{SYSTEM_ANNOTATION}" in {annotations}',
        f'"{PROFILE_ANNOTATION}" in {annotations}',
        f'"{CLASS_LABEL}" in {labels}',
        f'{annotations}["{REGISTRY_ANNOTATION}"] == params.metadata.name',
        f'{system} in params.spec.systems',
        f'{labels}["{CLASS_LABEL}"] == params.spec.systems[{system}].classification',
        f'params.spec.systems[{system}].profile == {profile}',
        f'"{CLASS_LABEL}" in object.spec.template.metadata.labels',
        f'object.spec.template.metadata.labels["{CLASS_LABEL}"] == {labels}["{CLASS_LABEL}"]',
    ])
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY},
        "spec": {
            "failurePolicy": "Fail",
            "paramKind": {"apiVersion": f"{GROUP}/{VERSION}", "kind": KIND},
            "matchConstraints": {"resourceRules": [{
                "apiGroups": ["apps"], "apiVersions": ["v1"],
                "operations": ["CREATE", "UPDATE"], "resources": ["deployments"],
            }]},
            "matchConditions": [{"name": "marked-ai-deployment",
                                  "expression": (f'has(object.metadata.labels) && '
                                                 f'"{AI_MARKER}" in object.metadata.labels && '
                                                 f'object.metadata.labels["{AI_MARKER}"] == "true"')}],
            "validations": [{"expression": expression, "message": DENIAL,
                             "reason": "Forbidden"}],
        },
    }


def binding_object():
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": BINDING},
        "spec": {"policyName": POLICY,
                 "paramRef": {"name": REGISTRY_NAME,
                              "parameterNotFoundAction": "Deny"},
                 "validationActions": ["Deny"],
                 "matchResources": {"namespaceSelector": {"matchLabels": {
                     "saf-lab.example/classification-verified": "true"}}}},
    }


def submit(lab, item, *, dry_run=False):
    args = ["create", "-f", "-", "-n", NAMESPACE]
    if dry_run:
        args.append("--dry-run=server")
    return lab.kubectl(*args, "-o", "json", payload=json.dumps(item),
                       allow_failure=dry_run)


def patch_incomplete(lab, name):
    # A no-op merge patch sends the same UPDATE request before and after policy;
    # server-side dry-run leaves the stored incomplete Deployment untouched.
    patch = {"metadata": {"labels": {AI_MARKER: "true"}}}
    return lab.kubectl("patch", "deployment", name, "--type=merge", "-p",
                       json.dumps(patch, sort_keys=True), "--dry-run=server", "-o", "json",
                       allow_failure=True), patch


def denial_matches(result):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and f"ValidatingAdmissionPolicy '{POLICY}'" in result.stderr
            and f"binding '{BINDING}'" in result.stderr and DENIAL in result.stderr)


def wait_policy_ready(lab):
    deadline = time.monotonic() + 25
    last = None
    while time.monotonic() < deadline:
        last = json.loads(lab.kubectl(
            "get", "validatingadmissionpolicy", POLICY, "-o", "json").stdout)
        checking = last.get("status", {}).get("typeChecking")
        if checking is not None:
            warnings = checking.get("expressionWarnings", [])
            if warnings:
                lab.block(f"Policy CEL type-check warnings: {warnings}")
            return
        time.sleep(0.25)
    lab.block(f"Policy CEL type-check status did not become available: {last}")


def run(lab):
    if (REGISTRY_FIXTURE_DATA.get("registry_name") != REGISTRY_NAME
            or REGISTRY_FIXTURE_DATA.get("registry_version") != "fixture-registry-v1"
            or set(RECORDS) != {"train-locked-synthetic", "continuous-learning-synthetic"}
            or RECORDS["train-locked-synthetic"] != {
                "classification": "train-verify-lock", "profile": "integrity-locked"}
            or RECORDS["continuous-learning-synthetic"] != {
                "classification": "continuous-learning", "profile": "update-governed"}):
        lab.block("The case-owned registry fixture does not match the reviewed two-profile matrix")
    lab.kubectl("label", "namespace", NAMESPACE, "saf-lab.example/classification-verified=true")
    lab.create(registry_crd())
    lab.kubectl("wait", "--for=condition=Established",
                f"customresourcedefinition/{PLURAL}.{GROUP}", "--timeout=30s")
    record = registry_object()
    lab.create(record)
    stored_record = json.loads(lab.kubectl(
        "get", f"{PLURAL}.{GROUP}", REGISTRY_NAME, "-o", "json").stdout)
    record_ok = stored_record["spec"] == record["spec"]
    lab.check("positive", "The named synthetic registry record is stored with both declared profiles",
              record_ok, {"name": REGISTRY_NAME, "systems": stored_record["spec"]["systems"]})

    # This exact candidate is incomplete but otherwise valid. Persist it and prove the API
    # would accept the same admission request before enabling the policy.
    incomplete = deployment("saf-0905-001-fixed-incomplete",
                            system_id="train-locked-synthetic",
                            classification="train-verify-lock", profile=None)
    lab.create(incomplete)
    saved_before = json.loads(lab.kubectl(
        "get", "deployment", incomplete["metadata"]["name"], "-o", "json").stdout)
    before, baseline_patch = patch_incomplete(lab, incomplete["metadata"]["name"])
    before_hash = hashlib.sha256(json.dumps(baseline_patch, sort_keys=True).encode()).hexdigest()
    lab.check("red", "The fixed incomplete AI Deployment is stored and the identical no-op UPDATE is admitted before policy",
              before.returncode == 0 and saved_before["metadata"]["name"] == incomplete["metadata"]["name"],
              {"stored": True, "same_request_sha256": before_hash,
               "pre_policy_admitted": before.returncode == 0, "stderr": before.stderr.strip()})

    lab.create(policy_object())
    lab.create(binding_object())
    wait_policy_ready(lab)

    deadline = time.monotonic() + 25
    while True:
        after, repeated_patch = patch_incomplete(lab, incomplete["metadata"]["name"])
        if denial_matches(after):
            break
        if after.returncode != 0 or time.monotonic() >= deadline:
            lab.block(f"Expected policy denial did not become active: {after.stderr.strip()}")
        time.sleep(0.5)
    after_hash = hashlib.sha256(json.dumps(repeated_patch, sort_keys=True).encode()).hexdigest()
    lab.check("green", "The identical no-op UPDATE to the fixed incomplete Deployment is denied by the named policy",
              denial_matches(after) and after_hash == before_hash, {"same_request_sha256": after_hash,
                                      "denied_by_policy": denial_matches(after),
                                      "stderr": after.stderr.strip()})

    probes = [
        ("unknown-system", deployment("saf-0905-001-unknown-system",
                                       system_id="not-in-registry", classification="train-verify-lock",
                                       profile="integrity-locked")),
        ("wrong-label", deployment("saf-0905-001-wrong-label",
                                    system_id="train-locked-synthetic",
                                    classification="continuous-learning", profile="integrity-locked")),
        ("wrong-profile", deployment("saf-0905-001-wrong-profile",
                                      system_id="continuous-learning-synthetic",
                                      classification="continuous-learning", profile="integrity-locked")),
        ("wrong-registry", deployment("saf-0905-001-wrong-registry",
                                       system_id="train-locked-synthetic",
                                       classification="train-verify-lock", profile="integrity-locked",
                                       registry="untrusted-lookalike-registry")),
    ]
    mismatch_results = {}
    for name, item in probes:
        result = submit(lab, item, dry_run=True)
        mismatch_results[name] = {"denied_by_policy": denial_matches(result),
                                  "stderr": result.stderr.strip()}
    all_mismatches_denied = all(value["denied_by_policy"] for value in mismatch_results.values())
    lab.check("green", "Unknown, mismatched and invalid registry evidence is denied by policy",
              all_mismatches_denied, mismatch_results)

    accepted = {}
    for system_id, values in RECORDS.items():
        name = "saf-0905-001-" + system_id.removesuffix("-synthetic")
        item = deployment(name, system_id=system_id,
                          classification=values["classification"], profile=values["profile"])
        result = submit(lab, item)
        stored = json.loads(lab.kubectl("get", "deployment", name, "-o", "json").stdout)
        accepted[system_id] = (result.returncode == 0
                               and stored["metadata"]["labels"].get(CLASS_LABEL) == values["classification"]
                               and stored["metadata"]["annotations"].get(PROFILE_ANNOTATION) == values["profile"]
                               and stored["metadata"]["annotations"].get(REGISTRY_ANNOTATION) == REGISTRY_NAME)
    benign = deployment("saf-0905-001-benign-unscoped", ai=False)
    benign_result = submit(lab, benign)
    benign_stored = lab.kubectl("get", "deployment", benign["metadata"]["name"], "-o", "json")
    benign_ok = (benign_result.returncode == 0
                 and AI_MARKER not in json.loads(benign_stored.stdout)["metadata"].get("labels", {}))
    lab.check("positive", "Both registry-matched profiles and an unscoped benign Deployment are API-stored",
              all(accepted.values()) and benign_ok,
              {"profiles": accepted, "benign_unscoped_admitted": benign_ok,
               "benign_stored": benign_result.returncode == 0})
