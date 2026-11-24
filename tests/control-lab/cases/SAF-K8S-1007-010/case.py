"""Check a target Kubernetes API against a synthetic operator compatibility profile."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from fixtures import BUSYBOX_IMAGE

HERE = Path(__file__).resolve().parent
FIXTURE_PATH = HERE / "fixtures.json"
CRD_NAME = "mockinferenceservices.models.saf-k8s.example"
APPROVAL_RECEIPT = "saf-1007-010-mock-approval"
SCOPE = (
    "One disposable Kind v1.36.1 target cluster, using the lab runner's digest-pinned node image. "
    "Reads the live server version and Kubernetes API discovery, flags a synthetic mock-operator "
    "inventory that still requires removed policy/v1beta1 PodDisruptionBudgets, then checks the "
    "repaired policy/v1 API with a server-side dry-run and persists one benign synthetic CRD and "
    "custom resource. A local mock upgrade gate denies promotion without evidence and on exact target "
    "version mismatch and persists only approved mock decisions. A small Job writes a "
    "synthetic training marker and an HTTP Service serves an inert inference marker on "
    "the actual target. Adopters validate their own operators, model behavior, GPUs and webhooks."
)


def read_fixture():
    return json.loads(FIXTURE_PATH.read_text())


def load_json(result):
    return json.loads(result.stdout)


def custom_resource_definition(fixture):
    item = fixture["synthetic_custom_resource"]
    return {
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {
            "name": f"{item['plural']}.{item['group']}",
            "labels": {
                "saf-k8s.example/control": "1007-010",
                "saf-k8s.example/data": "synthetic",
            },
        },
        "spec": {
            "group": item["group"],
            "scope": "Namespaced",
            "names": {
                "plural": item["plural"],
                "singular": "mockinferenceservice",
                "kind": item["kind"],
                "shortNames": ["mis-fixture"],
            },
            "versions": [{
                "name": item["version"],
                "served": True,
                "storage": True,
                "schema": {"openAPIV3Schema": {
                    "type": "object",
                    "properties": {
                        "spec": {"type": "object", "required": ["modelRef"],
                                 "properties": {
                                     "modelRef": {"type": "string", "minLength": 1},
                                     "replicas": {"type": "integer", "minimum": 0},
                                 }},
                        "status": {"type": "object", "x-kubernetes-preserve-unknown-fields": True},
                    },
                }},
            }],
        },
    }


def custom_resource(fixture):
    item = fixture["synthetic_custom_resource"]
    return {
        "apiVersion": f"{item['group']}/{item['version']}",
        "kind": item["kind"],
        "metadata": {
            "name": item["name"],
            "namespace": item["namespace"],
            "labels": {
                "saf-k8s.example/control": "1007-010",
                "saf-k8s.example/data": "synthetic",
            },
        },
        "spec": {"modelRef": item["model_ref"], "replicas": item["replicas"]},
    }


def gate_decision(observed_target, requested_target, evidence):
    """A deliberately local mock gate. It makes no production upgrade request."""
    reasons = []
    if observed_target != requested_target:
        reasons.append("target_version_mismatch")
    if not evidence:
        reasons.append("compatibility_evidence_missing")
    else:
        if evidence.get("target_version") != requested_target:
            reasons.append("evidence_target_version_mismatch")
        if evidence.get("compatible") is not True:
            reasons.append("compatibility_not_confirmed")
        if evidence.get("required_api") != "policy/v1/poddisruptionbudgets":
            reasons.append("required_api_evidence_missing")
        if evidence.get("synthetic_crd_accepted") is not True:
            reasons.append("synthetic_crd_evidence_missing")
        if evidence.get("training_workflow_verified") is not True:
            reasons.append("training_workflow_evidence_missing")
        if evidence.get("inference_workflow_verified") is not True:
            reasons.append("inference_workflow_evidence_missing")
    return {"decision": "deny" if reasons else "allow", "reasons": reasons,
            "observed_target": observed_target, "requested_target": requested_target}


def submit_mock_promotion(lab, observed_target, requested_target, evidence):
    decision = gate_decision(observed_target, requested_target, evidence)
    if decision["decision"] == "allow":
        lab.create({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": APPROVAL_RECEIPT, "labels": {"saf-k8s.example/control": "1007-010"}},
            "immutable": True,
            "data": {"target": requested_target, "evidence.json": json.dumps(evidence, sort_keys=True)},
        })
    return decision


def approval_missing(lab):
    inspected = lab.kubectl("get", "configmap", APPROVAL_RECEIPT, "--ignore-not-found", "-o", "name")
    return not inspected.stdout.strip()


def save_raw(lab, filename, value):
    (lab.evidence / filename).write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n")


def target_workflows(lab):
    labels = {"app": "saf-compat-inference"}
    security = {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}
    pod_security = {"runAsNonRoot": True, "runAsUser": 65532,
                    "seccompProfile": {"type": "RuntimeDefault"}}
    pod_base = {"automountServiceAccountToken": False, "restartPolicy": "Never",
                "securityContext": pod_security}
    training = {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": "saf-compat-training"},
        "spec": {"backoffLimit": 0, "template": {"spec": {**pod_base, "containers": [{
            "name": "training-check", "image": BUSYBOX_IMAGE, "securityContext": security,
            "command": ["sh", "-ec", "printf '%s' training-fixture-complete > /tmp/result; cat /tmp/result"],
        }]}}},
    }
    inference = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "saf-compat-inference", "labels": labels},
        "spec": {**pod_base, "containers": [{
            "name": "serving-check", "image": BUSYBOX_IMAGE, "securityContext": security,
            "command": ["sh", "-ec", "mkdir -p /tmp/saf-www; "
                        "printf '%s' inference-fixture-response > /tmp/saf-www/result; "
                        "exec httpd -f -p 8080 -h /tmp/saf-www"],
            "readinessProbe": {"httpGet": {"path": "/result", "port": 8080}, "periodSeconds": 2},
        }]},
    }
    service = {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "saf-compat-inference"},
        "spec": {"selector": labels, "ports": [{"port": 8080, "targetPort": 8080}]},
    }
    # Exercise effective native target admission as well as API schemas.
    lab.kubectl("label", "namespace", "saf-test", "--overwrite",
                "pod-security.kubernetes.io/enforce=restricted",
                "pod-security.kubernetes.io/enforce-version=v1.36")
    unapproved = deepcopy(inference)
    unapproved["metadata"]["name"] = "saf-invalid-inference-policy"
    unapproved["spec"]["containers"][0]["securityContext"]["allowPrivilegeEscalation"] = True
    rejected = lab.create(unapproved, dry_run=True, allow_failure=True)
    denial = (
        rejected.returncode != 0 and 'violates PodSecurity "restricted:v1.36"' in rejected.stderr
        and "allowPrivilegeEscalation" in rejected.stderr
    )
    lab.check("green", "The target's effective Pod Security policy rejects the unapproved serving variant",
              denial, {"specific_native_admission_denial": denial})
    # Use distinct target objects and confirm both real consumer outputs.
    lab.create(training)
    lab.create(service)
    served = lab.create(inference)
    lab.kubectl("wait", "--for=condition=Complete", "job/saf-compat-training",
                "--timeout=90s", timeout=105)
    lab.kubectl("wait", "--for=condition=Ready", "pod/saf-compat-inference",
                "--timeout=90s", timeout=105)
    job_result = lab.kubectl("logs", "job/saf-compat-training").stdout
    consumer = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "saf-compat-inference-consumer"},
        "spec": {**pod_base, "containers": [{
            "name": "serve-client", "image": BUSYBOX_IMAGE, "securityContext": security,
            "command": ["sh", "-ec", "for n in 1 2 3 4 5; do "
                        "if wget -q -O - -T 3 http://saf-compat-inference:8080/result; then exit 0; fi; "
                        "sleep 2; done; exit 1"],
        }]},
    }
    lab.create(consumer)
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded",
                "pod/saf-compat-inference-consumer", "--timeout=70s", timeout=85)
    inference_result = lab.kubectl("logs", "saf-compat-inference-consumer").stdout
    endpoints = load_json(lab.kubectl(
        "get", "endpointslices", "-l", "kubernetes.io/service-name=saf-compat-inference", "-o", "json",
    ))
    targets = [row for item in endpoints["items"] for row in item.get("endpoints", [])
               if row.get("conditions", {}).get("ready") is True]
    observed = {
        "training_workflow_verified": job_result == "training-fixture-complete",
        "inference_workflow_verified": inference_result == "inference-fixture-response",
        "service_targets_exact_ready_pod": len(targets) == 1
        and targets[0].get("targetRef", {}).get("uid") == served["metadata"]["uid"],
    }
    lab.check("positive", "Target Job completion and Service response validate the two runtime paths",
              all(observed.values()), observed)
    return {
        "training_workflow_verified": observed["training_workflow_verified"],
        "inference_workflow_verified": observed["inference_workflow_verified"]
        and observed["service_targets_exact_ready_pod"],
        "fixture_sha256": hashlib.sha256(
            json.dumps([training, inference, service, consumer], sort_keys=True).encode()
        ).hexdigest(),
    }


def run(lab):
    fixture = read_fixture()
    expected_target = fixture["target_version"]
    operator = fixture["synthetic_operator"]

    version = load_json(lab.kubectl("version", "-o", "json"))
    observed_target = version.get("serverVersion", {}).get("gitVersion")
    save_raw(lab, "target-version.raw.json", version)
    lab.check("green", "Preflight observes the exact pinned Kubernetes target version",
              observed_target == expected_target,
              {"expected": expected_target, "observed": observed_target,
               "node_image_digest_pinned_by_runner": True})

    policy_discovery = load_json(lab.kubectl("get", "--raw", "/apis/policy"))
    discovered_versions = {entry.get("groupVersion") for entry in policy_discovery.get("versions", [])}
    resources_by_version = {}
    discovery_by_version = {}
    for group_version in sorted(discovered_versions):
        version = group_version.split("/", 1)[1]
        response = load_json(lab.kubectl("get", "--raw", f"/apis/policy/{version}"))
        discovery_by_version[group_version] = response
        resources_by_version[group_version] = {
            entry.get("name") for entry in response.get("resources", [])
        }
    legacy = operator["legacy_requirement"]
    repaired = operator["repaired_requirement"]
    legacy_requirement = f"{legacy['api_group_version']}/{legacy['resource']}"
    repaired_requirement = f"{repaired['api_group_version']}/{repaired['resource']}"
    legacy_present = (legacy["api_group_version"] in discovered_versions
                      and legacy["resource"] in resources_by_version.get(
                          legacy["api_group_version"], set()))
    legacy_missing = not legacy_present
    repaired_present = (repaired["api_group_version"] in discovered_versions
                        and repaired["resource"] in resources_by_version.get(
                            repaired["api_group_version"], set()))
    api_preflight = {
        "target_version": observed_target,
        "discovered_policy_group_versions": sorted(discovered_versions),
        "discovered_policy_resources_by_version": {
            group_version: sorted(resources)
            for group_version, resources in resources_by_version.items()
        },
        "synthetic_operator": operator["name"],
        "synthetic_legacy_requirement": legacy_requirement,
        "synthetic_legacy_requirement_missing": legacy_missing,
        "synthetic_repaired_requirement": repaired_requirement,
        "synthetic_repaired_requirement_present": repaired_present,
    }
    save_raw(lab, "api-preflight.raw.json", {
        "policy_group_discovery": policy_discovery,
        "policy_resource_discovery_by_version": discovery_by_version,
        "assessment": api_preflight,
    })
    lab.check("red", "Preflight flags the synthetic operator's unavailable legacy API requirement",
              legacy_missing,
              {"requirement": legacy_requirement,
               "requirement_missing": legacy_missing,
               "discovered_group_versions": sorted(discovered_versions)})

    denied_without_evidence = submit_mock_promotion(lab, observed_target, expected_target, None)
    save_raw(lab, "upgrade-gate-missing-evidence.raw.json", denied_without_evidence)
    lab.check("red", "Mock upgrade gate denies promotion when compatibility evidence is missing",
              denied_without_evidence["decision"] == "deny"
              and "compatibility_evidence_missing" in denied_without_evidence["reasons"]
              and approval_missing(lab),
              denied_without_evidence)

    # Exercise only the migrated API request. The unavailable legacy endpoint is
    # established from discovery; the case never submits a removed-API request.
    pdb_result = lab.kubectl("create", "-f", "-", "--dry-run=server", "-o", "json",
                             payload=json.dumps(fixture["synthetic_pdb"]))
    pdb = load_json(pdb_result)
    pdb_accepted = (pdb.get("apiVersion") == repaired["api_group_version"]
                    and pdb.get("kind") == "PodDisruptionBudget"
                    and pdb.get("metadata", {}).get("name") == "mock-inference-budget")
    lab.check("green", "Repaired policy/v1 request passes target API server validation",
              repaired_present and pdb_accepted,
              {"api_version": pdb.get("apiVersion"), "kind": pdb.get("kind"),
               "name": pdb.get("metadata", {}).get("name"),
               "server_side_dry_run": True, "required_api_discovered": repaired_present})

    crd = custom_resource_definition(fixture)
    lab.kubectl("apply", "-f", "-", payload=json.dumps(crd))
    lab.kubectl("wait", f"--for=condition=Established", f"crd/{CRD_NAME}", "--timeout=30s")
    custom = custom_resource(fixture)
    malformed = {**custom, "metadata": {**custom["metadata"], "name": "missing-model-reference"},
                 "spec": {"replicas": 1}}
    refused = lab.kubectl("create", "-f", "-", "--validate=false", "--dry-run=server",
                          payload=json.dumps(malformed), allow_failure=True)
    schema_error = (refused.returncode != 0 and "spec.modelRef: Required value" in refused.stderr)
    lab.check("green", "Target custom resource schema rejects an omitted model reference",
              schema_error, {"server_side_required_field_rejection": schema_error})
    lab.kubectl("apply", "-f", "-", payload=json.dumps(custom))
    live_crd = load_json(lab.kubectl("get", "crd", CRD_NAME, "-o", "json"))
    live_custom = load_json(lab.kubectl(
        "get", fixture["synthetic_custom_resource"]["plural"],
        custom["metadata"]["name"], "-o", "json"))
    crd_version = next((entry for entry in live_crd.get("spec", {}).get("versions", [])
                        if entry.get("name") == fixture["synthetic_custom_resource"]["version"]), {})
    crd_accepted = (crd_version.get("served") is True and crd_version.get("storage") is True
                    and live_custom.get("apiVersion") == custom["apiVersion"]
                    and live_custom.get("spec", {}).get("modelRef") == custom["spec"]["modelRef"])
    save_raw(lab, "synthetic-crd-and-custom-resource.raw.json",
             {"custom_resource_definition": live_crd, "custom_resource": live_custom,
              "accepted": crd_accepted})
    lab.check("positive", "Target API accepts the synthetic operator CRD and custom resource",
              crd_accepted,
              {"crd": CRD_NAME, "custom_resource_api": custom["apiVersion"],
               "kind": custom["kind"], "accepted": crd_accepted})

    evidence = {
        "target_version": observed_target,
        "compatible": (observed_target == expected_target and legacy_missing
                       and repaired_present and pdb_accepted),
        "required_api": repaired_requirement if repaired_present and pdb_accepted else None,
        "synthetic_crd_accepted": crd_accepted,
        **target_workflows(lab),
    }
    missing_workflow = submit_mock_promotion(
        lab, observed_target, expected_target,
        {**evidence, "inference_workflow_verified": False},
    )
    lab.check("red", "An API-compatible target without complete runtime evidence cannot record approval",
              missing_workflow["reasons"] == ["inference_workflow_evidence_missing"]
              and approval_missing(lab), {"decision": missing_workflow["decision"],
                                          "reasons": missing_workflow["reasons"]})
    wrong_target_gate = submit_mock_promotion(lab, observed_target, "v1.36.0", evidence)
    still_absent = approval_missing(lab)
    repaired_gate = submit_mock_promotion(lab, observed_target, expected_target, evidence)
    approved = load_json(lab.kubectl("get", "configmap", APPROVAL_RECEIPT, "-o", "json"))
    matching_receipt = (approved.get("immutable") is True
                        and approved["data"]["target"] == expected_target
                        and json.loads(approved["data"]["evidence.json"]) == evidence)
    save_raw(lab, "upgrade-gate-evidence.raw.json",
             {"evidence": evidence, "matching_target": repaired_gate,
              "mismatched_target": wrong_target_gate, "api_receipt": approved})
    lab.check("green", "Mock promotion is allowed only with evidence for this exact target",
              repaired_gate["decision"] == "allow"
              and wrong_target_gate["decision"] == "deny"
              and "target_version_mismatch" in wrong_target_gate["reasons"] and still_absent,
              {"matching_target_decision": repaired_gate["decision"],
               "matching_target": repaired_gate["requested_target"],
               "mismatched_target_decision": wrong_target_gate["decision"],
               "mismatched_target": wrong_target_gate["requested_target"],
               "mismatch_reasons": wrong_target_gate["reasons"]})
    lab.check("positive", "Compatibility evidence permits only the mock promotion decision",
              repaired_gate["decision"] == "allow" and matching_receipt,
              {"decision": repaired_gate["decision"], "approved_receipt_matches": matching_receipt,
               "evidence_target": evidence["target_version"]})
