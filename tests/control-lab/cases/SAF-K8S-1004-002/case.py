"""Verify synthetic source and build provenance before deploying an exact artifact."""
import base64
import copy
import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
IMAGE = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
BUILDER = "https://example.invalid/synthetic-builder/v1"
SOURCE_URI = "https://example.invalid/source.json"
BUILD_TYPE = "https://example.invalid/normalize-config/v1"
SCOPE = (
    "A synthetic promotion gate checks signed builder provenance, source, and the digest of "
    "a deterministically generated configuration artifact. The allowed bytes are mounted in "
    "a digest-pinned Kubernetes Job and independently read and hashed there. This covers a "
    "selected CI/CD provenance control and artifact propagation check. An additive inert-record "
    "gate checks three-stage threat-model structure and exact graph review binding, not risk or "
    "mitigation adequacy. Production trust, image admission, organization-wide threat modeling, "
    "AI pipeline coverage and ongoing deployment monitoring need separate evidence."
)


class Rejected(ValueError):
    """The declared fixture or its approved provenance failed verification."""


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def build(source):
    record = json.loads(source)
    return (json.dumps({"flags": sorted(record["flags"]), "release": record["release"]},
                       sort_keys=True, separators=(",", ":")) + "\n").encode()


def verify(source, artifact, statement, signature):
    if statement is None or signature is None:
        raise Rejected("missing provenance")
    with tempfile.TemporaryDirectory(prefix="saf-1004-002-") as temp:
        path = Path(temp)
        (path / "statement.json").write_bytes(statement)
        (path / "proof.sig").write_bytes(signature)
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(FIXTURES / "trusted-builder.pub"),
             "-signature", str(path / "proof.sig"), str(path / "statement.json")],
            capture_output=True, text=True, timeout=10,
        )
    if result.returncode:
        raise Rejected("invalid builder signature")
    doc = json.loads(statement)
    if (doc["_type"] != "https://in-toto.io/Statement/v1" or
            doc["predicateType"] != "https://slsa.dev/provenance/v1"):
        raise Rejected("unexpected statement type")
    definition = doc["predicate"]["buildDefinition"]
    builder = doc["predicate"]["runDetails"]["builder"]["id"]
    if builder != BUILDER or definition["buildType"] != BUILD_TYPE:
        raise Rejected("unexpected build identity")
    if definition["resolvedDependencies"] != [{"uri": SOURCE_URI, "digest": {"sha256": sha256(source)}}]:
        raise Rejected("source digest mismatch")
    subject = {"name": "generated-config.json", "digest": {"sha256": sha256(artifact)}}
    if doc["subject"] != [subject] or artifact != build(source):
        raise Rejected("artifact does not match signed build output")
    return {"source_sha256": sha256(source), "artifact_sha256": sha256(artifact), "builder": builder}


def promote(lab, name, source, artifact, statement, signature):
    binding = verify(source, artifact, statement, signature)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "immutable": True,
                "binaryData": {"generated-config.json": base64.b64encode(artifact).decode("ascii")}})
    container = {
        "name": "validator", "image": IMAGE,
        "command": ["/bin/sh", "-ec",
                    "test \"$(sha256sum /fixture/generated-config.json | cut -d' ' -f1)\" = \"$1\"; "
                    "sha256sum /fixture/generated-config.json; cat /fixture/generated-config.json",
                    "validate-artifact", binding["artifact_sha256"]],
        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]}},
        "volumeMounts": [{"name": "artifact", "mountPath": "/fixture", "readOnly": True}],
    }
    pod = {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [container],
        "volumes": [{"name": "artifact", "configMap": {"name": name}}],
    }
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 110, "template": {"spec": pod}}})
    return binding


def run_structure_gate(lab):
    gate_path = HERE / "threat_model_gate.py"
    spec = importlib.util.spec_from_file_location("saf_1004_002_threat_model_gate", gate_path)
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    graph_text = (FIXTURES / "ssc-graph.json").read_text()
    record = json.loads((FIXTURES / "ssc-threat-model.json").read_text())
    evidence_root = FIXTURES / "ssc-evidence"
    complete = gate.evaluate(record, graph_text, evidence_root)
    lab.check("green", "A complete inert SSC model covers all three stages with owned mitigations and evidence",
              complete["status"] == "pass",
              {"complete_model_passes": complete["status"] == "pass",
               "all_three_attack_stages_present": set(item.split(":", 1)[1] for item in complete["classification_stage_pairs"] if item.startswith("attack:")) == set(gate.STAGES),
               "defect_and_attack_classifications_distinct": {item.split(":", 1)[0] for item in complete["classification_stage_pairs"]} == {"attack", "defect"}})

    missing_stage = copy.deepcopy(record)
    missing_stage["threats"][0]["findings"] = [item for item in missing_stage["threats"][0]["findings"] if item["stage"] != "exploitation"]
    missing_stage_result = gate.evaluate(missing_stage, graph_text, evidence_root)
    confused_taxonomy = copy.deepcopy(record)
    confused_taxonomy["threats"][1]["intent"] = "malicious"
    taxonomy_result = gate.evaluate(confused_taxonomy, graph_text, evidence_root)
    missing_defect = copy.deepcopy(record)
    missing_defect["threats"] = [threat for threat in missing_defect["threats"] if threat["classification"] != "defect"]
    missing_defect_result = gate.evaluate(missing_defect, graph_text, evidence_root)
    missing_mitigation = copy.deepcopy(record)
    missing_mitigation["mitigations"][1]["control"] = ""
    mitigation_result = gate.evaluate(missing_mitigation, graph_text, evidence_root)
    flat_graph = json.loads(graph_text)
    flat_graph["components"] = sorted(flat_graph["components"])
    flat_graph_text = json.dumps(flat_graph, sort_keys=True, separators=(",", ":")) + "\n"
    flat_graph_review = copy.deepcopy(record)
    flat_graph_review["reviewed_graph"]["sha256"] = gate.digest(flat_graph_text)
    flat_graph_result = gate.evaluate(flat_graph_review, flat_graph_text, evidence_root)
    aliased_finding = copy.deepcopy(record)
    findings = aliased_finding["threats"][0]["findings"]
    findings.append(copy.deepcopy(findings[0]))
    alias_result = gate.evaluate(aliased_finding, graph_text, evidence_root)
    incomplete_rejected = ("attack-lifecycle-incomplete:attack-synthetic" in missing_stage_result["errors"]
                           and any(item.startswith("classification-intent-invalid:") for item in taxonomy_result["errors"])
                           and "classification-coverage-incomplete" in missing_defect_result["errors"]
                           and "stage-mitigation-invalid:attack-synthetic:propagation" in mitigation_result["errors"]
                           and "graph-components-invalid" in flat_graph_result["errors"]
                           and "architecture-review-stale" not in flat_graph_result["errors"]
                           and alias_result["errors"] == ["finding-identifiers-invalid"])
    lab.check("red", "Incomplete or malformed model structure and aliased evidence identities are rejected",
              incomplete_rejected,
              {"missing_stage_rejected": "attack-lifecycle-incomplete:attack-synthetic" in missing_stage_result["errors"],
               "taxonomy_confusion_rejected": any(item.startswith("classification-intent-invalid:") for item in taxonomy_result["errors"]),
               "missing_defect_class_rejected": "classification-coverage-incomplete" in missing_defect_result["errors"],
               "missing_stage_mitigation_rejected": "stage-mitigation-invalid:attack-synthetic:propagation" in mitigation_result["errors"],
               "malformed_component_inventory_rejected": "graph-components-invalid" in flat_graph_result["errors"],
               "duplicate_finding_identity_rejected": alias_result["errors"] == ["finding-identifiers-invalid"]})

    borrowed_evidence = copy.deepcopy(record)
    borrowed_evidence["threats"][0]["findings"][2]["evidence_ref"] = "propagation/attack-propagation.json"
    borrowed_result = gate.evaluate(borrowed_evidence, graph_text, evidence_root)
    borrowed_rejected = "evidence-path-unauthorized:attack-synthetic:exploitation" in borrowed_result["errors"]
    lab.check("red", "Evidence references remain within their authorized lifecycle-stage fixture path",
              borrowed_rejected,
              {"cross_stage_evidence_rejected": borrowed_rejected})

    graph = json.loads(graph_text)
    graph["revision"] = "ssc-r2"
    graph["components"]["build-runner"]["trust_boundary"] = "ephemeral-isolated-build"
    changed_graph_text = json.dumps(graph, sort_keys=True, separators=(",", ":")) + "\n"
    stale_result = gate.evaluate(record, changed_graph_text, evidence_root)
    refreshed = copy.deepcopy(record)
    refreshed["reviewed_graph"] = {"revision": graph["revision"], "sha256": gate.digest(changed_graph_text)}
    refreshed_result = gate.evaluate(refreshed, changed_graph_text, evidence_root)
    graph_review_bound = (gate.digest(graph_text) != gate.digest(changed_graph_text)
                          and "architecture-review-stale" in stale_result["errors"]
                          and refreshed_result["status"] == "pass")
    lab.check("green", "A material graph digest change stales the prior review until the model is refreshed",
              graph_review_bound,
              {"graph_digest_changed": gate.digest(graph_text) != gate.digest(changed_graph_text),
               "old_review_rejected": "architecture-review-stale" in stale_result["errors"],
               "refreshed_review_passes": refreshed_result["status"] == "pass"})
    (lab.evidence / "ssc-threat-model-structure.raw.json").write_text(json.dumps({
        "fixture_only": True,
        "base_graph_sha256": gate.digest(graph_text),
        "changed_graph_sha256": gate.digest(changed_graph_text),
        "complete_model": complete,
        "missing_stage": missing_stage_result,
        "confused_taxonomy": taxonomy_result,
        "missing_defect_class": missing_defect_result,
        "missing_mitigation": mitigation_result,
        "malformed_component_inventory": flat_graph_result,
        "duplicate_finding_identity": alias_result,
        "cross_stage_evidence": borrowed_result,
        "stale_graph_review": stale_result,
        "refreshed_graph_review": refreshed_result,
    }, sort_keys=True, indent=2) + "\n")


def run(lab):
    source = (FIXTURES / "source.json").read_bytes()
    artifact = build(source)
    statement = (FIXTURES / "provenance.json").read_bytes()
    signature = base64.b64decode((FIXTURES / "provenance.sig.b64").read_text(), validate=False)
    invalid = (
        ("missing", source, artifact, None, None, "missing provenance"),
        ("source", source + b" ", artifact, statement, signature, "source digest mismatch"),
        ("artifact", source, artifact + b" ", statement, signature, "artifact does not match signed build output"),
        ("signature", source, artifact, statement + b" ", signature, "invalid builder signature"),
    )
    for label, candidate_source, candidate_artifact, candidate_statement, candidate_signature, reason in invalid:
        name = f"saf-1004-002-{label}"
        rejection = None
        try:
            promote(lab, name, candidate_source, candidate_artifact, candidate_statement, candidate_signature)
        except Rejected as exc:
            rejection = str(exc)
        objects = lab.kubectl("get", f"job/{name}", f"configmap/{name}", "--ignore-not-found", "-o", "name")
        lab.check("red", reason, rejection == reason and not objects.stdout.strip(),
                  {"rejection": rejection, "release_objects_created": bool(objects.stdout.strip())})

    name = "saf-1004-002-approved"
    binding = promote(lab, name, source, artifact, statement, signature)
    job = json.loads(lab.kubectl("get", f"job/{name}", "-o", "json").stdout)
    image = job["spec"]["template"]["spec"]["containers"][0]["image"]
    lab.check("green", "The gate promotes an artifact bound to the signed source and builder",
              binding["artifact_sha256"] == sha256(artifact) and image == IMAGE, binding)
    lab.kubectl("wait", "--for=condition=complete", f"job/{name}", "--timeout=125s")
    logs = lab.kubectl("logs", f"job/{name}").stdout
    (lab.evidence / "workload.raw.log").write_text(logs)
    actual_hash, _, content = logs.partition("\n")
    lab.check("positive", "The native Job completes after reading and hashing the mounted build bytes",
              actual_hash.split()[0] == binding["artifact_sha256"] and content.encode() == artifact,
              {"mounted_sha256": sha256(content.encode()), "job_completed": True, "image": image})
    run_structure_gate(lab)
