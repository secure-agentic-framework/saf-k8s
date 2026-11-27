"""Check inert supply-chain model structure and bind it to exact graph bytes."""
import hashlib
import json
from pathlib import Path, PurePosixPath

STAGES = ("compromise", "propagation", "exploitation")
CLASSIFICATION_INTENT = {"defect": "non-malicious", "attack": "malicious"}


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def evaluate(record, graph_text, evidence_root):
    errors = []
    try:
        graph = json.loads(graph_text)
    except (TypeError, json.JSONDecodeError):
        graph = None
    if not isinstance(graph, dict):
        graph = {}
        errors.append("graph-invalid")
    review = record.get("reviewed_graph") if isinstance(record, dict) else None
    if not isinstance(review, dict) or review.get("revision") != graph.get("revision") or review.get("sha256") != digest(graph_text):
        errors.append("architecture-review-stale")

    components = graph.get("components")
    if (graph.get("schema") != "saf-ssc-graph/v1" or not isinstance(graph.get("revision"), str)
            or not graph["revision"]):
        errors.append("graph-schema-invalid")
    if (not isinstance(components, dict) or not components
            or any(not isinstance(component, dict)
                   or not isinstance(component.get("trust_boundary"), str)
                   or not component["trust_boundary"] for component in components.values())):
        errors.append("graph-components-invalid")
        components = {}
    flows_list = graph.get("flows", [])
    flows = {item.get("id"): item for item in flows_list if isinstance(item, dict) and isinstance(item.get("id"), str)}
    if len(flows) != len(flows_list):
        errors.append("graph-flow-identifiers-invalid")
    if not isinstance(record, dict):
        record = {}
    record_components = record.get("components")
    if (not isinstance(record_components, list)
            or any(not isinstance(component, str) for component in record_components)
            or len(set(record_components)) != len(record_components)
            or set(record_components) != set(components)):
        errors.append("component-coverage-incomplete")

    mitigations = record.get("mitigations", [])
    mitigation_by_id = {item.get("id"): item for item in mitigations if isinstance(item, dict) and isinstance(item.get("id"), str)}
    if len(mitigation_by_id) != len(mitigations):
        errors.append("mitigation-identifiers-invalid")

    evidence_root = Path(evidence_root).resolve()
    observed_stage_pairs = set()
    attack_stages = set()
    threat_ids = set()
    finding_ids = set()
    threats = record.get("threats", [])
    for threat in threats if isinstance(threats, list) else []:
        if not isinstance(threat, dict):
            errors.append("threat-record-invalid")
            continue
        threat_id = threat.get("id")
        if not isinstance(threat_id, str) or not threat_id or threat_id in threat_ids:
            errors.append("threat-identifiers-invalid")
            continue
        threat_ids.add(threat_id)
        classification = threat.get("classification")
        if classification not in CLASSIFICATION_INTENT or threat.get("intent") != CLASSIFICATION_INTENT.get(classification):
            errors.append(f"classification-intent-invalid:{threat_id}")
        findings = threat.get("findings", [])
        if not isinstance(findings, list) or not findings:
            errors.append(f"findings-missing:{threat_id}")
            continue
        threat_stages = set()
        for finding in findings:
            if not isinstance(finding, dict):
                errors.append(f"finding-invalid:{threat_id}")
                continue
            finding_id = finding.get("id")
            if not isinstance(finding_id, str) or not finding_id or finding_id in finding_ids:
                errors.append("finding-identifiers-invalid")
                continue
            finding_ids.add(finding_id)
            stage = finding.get("stage")
            component_id = finding.get("component")
            flow = flows.get(finding.get("flow_ref"))
            mitigation = mitigation_by_id.get(finding.get("mitigation_ref"))
            if stage not in STAGES:
                errors.append(f"stage-invalid:{threat_id}")
                continue
            threat_stages.add(stage)
            observed_stage_pairs.add((classification, stage))
            if classification == "attack":
                attack_stages.add(stage)
            if component_id not in components or not isinstance(flow, dict) or flow.get("stage") != stage or flow.get("component") != component_id:
                errors.append(f"component-flow-owner-invalid:{threat_id}:{stage}")
            if (not isinstance(finding.get("target_asset"), str) or not finding.get("target_asset")
                    or not isinstance(finding.get("vector"), str) or not finding.get("vector")):
                errors.append(f"target-or-vector-missing:{threat_id}:{stage}")
            if (not isinstance(mitigation, dict) or mitigation.get("stage") != stage
                    or mitigation.get("component") != component_id or not mitigation.get("control")):
                errors.append(f"stage-mitigation-invalid:{threat_id}:{stage}")

            ref = finding.get("evidence_ref", "")
            pure = PurePosixPath(ref) if isinstance(ref, str) else PurePosixPath(".")
            if (pure.is_absolute() or ".." in pure.parts or not pure.parts
                    or pure.parts[0] != stage or len(pure.parts) != 2):
                errors.append(f"evidence-path-unauthorized:{threat_id}:{stage}")
                continue
            path = evidence_root.joinpath(*pure.parts)
            try:
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(evidence_root) or path.is_symlink() or not resolved.is_file():
                    raise ValueError
                evidence = json.loads(resolved.read_text())
            except (OSError, ValueError, json.JSONDecodeError):
                errors.append(f"evidence-path-unauthorized:{threat_id}:{stage}")
                continue
            if (not isinstance(evidence, dict) or evidence.get("stage") != stage
                    or evidence.get("finding_id") != finding.get("id")):
                errors.append(f"evidence-binding-invalid:{threat_id}:{stage}")
        if classification == "attack" and threat_stages != set(STAGES):
            errors.append(f"attack-lifecycle-incomplete:{threat_id}")
    if attack_stages != set(STAGES):
        errors.append("attack-lifecycle-coverage-incomplete")
    if {classification for classification, _ in observed_stage_pairs} != set(CLASSIFICATION_INTENT):
        errors.append("classification-coverage-incomplete")
    return {"status": "fail" if errors else "pass", "errors": sorted(set(errors)),
            "graph_sha256": digest(graph_text),
            "classification_stage_pairs": sorted(f"{kind}:{stage}" for kind, stage in observed_stage_pairs)}
