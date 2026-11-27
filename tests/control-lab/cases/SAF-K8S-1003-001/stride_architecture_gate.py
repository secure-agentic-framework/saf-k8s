"""Bind synthetic STRIDE evidence to a reviewed DFD revision and exact flow."""
import argparse
import hashlib
import json
from datetime import date
from pathlib import Path

from review_gate import evaluate as evaluate_record


def evaluate(record, graph_text, evidence_root, today):
    errors = list(evaluate_record(record, Path(evidence_root), date.fromisoformat(today))["errors"])
    try:
        graph = json.loads(graph_text)
    except (TypeError, json.JSONDecodeError):
        graph = {}
        errors.append("architecture-graph-invalid")
    digest = hashlib.sha256(graph_text.encode()).hexdigest()
    review = record.get("reviewed_architecture") or {}
    if (review.get("revision") != graph.get("revision")
            or review.get("sha256") != digest):
        errors.append("architecture-review-stale")

    boundaries = {item.get("id"): item for item in graph.get("boundaries", [])
                  if isinstance(item, dict) and isinstance(item.get("id"), str)}
    flows = {item.get("id"): item for item in graph.get("flows", [])
             if isinstance(item, dict) and isinstance(item.get("id"), str)}
    if len(flows) != len(graph.get("flows", [])) or len(boundaries) != len(graph.get("boundaries", [])):
        errors.append("architecture-graph-identifiers-invalid")
    components = record.get("components", {})
    flows_by_component = {}
    for flow_id, flow in flows.items():
        component = flow.get("component")
        boundary_id = flow.get("boundary_id")
        if component not in components or boundary_id not in boundaries:
            errors.append("architecture-graph-reference-invalid")
            continue
        flows_by_component.setdefault(component, set()).add(flow_id)

    for component, entry in components.items():
        expected = flows_by_component.get(component, set())
        declared = entry.get("flow_ids") if isinstance(entry, dict) else None
        if (not expected or not isinstance(declared, list) or set(declared) != expected
                or entry.get("boundary_id") not in {
                    flows[flow_id].get("boundary_id") for flow_id in expected
                }):
            errors.append(f"component-flow-mapping-invalid:{component}")

    for threat in record.get("threats", []):
        threat_id = threat.get("id", "<missing>")
        flow = flows.get(threat.get("flow_ref"))
        component = threat.get("component")
        component_record = components.get(component, {})
        if (flow is None or flow.get("component") != component
                or flow.get("boundary_id") != threat.get("boundary_ref")
                or threat.get("flow_ref") not in component_record.get("flow_ids", [])):
            errors.append(f"threat-flow-reference-invalid:{threat_id}")
    return {"status": "fail" if errors else "pass", "errors": sorted(set(errors)),
            "architecture_digest": digest}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("record", type=Path)
    parser.add_argument("graph", type=Path)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--today", default="2026-11-22")
    args = parser.parse_args()
    result = evaluate(json.loads(args.record.read_text()), args.graph.read_text(),
                      args.evidence_root, args.today)
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["status"] == "pass" else 1)


if __name__ == "__main__":
    main()
