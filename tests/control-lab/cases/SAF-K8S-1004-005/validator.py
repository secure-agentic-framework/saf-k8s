"""Review case-owned abstract records without inferring an actor or attack."""
REQUIRED_DIMENSIONS = {
    "system_type",
    "learning_method_and_lifecycle_stage",
    "attacker_goals_and_objectives",
    "attacker_capabilities_and_access",
    "attacker_knowledge",
}

def _validation(record, fixture):
    """Return a conservative schema/freshness decision, not an attack verdict."""
    errors = []
    observations = {item["observation_id"]: item for item in fixture["observations"]}
    if record.get("taxonomy_id") != "NIST AI 100-2e2025":
        errors.append("taxonomy_id_mismatch")
    if not record.get("tenant") or not record.get("namespace"):
        errors.append("missing_review_namespace")
    if not isinstance(record.get("review_age_days"), int) or record["review_age_days"] < 0:
        errors.append("invalid_review_age")
    elif record["review_age_days"] > fixture["freshness_policy_days"]:
        errors.append("stale_record")
    dimensions = record.get("dimensions")
    if not isinstance(dimensions, dict) or set(dimensions) != REQUIRED_DIMENSIONS:
        errors.append("dimension_set_incomplete")
        dimensions = dimensions if isinstance(dimensions, dict) else {}
    for name in REQUIRED_DIMENSIONS & set(dimensions):
        item = dimensions[name]
        if not isinstance(item, dict) or "value" not in item:
            errors.append("dimension_value_missing:" + name)
            continue
        evidence = item.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            errors.append("evidence_missing:" + name)
        elif any(ref not in observations for ref in evidence):
            errors.append("evidence_reference_unknown:" + name)
        else:
            cited = [observations[ref] for ref in evidence]
            if any((item.get("tenant"), item.get("namespace"))
                   != (record.get("tenant"), record.get("namespace")) for item in cited):
                errors.append("evidence_scope_mismatch:" + name)
            if name == "system_type":
                types = {value["values"].get("system_type") for value in cited}
                resolved = types & {"predictive", "generative"}
                if item["value"] in ("unknown", "undetermined_from_observation"):
                    if len(resolved) != 2 and item["value"] not in types:
                        errors.append("evidence_value_mismatch:" + name)
                elif len(resolved) > 1:
                    errors.append("conflicting_system_type_evidence")
                elif item["value"] not in resolved:
                    errors.append("evidence_value_mismatch:" + name)
            if name == "learning_method_and_lifecycle_stage" and not any(
                    item["value"] == {"learning_method": value["values"].get("learning_method"),
                                      "stage": value["values"].get("lifecycle_stage")}
                    for value in cited):
                errors.append("evidence_value_mismatch:" + name)
        if name in {"attacker_goals_and_objectives", "attacker_capabilities_and_access", "attacker_knowledge"}:
            if item["value"] not in ("unknown", "undetermined_from_observation"):
                errors.append("unsupported_actor_inference:" + name)
        if item["value"] in ("unknown", "undetermined_from_observation"):
            if not item.get("rationale"):
                errors.append("unknown_without_rationale:" + name)
    if record.get("actual_incident") is not False:
        errors.append("incident_status_not_bounded")
    if record.get("candidate_attack_class") is not None:
        errors.append("unsupported_attack_class_assignment")
    return {"accepted_for_review": not errors, "errors": sorted(set(errors)),
            "review_state": "pending_human_review" if not errors else "rejected"}
