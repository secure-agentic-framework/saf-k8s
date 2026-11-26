"""Static-only RBAC manifest inventory oracle; objects are never submitted to Kubernetes."""
SENSITIVE_VERBS = {"bind", "escalate", "impersonate"}


def findings(objects):
    out = []
    for obj in objects:
        meta = obj.get("metadata", {})
        name = meta.get("name", "")
        namespace = meta.get("namespace")
        for index, rule in enumerate(obj.get("rules", [])):
            categories = []
            for field in ("apiGroups", "resources", "verbs"):
                values = rule.get(field, [])
                if "*" in values:
                    categories.append("wildcard-" + field)
            verbs = set(rule.get("verbs", []))
            sensitive = sorted(verbs & SENSITIVE_VERBS)
            if sensitive:
                categories.append("authorization-sensitive-verbs")
            if categories:
                out.append({
                    "object_kind": obj.get("kind"),
                    "object_name": name,
                    "namespace": namespace,
                    "rule_index": index,
                    "categories": sorted(categories),
                    "sensitive_verbs": sensitive,
                    "disposition": "manifest_candidate_only",
                    "effective_authorization": "not_evaluated",
                    "subject_bindings": "not_present_in_fixture",
                })
    return sorted(out, key=lambda row: (row["object_kind"], row["object_name"], row["rule_index"]))


def inventory(objects):
    return {
        "object_count": len(objects),
        "objects": sorted(
            [{"kind": o.get("kind"), "name": o.get("metadata", {}).get("name"),
              "namespace": o.get("metadata", {}).get("namespace"),
              "rule_count": len(o.get("rules", []))} for o in objects],
            key=lambda row: (row["kind"], row["namespace"] or "", row["name"])),
        "findings": findings(objects),
    }


def evaluate(fixture):
    objects = fixture["objects"]
    baseline = inventory(objects)
    remove_names = set(fixture["reconciled_remove_names"])
    reconciled_objects = [o for o in objects if o["metadata"]["name"] not in remove_names]
    reconciled = inventory(reconciled_objects)
    return {
        "format": "saf-rbac-static-inventory-result/v1",
        "execution_scope": "offline fixture data only; no Kubernetes/API calls",
        "baseline": baseline,
        "reconciled": reconciled,
        "removed_names": sorted(remove_names),
    }
