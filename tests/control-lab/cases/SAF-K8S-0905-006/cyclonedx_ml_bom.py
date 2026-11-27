"""Parse the bounded CycloneDX 1.6 fields used by this fixture only."""


class IngestError(ValueError):
    """The fixture is malformed or contains an unresolved relationship."""


SUPPORTED_COMPONENT_TYPES = {"data", "machine-learning-model", "application"}
REQUIRED_PROPERTIES = {
    "saf-k8s.example:configmap-namespace",
    "saf-k8s.example:configmap-name",
    "saf-k8s.example:record-kind",
}


def ingest(bom):
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.6":
        raise IngestError("unsupported CycloneDX header")
    if not isinstance(bom.get("serialNumber"), str) or not bom["serialNumber"].startswith("urn:uuid:"):
        raise IngestError("invalid BOM serial number")
    if not isinstance(bom.get("version"), int) or bom["version"] < 1:
        raise IngestError("invalid BOM version")
    metadata = bom.get("metadata")
    subject = metadata.get("component") if isinstance(metadata, dict) else None
    items = []
    if subject is not None:
        items.append(subject)
    components = bom.get("components")
    if not isinstance(components, list):
        raise IngestError("invalid components collection")
    items.extend(components)

    by_ref = {}
    configmap_to_ref = {}
    for item in items:
        if not isinstance(item, dict):
            raise IngestError("invalid component")
        ref = item.get("bom-ref")
        if not isinstance(ref, str) or not ref or ref in by_ref:
            raise IngestError("missing or duplicate component reference")
        if item.get("type") not in SUPPORTED_COMPONENT_TYPES:
            raise IngestError("unsupported component type")
        if not isinstance(item.get("name"), str) or not item["name"]:
            raise IngestError("missing component name")
        if not isinstance(item.get("version"), str) or not item["version"]:
            raise IngestError("missing component version")
        properties = item.get("properties")
        if not isinstance(properties, list):
            raise IngestError("missing ConfigMap binding properties")
        property_map = {}
        for prop in properties:
            if not isinstance(prop, dict) or not isinstance(prop.get("name"), str) or not isinstance(prop.get("value"), str):
                raise IngestError("invalid component property")
            if prop["name"] in property_map:
                raise IngestError("duplicate component property")
            property_map[prop["name"]] = prop["value"]
        if not REQUIRED_PROPERTIES.issubset(property_map):
            raise IngestError("missing ConfigMap binding property")
        if property_map["saf-k8s.example:configmap-namespace"] != "saf-test":
            raise IngestError("component outside owned namespace")
        name = property_map["saf-k8s.example:configmap-name"]
        if name in configmap_to_ref:
            raise IngestError("duplicate ConfigMap binding")
        component = dict(item)
        component["properties"] = property_map
        by_ref[ref] = component
        configmap_to_ref[name] = ref

    dependencies = bom.get("dependencies")
    if not isinstance(dependencies, list):
        raise IngestError("missing dependency graph")
    dependency_by_ref = {}
    reverse_edges = {ref: set() for ref in by_ref}
    for row in dependencies:
        if not isinstance(row, dict):
            raise IngestError("invalid dependency row")
        ref = row.get("ref")
        if ref not in by_ref:
            raise IngestError("unknown dependency reference")
        if ref in dependency_by_ref:
            raise IngestError("duplicate dependency row")
        depends_on = row.get("dependsOn")
        if (not isinstance(depends_on, list)
                or any(not isinstance(value, str) or not value for value in depends_on)
                or len(set(depends_on)) != len(depends_on)):
            raise IngestError("invalid dependsOn list")
        for source_ref in depends_on:
            if source_ref not in by_ref:
                raise IngestError("unknown dependency reference")
            reverse_edges[source_ref].add(ref)
        dependency_by_ref[ref] = {"ref": ref, "dependsOn": list(depends_on)}
    if set(dependency_by_ref) != set(by_ref):
        raise IngestError("dependency graph does not explicitly cover every component")
    return {"components": by_ref, "configmap_to_ref": configmap_to_ref,
            "dependencies": dependency_by_ref, "reverse_edges": reverse_edges}


def reverse_closure(reverse_edges, source_ref):
    if source_ref not in reverse_edges:
        raise IngestError("unknown lineage source")
    visited = set()
    pending = list(reverse_edges[source_ref])
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        pending.extend(reverse_edges[current])
    return visited
