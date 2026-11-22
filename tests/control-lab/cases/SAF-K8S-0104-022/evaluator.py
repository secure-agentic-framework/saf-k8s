"""Statically classify effective feature-gate observations against a pinned baseline."""


def evaluate(baseline, observations):
    if baseline.get("kubernetes_version") != "1.36.1":
        raise ValueError("the baseline must match the case's pinned Kubernetes version")
    if not isinstance(observations, list):
        raise ValueError("observations must be a list")

    inventory = []
    identities = set()
    for item in observations:
        if not isinstance(item, dict):
            raise ValueError("each observation must be an object")
        component = item.get("component")
        feature = item.get("feature")
        enabled = item.get("enabled")
        stage = item.get("stage")
        if not all(isinstance(value, str) and value for value in (component, feature, stage)):
            raise ValueError("each observation needs component, feature, and stage strings")
        if not isinstance(enabled, bool):
            raise ValueError("effective feature state must be boolean")
        identity = (component, feature)
        if identity in identities:
            raise ValueError(f"duplicate effective observation: {identity}")
        identities.add(identity)

        if identity != (baseline["component"], baseline["gate"]):
            continue
        if stage != baseline["stage"]:
            raise ValueError("effective metric stage disagrees with the versioned baseline")
        default = baseline["default"]
        if enabled != default:
            classification = "non-default-enabled" if enabled else "non-default-disabled"
            inventory.append({
                "component": component,
                "feature": feature,
                "effective": enabled,
                "default": default,
                "stage": stage,
                "classification": classification,
            })
    return inventory
