#!/usr/bin/env python3
"""Check raw Pod JSON before API admission/defaulting."""
import json
import sys

RESOURCES = ("cpu", "memory", "ephemeral-storage")


def omissions(pod):
    errors = []
    spec = pod.get("spec", {})
    for kind in ("containers", "initContainers"):
        for container in spec.get(kind, []):
            resources = container.get("resources", {})
            for direction in ("requests", "limits"):
                declared = resources.get(direction, {})
                for name in RESOURCES:
                    if name not in declared:
                        errors.append(f"{kind}/{container.get('name', '<unnamed>')} missing {direction}.{name}")
    return errors


def main():
    pod = json.load(sys.stdin)
    errors = omissions(pod)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("all regular and init containers declare CPU, memory, and ephemeral-storage requests and limits")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
