"""Compare read-only Node status captures from the paired kind configurations."""
from decimal import Decimal
import json
from pathlib import Path
import sys


EXPECTED_DELTA = {
    "cpu": 60,  # millicores: systemReserved 25m + kubeReserved 35m
    "memory": 80 * 1024 * 1024,  # bytes: 32Mi + 48Mi
    "ephemeral-storage": 3 * 1024 * 1024,  # bytes: systemReserved 2Mi + kubeReserved 1Mi
}


def quantity(resource, value):
    """Parse the small subset of Kubernetes quantities used in Node status."""
    text = str(value)
    if resource == "cpu":
        return int(text[:-1]) if text.endswith("m") else int(Decimal(text) * 1000)
    suffixes = {
        "Ki": 1024,
        "Mi": 1024**2,
        "Gi": 1024**3,
        "Ti": 1024**4,
        "k": 1000,
        "M": 1000**2,
        "G": 1000**3,
        "T": 1000**4,
    }
    for suffix, multiplier in suffixes.items():
        if text.endswith(suffix):
            return int(Decimal(text[:-len(suffix)]) * multiplier)
    return int(Decimal(text))


def node_status(path):
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    nodes = document.get("items", [])
    if len(nodes) != 1:
        raise ValueError(f"{path}: expected one Node, got {len(nodes)}")
    status = nodes[0]["status"]
    capacity = status["capacity"]
    allocatable = status["allocatable"]
    values = {}
    for resource in EXPECTED_DELTA:
        if resource not in capacity or resource not in allocatable:
            raise ValueError(f"{path}: Node status omits {resource}")
        values[resource] = (
            quantity(resource, capacity[resource]),
            quantity(resource, allocatable[resource]),
        )
    return values


def compare(zero_path, reserved_path):
    zero = node_status(zero_path)
    reserved = node_status(reserved_path)
    results = {}
    for resource, expected in EXPECTED_DELTA.items():
        zero_capacity, zero_allocatable = zero[resource]
        reserved_capacity, reserved_allocatable = reserved[resource]
        zero_delta = zero_capacity - zero_allocatable
        reserved_delta = reserved_capacity - reserved_allocatable
        observed = reserved_delta - zero_delta
        results[resource] = {
            "zero_capacity_minus_allocatable": zero_delta,
            "reserved_capacity_minus_allocatable": reserved_delta,
            "reservation_delta": observed,
            "expected_reservation_delta": expected,
            "matched": observed == expected,
        }
    return results


def main(argv):
    if len(argv) != 3:
        print(f"usage: {Path(argv[0]).name} ZERO_NODE_JSON RESERVED_NODE_JSON", file=sys.stderr)
        return 2
    results = compare(argv[1], argv[2])
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0 if all(item["matched"] for item in results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
