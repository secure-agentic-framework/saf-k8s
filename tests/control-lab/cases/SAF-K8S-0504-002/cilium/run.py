"""Run the Cilium runtime case for SAF-K8S-0504-002 in a fresh Kind cluster."""
import argparse
import json
import os
from pathlib import Path
import sys

import cilium_case

LAB_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(LAB_ROOT))
from lab import run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog-index", type=Path, default=LAB_ROOT / "catalog/index.json")
    parser.add_argument("--docker-context", default=os.getenv("DOCKER_CONTEXT") or "default")
    args = parser.parse_args()
    index = json.loads(args.catalog_index.read_text())
    control = cilium_case.CONTROL_ID
    if control not in index["controls"]:
        parser.error(f"{control} is absent from {args.catalog_index}")
    return run(control, cilium_case, index, args.docker_context)


if __name__ == "__main__":
    raise SystemExit(main())
