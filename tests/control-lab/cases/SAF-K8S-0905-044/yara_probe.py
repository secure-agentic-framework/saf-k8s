"""Run a pinned defensive signature engine on two inert JSON fixtures."""

import hashlib
import importlib.metadata
import json
from pathlib import Path

import yara_x


def scan(path, rules):
    data = path.read_bytes()
    if len(data) > 2048:
        raise ValueError("Fixed scan input exceeds the fixture length bound")
    document = json.loads(data)
    if (set(document) != {"format", "marker", "model_id", "parameters"}
            or document["format"] != "saf-inert-model-json-v1"):
        raise ValueError("Fixture is not the expected inert JSON")
    matches = rules.scan(data).matching_rules
    return {"sha256": hashlib.sha256(data).hexdigest(),
            "matching_rules": sorted(rule.identifier for rule in matches)}


def main():
    fixture = Path("/fixture")
    rule_source = (fixture / "fixture.yar").read_bytes()
    rules = yara_x.compile(rule_source.decode())
    print(json.dumps({
        "scanner": "yara-x",
        "version": importlib.metadata.version("yara-x"),
        "rule_sha256": hashlib.sha256(rule_source).hexdigest(),
        "approved": scan(fixture / "model.json", rules),
        "flagged": scan(fixture / "flagged.json", rules),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
