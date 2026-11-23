"""Apply a single-process relying-party policy to inert evidence records."""

import json
from pathlib import Path

fixtures = json.loads(Path("/fixture/requests.json").read_text())
consumed = set()
results = {}
for request in fixtures:
    record = request["record"]
    challenge = record["challenge"]
    if not request["signature_verified"]:
        result = "invalid-signature"
    elif record["subject"] != request["expected_subject"] or record["reference"] != request["expected_reference"]:
        result = "binding-mismatch"
    elif record["issued"] > request["now"] or request["now"] >= record["expires"]:
        result = "outside-validity"
    elif challenge != request["expected_challenge"]:
        result = "challenge-mismatch"
    elif challenge in consumed:
        result = "already-used"
    else:
        consumed.add(challenge)
        result = "eligible-fixture"
    results[request["name"]] = result
print(json.dumps(results, sort_keys=True))
