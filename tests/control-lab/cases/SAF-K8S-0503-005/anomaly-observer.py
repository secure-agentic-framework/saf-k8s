"""Small, deterministic counter oracle over captured case-local CoreDNS rows."""
import json
from pathlib import Path

from evaluator import evaluate

rows = json.loads(Path("/fixture/rows.json").read_text())
expected = json.loads(Path("/fixture/expected.json").read_text())
print(json.dumps(evaluate(rows, expected), sort_keys=True))
