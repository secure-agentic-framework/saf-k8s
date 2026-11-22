"""Run a finite HTTP workload inside the case-owned Pod."""

import json
from pathlib import Path
import secrets
import sys
from tempfile import TemporaryDirectory

from synthetic_services import MODEL, SYNTHETIC_PROMPT, ScopedCollector, SyntheticApplication
from synthetic_services import post_synthetic_request


def run(collect, path):
    collector = ScopedCollector(path) if collect else None
    app = SyntheticApplication(collector.url if collector else None)
    if collector:
        collector.start()
    app.start()
    event_id = f"saf-k8s-1001-007-{secrets.token_hex(16)}"
    try:
        status, response = post_synthetic_request(app.url, event_id)
    finally:
        app.close()
        if collector:
            collector.close()

    stored = path.read_text() if path.is_file() else ""
    records = [json.loads(line) for line in stored.splitlines()]
    summary = {
        "event_id": event_id,
        "status": status,
        "response_matches_event": response.get("event_id") == event_id,
        "records": len(records),
    }
    if collect:
        summary.update(
            persisted_event_matches_allowlist=records == [{
                "event_id": event_id,
                "event_type": "inference_completed",
                "model": MODEL["name"],
                "model_version": MODEL["version"],
                "outcome": "synthetic-success",
            }],
            prompt_absent_from_record=SYNTHETIC_PROMPT not in stored,
        )
    return summary


if __name__ == "__main__":
    with TemporaryDirectory() as directory:
        print(json.dumps(run(sys.argv[1] == "green", Path(directory) / "events.jsonl")))
