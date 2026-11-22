"""Fixed authenticated requests from the case-owned MLflow client Pod."""
import base64
import json
import sys
from urllib.request import Request, urlopen

CREDS = {
    "lab-admin": "fixture-admin-key-0904",
    "lab-reader": "fixture-reader-key-0904",
    "lab-writer": "fixture-writer-key-0904",
}


def request(base, actor, operation, phase, **fields):
    body = json.dumps({"operation": operation, "phase": phase, **fields}, sort_keys=True).encode()
    credential = base64.b64encode((actor + ":" + CREDS[actor]).encode()).decode()
    req = Request(base + "/dispatch", data=body, method="POST", headers={
        "Content-Type": "application/json", "Authorization": "Basic " + credential,
    })
    with urlopen(req, timeout=5) as response:
        return json.loads(response.read())


def phase(base, name):
    experiment = request(base, "lab-admin", "create_experiment", name)
    experiment_id = experiment["resource_id"]
    read = request(base, "lab-reader", "get_experiment", name, experiment_id=experiment_id)
    run = request(base, "lab-writer", "create_run", name, experiment_id=experiment_id)
    run_id = run["resource_id"]
    write = request(base, "lab-writer", "log_parameter", name, run_id=run_id)
    delete = request(base, "lab-writer", "delete_run", name, run_id=run_id)
    return {
        "dispatch": ["administrative", "read", "write", "write", "delete"],
        "http_successes": [True] * 5,
        "api_successes": [all(item.get("ok") is True for item in (experiment, read, run, write, delete))],
        "resource_ids": {"experiment_id": experiment_id, "run_id": run_id},
    }


if len(sys.argv) == 3 and sys.argv[1] == "--health":
    with urlopen(sys.argv[2] + "/health", timeout=2) as response:
        print(json.dumps({"ready": response.status == 200}, sort_keys=True))
elif len(sys.argv) == 3 and sys.argv[1] in ("off", "on"):
    try:
        print(json.dumps(phase(sys.argv[2], sys.argv[1]), sort_keys=True))
    except Exception:
        # Never echo request headers, bodies, credentials, or exception strings.
        print(json.dumps({"fixture_request_failed": True}, sort_keys=True))
        raise SystemExit(2)
elif len(sys.argv) == 4 and sys.argv[1] == "--positive":
    try:
        base, experiment_id = sys.argv[2:]
        result = request(base, "lab-reader", "get_experiment", "on", experiment_id=experiment_id)
        print(json.dumps({"read_succeeded": result.get("ok") is True,
                          "resource_id": result.get("resource_id")}, sort_keys=True))
    except Exception:
        print(json.dumps({"fixture_request_failed": True}, sort_keys=True))
        raise SystemExit(2)
else:
    raise SystemExit(2)
