"""Exercise actor-aware audit coverage on fixed MLflow tracking API traffic."""
import json
from pathlib import Path
import time

CONTROL_ID = "SAF-K8S-0904-016"
IMAGE = "ghcr.io/mlflow/mlflow:v3.5.1@sha256:7a8c21cd553b84227391ad7daa39c029dab64328da7607c372370cfa07ef43d9"
NAMESPACE = "saf-test"
BASE = "http://saf-0904-016-bridge:8080"
HERE = Path(__file__).resolve().parent
SCOPE = (
    "One fresh Kind v1.36.1 cluster in the runner's saf-test namespace; official MLflow "
    "3.5.1 server and client image, one SQLite backend, and a same-Pod authenticated "
    "append-only audit bridge. The server binds only to Pod loopback; the only Service "
    "targets the bridge. A fixed five-request sequence exercises experiment creation, "
    "experiment read, run creation, parameter write, and run deletion through actual "
    "MLflow REST APIs with three fixture-only Basic-auth symbolic actors. The sequence "
    "runs once with audit off and once with audit on; a separate permitted read checks "
    "continued access. Dynamic experiment/run IDs are retained only in raw evidence. "
    "This is not proof of production identity federation, every MLflow endpoint, artifact "
    "store access, durable/tamper-resistant export, retention, or Kubernetes network policy."
)


def _exec(lab, pod, container, *args, timeout=30, allow_failure=False):
    return lab.kubectl("exec", f"pod/{pod}", "-c", container, "--",
                       *args, timeout=timeout, allow_failure=allow_failure)


def _client_exec(lab, *args, timeout=40):
    return lab.kubectl("exec", "pod/saf-0904-016-client", "-c", "client", "--",
                       "python", "-B", "/fixture/client.py", *args,
                       timeout=timeout, allow_failure=True)


def _client(lab, *args):
    result = _exec(lab, "saf-0904-016-client", "client", "python", "-B", "/fixture/client.py", *args,
                   timeout=40, allow_failure=True)
    if result.returncode != 0:
        lab.block("The fixed authenticated MLflow request sequence did not complete")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError:
        lab.block("The fixture client returned no typed operation receipt")
    if value.get("fixture_request_failed"):
        lab.block("A fixed MLflow API request failed; no security conclusion is available")
    return value


def _audit_events(lab):
    script = (
        "from pathlib import Path; import json; p=Path('/audit/events.jsonl'); "
        "print(json.dumps([json.loads(x) for x in p.read_text().splitlines()] "
        "if p.exists() else [],sort_keys=True))"
    )
    result = _exec(lab, "saf-0904-016-tracking", "audit-bridge", "python", "-B", "-c", script)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        lab.block("Persisted audit evidence is not valid JSONL")


def _wait_ready(lab):
    deadline = time.monotonic() + 90
    last = None
    while time.monotonic() < deadline:
        result = _exec(lab, "saf-0904-016-client", "client", "python", "-B", "/fixture/client.py",
                       "--health", BASE, timeout=8, allow_failure=True)
        if result.returncode == 0:
            try:
                last = json.loads(result.stdout)
                if last == {"ready": True}:
                    return
            except json.JSONDecodeError:
                pass
        time.sleep(1)
    lab.block("The pinned MLflow backend did not become healthy behind the bridge")


def _set_mode(lab, mode):
    lab.kubectl("patch", "configmap/saf-0904-016-audit-mode", "--type=merge", "-p",
                json.dumps({"data": {"audit-mode": mode}}))
    lab.kubectl("annotate", "pod", "saf-0904-016-tracking",
                f"saf.example.test/audit-mode={mode}", "--overwrite")
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        result = _exec(lab, "saf-0904-016-tracking", "audit-bridge", "python", "-B", "-c",
                       "from pathlib import Path; print(Path('/mode/audit-mode').read_text().strip())",
                       allow_failure=True)
        if result.returncode == 0 and result.stdout.strip() == mode:
            return
        time.sleep(0.5)
    lab.block("The fixture audit-mode ConfigMap did not reach the mounted bridge")


def _summary(receipt):
    return {
        "dispatch": receipt.get("dispatch"),
        "http_successes": receipt.get("http_successes"),
        "api_successes": receipt.get("api_successes"),
    }


def run(lab):
    # The manifest is namespace-explicit for every object and the runner's default
    # namespace is repeated in the case constants and scope.
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "saf-0904-016-fixtures"}, "immutable": True,
                "data": {name: (HERE / name).read_text() for name in ("bridge.py", "client.py")}})
    lab.apply(HERE / "manifest.yaml")
    lab.kubectl("wait", "--for=condition=Ready", "pod/saf-0904-016-tracking", "--timeout=90s",
                timeout=100)
    lab.kubectl("wait", "--for=condition=Ready", "pod/saf-0904-016-client", "--timeout=60s",
                timeout=70)
    _wait_ready(lab)

    _set_mode(lab, "off")
    red = _client(lab, "off", BASE)
    red_events = _audit_events(lab)
    red_summary = _summary(red)
    lab.check(
        "red",
        "With the audit bridge disabled, fixed MLflow API operations succeed but leave no persisted actor-aware events",
        red_summary == {
            "dispatch": ["administrative", "read", "write", "write", "delete"],
            "http_successes": [True] * 5,
            "api_successes": [True],
        } and red_events == [],
        {"all_fixed_api_operations_succeeded": red_summary.get("api_successes") == [True],
         "persisted_event_count": len(red_events)},
    )
    _set_mode(lab, "on")
    green = _client(lab, "on", BASE)
    green_events = _audit_events(lab)
    expected_events = [
        ("lab-admin", "administrative", "success"),
        ("lab-reader", "read", "success"),
        ("lab-writer", "write", "success"),
        ("lab-writer", "write", "success"),
        ("lab-writer", "delete", "success"),
    ]
    event_shape = [(event.get("actor"), event.get("operation"), event.get("result"))
                   for event in green_events]
    ids_present = all(isinstance(event.get("resource_id"), str) and event["resource_id"]
                      for event in green_events)
    same_dispatch = red_summary == _summary(green)
    lab.check(
        "green",
        "With audit enabled, the same successful MLflow dispatch persists actor, operation, resource ID, and result",
        same_dispatch and event_shape == expected_events and ids_present
        and len(green_events) == 5,
        {"same_dispatch_and_success": same_dispatch,
         "event_actor_operation_result": event_shape,
         "resource_ids_present": ids_present,
         "persisted_event_count": len(green_events)},
    )

    positive = _client(lab, "--positive", BASE, green["resource_ids"]["experiment_id"])
    positive_events = _audit_events(lab)
    positive_event = positive_events[-1] if positive_events else {}
    positive_ok = (
        positive.get("read_succeeded") is True
        and positive_event.get("actor") == "lab-reader"
        and positive_event.get("operation") == "read"
        and positive_event.get("result") == "success"
        and bool(positive_event.get("resource_id"))
        and len(positive_events) == 6
    )
    lab.check(
        "positive",
        "An approved reader continues to retrieve the fixed experiment while an attributable read event is persisted",
        positive_ok,
        {"read_succeeded": positive.get("read_succeeded") is True,
         "reader_read_success_recorded": positive_ok,
         "persisted_event_count": len(positive_events)},
    )

    # Dynamic IDs and the complete audit rows belong in raw evidence, not assertions.
    raw = {"red_dispatch": red, "red_persisted_events": red_events,
           "green_dispatch": green, "green_persisted_events": green_events,
           "positive_read": positive, "positive_persisted_events": positive_events}
    (lab.evidence / "mlflow-audit.raw.json").write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
