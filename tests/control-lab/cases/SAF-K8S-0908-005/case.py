"""Isolated marker-detection and real alert-delivery fixture for SAF-K8S-0908-005."""
import importlib.util
import json
from pathlib import Path



HERE = Path(__file__).resolve().parent
NS = "saf-test"
SCOPE = (
    "Case-owned synthetic requests exercise an actual configured marker event and its "
    "delivery to a separate HTTP receiver in Kind. Sanitized fields correlate the "
    "fixture request, claimed principal and model. A routine request still succeeds "
    "without an alert. Actual identity binding and external monitoring require site evidence."
)
BASELINE = "fixture-model-baseline"
ENFORCED = "fixture-model-enforced"
ALERT = "fixture-alert"
CLIENT = "fixture-client"
CODE = "fixture-code"
EXPECTED_ALERT = {
    "event": "model-marker-detected",
    "alert_id": "alert-req-marker-001",
    "rule_id": "fixture.marker.review.v1",
    "request_id": "req-marker-001",
    "principal": "fixture:principal:reviewer",
    "model_id": "fixture-model-v1",
    "marker": "review",
}
OK = {"status": 200, "response": {
    "status": "ok", "model_id": "fixture-model-v1", "label": "fixture-class-a"}}


def load_runtime(lab):
    """Load the shared pinned-image helper supplied by SAF-K8S-0908-001."""
    helper = Path(__file__).resolve().parents[1] / "SAF-K8S-0908-001" / "case.py"
    if not helper.is_file():
        lab.block(f"Required shared runtime helper is unavailable: {helper}")
    spec = importlib.util.spec_from_file_location("saf_k8s_0908_001_runtime", helper)
    if spec is None or spec.loader is None:
        lab.block("Could not load the shared SAF-K8S-0908-001 runtime helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_runtime(lab)


def create(lab, manifest):
    lab.create(manifest)


def call(lab, service_name, record):
    result = lab.kubectl("exec", f"pod/{CLIENT}", "--", "python", "/fixture/fixture_service.py",
                         "probe", service_name, record, timeout=12)
    return json.loads(result.stdout)


def alerts(lab):
    raw = lab.kubectl("logs", f"pod/{ALERT}").stdout
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def run(lab):
    image = load_runtime(lab)
    spec = importlib.util.spec_from_file_location("saf_alert_resources", HERE/"alert_resources.py")
    resources = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(resources)
    create(lab, {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CODE},
                 "immutable": True,
                 "data": {"fixture_service.py": (HERE / "fixture_service.py").read_text()}})

    for name, role, ports in (
        (ALERT, "alert-sink", (8082,)),
        (BASELINE, "baseline", (8080,)),
        (ENFORCED, "enforced", (8081,)),
    ):
        create(lab, resources.pod(name, image, role, ports=ports))
        create(lab, resources.service(name, ports[0]))
    create(lab, resources.pod(CLIENT, image, "client"))
    for name in (ALERT, BASELINE, ENFORCED, CLIENT):
        resources.ready(lab, name)

    before_normal = call(lab, BASELINE, "normal")
    before_marker = call(lab, BASELINE, "selected")
    red_alerts = alerts(lab)
    red = {
        "normal_fixed_record_returns_success_without_rule": before_normal == OK,
        "selected_benign_marker_returns_success_without_rule": before_marker == OK,
        "no_alert_before_rule": red_alerts == [],
    }
    lab.check("red", "Baseline accepts both fixed benign records and emits no alert",
              all(red.values()), red)

    selected = call(lab, ENFORCED, "selected")
    routed = alerts(lab)
    green = {
        "selected_marker_request_succeeds": selected == OK,
        "alert_is_delivered_to_separate_receiver": routed == [EXPECTED_ALERT],
        "delivered_alert_has_fixed_principal_request_and_model_attribution":
            len(routed) == 1 and all(routed[0].get(key) == EXPECTED_ALERT[key]
                                     for key in ("principal", "request_id", "model_id")),
        "alert_receiver_logs_no_features_or_prompt_text":
            len(routed) == 1 and set(routed[0]) == set(EXPECTED_ALERT),
    }
    lab.check("green", "The configured marker rule routes one attributed alert over HTTP",
              all(green.values()), green)

    normal = call(lab, ENFORCED, "normal")
    after_normal = alerts(lab)
    positive = {
        "normal_tolerated_record_returns_success": normal == OK,
        "normal_record_does_not_create_an_additional_alert": after_normal == [EXPECTED_ALERT],
    }
    lab.check("positive", "A normal fixed request succeeds under the detector without another alert",
              all(positive.values()), positive)

    evidence = {
        "case": "SAF-K8S-0908-005",
        "status": "observed-by-runner",
        "scope": "local isolated Kind fixture; synthetic model response; fixed benign request records",
        "request_schema": {
            "required_fields": ["request_id", "principal", "model_id", "marker", "features"],
            "feature_fields": ["signal", "context"],
            "feature_range": [0, 1],
            "logs_include_features": False,
        },
        "checks": {"red": red, "green": green, "positive": positive},
        "sanitized_alert": EXPECTED_ALERT,
    }
    (lab.evidence / "model-marker-detection.json").write_text(
        json.dumps(evidence, sort_keys=True, indent=2) + "\n")
