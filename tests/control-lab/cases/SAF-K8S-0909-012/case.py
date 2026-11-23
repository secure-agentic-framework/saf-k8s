"""Monitor a benign synthetic RAG index and observe scoped incident handling."""
import hashlib
import importlib.util
import json
from pathlib import Path

from fixtures import pod

HERE = Path(__file__).resolve().parent
NS = "saf-test"  # runner-managed namespace
PVC = "rag-context-index"
CODE = "rag-context-fixture"
REGISTRY = "rag-approved-registry"
CONTROLLER = "rag-context-controller"
AUDITOR = "rag-context-auditor"
CONSUMER = "rag-context-consumer"
ALERTS = "rag-incident-sink"
SCOPE = (
    "Compare a fixed persistent synthetic RAG corpus against an approved generation/source/version/digest "
    "registry. Observe an unmonitored baseline with no detection or response, then detect a fixed "
    "metadata/content discrepancy, emit a sanitized incident to a separate receiver, hold only the "
    "unapproved generation, and restore the approved active pointer. Confirm the held state through a "
    "second read-only PVC consumer, then observe a clean monitoring scan and an ordinary approved release."
)


def runtime_image(lab):
    adjacent = HERE.parent / "SAF-K8S-0908-001" / "case.py"
    if not adjacent.is_file():
        lab.block("Actual adjacent SAF-K8S-0908-001/case.py loader not found")
    spec = importlib.util.spec_from_file_location("saf_k8s_0908_001_runtime", adjacent)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_runtime(lab)

def create(lab, kind, name, **fields):
    return lab.create({"apiVersion": "v1", "kind": kind,
                       "metadata": {"name": name, "namespace": NS}, **fields})


def workload(lab, image, name, command, *, port=None, pvc=None, read_only=False, env=None,
             approved_registry=False):
    mounts = [{"name": "code", "mountPath": "/fixture", "readOnly": True}]
    volumes = [{"name": "code", "configMap": {"name": CODE}}]
    if pvc:
        mounts.append({"name": "index", "mountPath": "/data", "readOnly": read_only})
        volumes.append({"name": "index", "persistentVolumeClaim": {"claimName": PVC, "readOnly": read_only}})
    if approved_registry:
        mounts.append({"name": "registry", "mountPath": "/trusted", "readOnly": True})
        volumes.append({"name": "registry", "configMap": {"name": REGISTRY, "items": [
            {"key": "approved-generations.json", "path": "approved-generations.json"}]}})
    if name == ALERTS:
        mounts.append({"name": "alerts", "mountPath": "/alerts"})
        volumes.append({"name": "alerts", "emptyDir": {}})
    unit = {"name": "fixture", "image": image, "imagePullPolicy": "Never", "command": command,
            "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                                "runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "volumeMounts": mounts}
    if env:
        unit["env"] = [{"name": key, "value": value} for key, value in env.items()]
    if port:
        unit["ports"] = [{"containerPort": port}]
        unit["readinessProbe"] = {"tcpSocket": {"port": port}, "periodSeconds": 1}
    request = pod(name, [unit], automountServiceAccountToken=False, volumes=volumes,
                  securityContext={"fsGroup": 65534})
    request["metadata"]["namespace"] = NS
    request["metadata"]["labels"] = {"app": name}
    lab.create(request)
    if port:
        create(lab, "Service", name,
               spec={"selector": {"app": name}, "ports": [{"port": port, "targetPort": port}]})


def observe(lab, mode, pod_name=CONTROLLER):
    raw = lab.kubectl("exec", "pod/" + pod_name, "--", "python", "/fixture/fixture.py", mode, timeout=20).stdout
    return json.loads(raw.strip())


def run(lab):
    image = runtime_image(lab)
    fixture = (HERE / "fixture.py").read_text()
    create(lab, "ConfigMap", CODE, immutable=True, data={"fixture.py": fixture})
    registry = {
        "gen-cedar-v1": {"source_id": "synthetic://cedar", "version": "v1",
                         "chunk_id": "chunk-cedar",
                         "sha256": hashlib.sha256(b"Cedar sample color is amber.").hexdigest()},
        "gen-maple-v1": {"source_id": "synthetic://maple", "version": "v1",
                         "chunk_id": "chunk-maple",
                         "sha256": hashlib.sha256(b"Maple sample color is green.").hexdigest()},
    }
    # The candidate generation has an expected approved content binding independent of its stored bytes.
    registry["gen-unapproved"] = dict(registry["gen-cedar-v1"])
    create(lab, "ConfigMap", REGISTRY, immutable=True,
           data={"approved-generations.json": json.dumps(registry, sort_keys=True)})
    create(lab, "PersistentVolumeClaim", PVC,
           spec={"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}})

    # Create every PVC consumer before waiting: WaitForFirstConsumer classes bind only after scheduling.
    workload(lab, image, CONSUMER, ["python", "/fixture/fixture.py", "serve", "consumer"], port=8081)
    workload(lab, image, ALERTS, ["python", "/fixture/fixture.py", "serve", "alerts"], port=8082)
    workload(lab, image, CONTROLLER, ["python", "/fixture/fixture.py", "serve", "controller"],
             port=8080, pvc=True,
             approved_registry=True,
             env={"CONSUMER_URL": f"http://{CONSUMER}:8081", "ALERT_URL": f"http://{ALERTS}:8082"})
    workload(lab, image, AUDITOR, ["sleep", "300"], pvc=True, read_only=True)
    for name in (CONSUMER, ALERTS, CONTROLLER, AUDITOR):
        lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=95s", timeout=105)

    baseline = observe(lab, "baseline")
    baseline_alerts = observe(lab, "alert-status")
    baseline_state = observe(lab, "audit", AUDITOR)
    baseline_check = {"ordinary_unmonitored_release_occurred": baseline["forwarded"]
                      and baseline["consumer_delta"] == 1,
                      "baseline_had_no_detection": baseline["detection_count"] == 0,
                      "baseline_had_no_response": baseline["incident_count"] == 0
                      and baseline_alerts["count"] == 0 and baseline_state["held_generations"] == []
                      and not baseline_state["monitoring"]
                      and baseline_state["active_generation"] == "gen-unapproved"}
    lab.check("red", "The baseline releases its fixed fixture generation with no detection or response",
              all(baseline_check.values()), baseline_check)

    incident = observe(lab, "scan")
    held = observe(lab, "audit", AUDITOR)
    alert_state = observe(lab, "alert-status")
    alert_count = alert_state["count"]
    discrepancy = incident["detections"][0] if incident["detections"] else {}
    green = {
        "fixed_metadata_content_discrepancy_detected": len(incident["detections"]) == 1
            and discrepancy.get("generation") == "gen-unapproved"
            and discrepancy.get("reason") == "metadata_content_digest_mismatch"
            and discrepancy.get("expected_sha256") != discrepancy.get("observed_sha256"),
        "independent_alert_sink_received_one_event": alert_count == 1,
        "alert_sink_record_matches_detected_event": alert_state["receipts"] == [discrepancy],
        "incident_action_held_only_fixture_generation": incident["held_generations"] == ["gen-unapproved"]
            and incident["incident_action"] == "held-scoped-generation-and-restored-approved-pointer"
            and held["held_generation_present"] and not held["unapproved_generation_present_in_active_index"],
        "active_pointer_rolled_back_to_approved_generation": incident["active_generation"] == "gen-cedar-v1"
            and held["active_generation"] == "gen-cedar-v1",
        "monitoring_stays_enabled": held["monitoring"] and held["scan_count"] == 1,
    }
    lab.check("green", "Integrity monitoring alerts independently and holds the discrepant generation",
              all(green.values()), {"incident": incident, "held_state": held, "alert_count": alert_count})

    blocked = observe(lab, "release-held")
    lab.check("green", "The held generation cannot reach the ordinary consumer",
              blocked == {"held_generation_denied": True, "consumer_delta": 0}, blocked)
    positive = observe(lab, "positive")
    positive_check = {"approved_ordinary_release_succeeds": positive["approved_ordinary_generation_released"]
                      and positive["consumer_delta"] == 1
                      and positive["consumer_receipt"]["generation"] == "gen-maple-v1",
                      "monitoring_clean_scan_has_no_false_incident": positive["monitoring_remains_enabled"]
                      and positive["clean_scan_detected_nothing"] and positive["clean_scan_emitted_no_incident"]
                      and positive["alert_count"] == alert_count,
                      "held_generation_remains_scoped": positive["held_generations"] == ["gen-unapproved"]}
    lab.check("positive", "Monitoring remains clean and an approved ordinary generation is released",
              all(positive_check.values()), positive)
    receipt = {"scope": "fixed-benign-synthetic-corpus", "namespace": NS,
               "red": baseline_check, "green": green, "positive": positive_check,
               "incident": {"generation": "gen-unapproved", "reason": "metadata_content_digest_mismatch",
                            "action": "held-scoped-generation-and-restored-approved-pointer",
                            "alert_sink_count": alert_count}}
    (lab.evidence / "rag-context-monitoring.json").write_text(
        json.dumps(receipt, sort_keys=True, indent=2) + "\n")
