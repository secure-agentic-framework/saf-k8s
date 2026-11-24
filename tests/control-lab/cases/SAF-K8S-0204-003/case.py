"""Verify measured filesystem drift and the boundary of a read-only root."""

import hashlib
import json
from pathlib import Path

from fixtures import container, pod, ready

SCOPE = "Measure owned image files and approved writable state, compare against the exact runtime image, and verify independent alert receipt."
HERE = Path(__file__).resolve().parent
SOURCE = hashlib.sha256((HERE / "Dockerfile").read_bytes() + (HERE / "drift-marker.txt").read_bytes()).hexdigest()
IMAGE = "saf-lab-drift-fixture:source-" + SOURCE[:24]
LABEL = "org.saf.fixture.drift-source"
RECEIVER = "fixture-drift-receiver"
DETECTOR = "fixture-drift-comparator"
READ_RECEIPT = ("from urllib.request import urlopen; "
                "print(urlopen('http://127.0.0.1:18082/alerts', timeout=4).read().decode())")


def build(lab):
    found = lab.command("docker", "image", "inspect", IMAGE, allow_failure=True)
    if found.returncode:
        lab.command("docker", "build", "-q", "-t", IMAGE, "--label", f"{LABEL}={SOURCE}", str(HERE), timeout=300)
        found = lab.command("docker", "image", "inspect", IMAGE)
    value, = json.loads(found.stdout)
    if value["Config"]["Labels"].get(LABEL) != SOURCE:
        lab.block("Local image does not match the reviewed baseline build")
    lab.command("kind", "load", "docker-image", IMAGE, "--name", lab.cluster, timeout=180)
    return value


def create(lab, name, *, readonly):
    unit = {"name": "probe", "image": IMAGE, "imagePullPolicy": "Never",
            "command": ["python", "/test/probe.py"],
            "volumeMounts": [{"name": "probe", "mountPath": "/test", "readOnly": True},
                             {"name": "allowed-state", "mountPath": "/state"}],
            "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"cpu": "100m", "memory": "64Mi"}},
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": readonly,
                                "capabilities": {"drop": ["ALL"]}}}
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                "spec": {"backoffLimit": 0, "template": {"spec": {
                    "restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [unit], "volumes": [
                        {"name": "probe", "configMap": {"name": "drift-probe"}},
                        {"name": "allowed-state", "emptyDir": {}},
                    ],
                }}}})


def observations(lab, name):
    lab.kubectl("wait", "--for=condition=Complete", f"job/{name}", "--timeout=60s", timeout=70)
    probe = json.loads(lab.kubectl("logs", f"job/{name}").stdout)
    jobs = json.loads(lab.kubectl("get", "pod", "-l", f"job-name={name}", "-o", "json").stdout)["items"]
    unit, = jobs
    status, = unit["status"]["containerStatuses"]
    return {**probe, "image_id": status["imageID"], "pod_uid": unit["metadata"]["uid"],
            "node": unit["spec"]["nodeName"]}


def collect_alerts(lab, expected, runtime_id, samples):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": DETECTOR}, "immutable": True,
                "data": {"integrity.py": (HERE / "integrity-fixture.py").read_text(),
                         "verified.json": json.dumps({"approved": expected, "image_id": runtime_id,
                                                      "observations": samples})}})
    volumes = [{"name": "samples", "configMap": {"name": DETECTOR}}]
    args = {"image": IMAGE, "imagePullPolicy": "Never",
            "volumeMounts": [{"name": "samples", "mountPath": "/samples", "readOnly": True}]}
    consumer = pod(RECEIVER, [container("receive", **args, command=["python", "/samples/integrity.py", "receive"],
                    readinessProbe={"tcpSocket": {"port": 18082}})],
                    automountServiceAccountToken=False, volumes=volumes)
    consumer["metadata"]["labels"] = {"app": RECEIVER}
    lab.create(consumer)
    service = lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": RECEIVER},
                "spec": {"selector": {"app": RECEIVER}, "ports": [{"port": 18082}]}})
    ready(lab, RECEIVER)
    unit = container("detect", **args, command=["python", "/samples/integrity.py", "compare"],
                     env=[{"name": "FIXTURE_RECEIVER_IP", "value": service["spec"]["clusterIP"]}])
    spec = {"restartPolicy": "Never", "automountServiceAccountToken": False, "volumes": volumes, "containers": [unit]}
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": DETECTOR}, "spec": {
        "backoffLimit": 0, "template": {"spec": spec}}})
    waited = lab.kubectl("wait", "--for=condition=Complete", "job/" + DETECTOR, "--timeout=65s",
                         timeout=75, allow_failure=True)
    detected = lab.kubectl("logs", "job/" + DETECTOR, allow_failure=True)
    if waited.returncode or detected.returncode:
        lab.block("The independent comparator did not complete")
    received = lab.kubectl("exec", "pod/" + RECEIVER, "--", "python", "-c", READ_RECEIPT)
    return json.loads(detected.stdout), json.loads(received.stdout)


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    built = build(lab)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "drift-probe"},
                "immutable": True, "data": {"probe.py": (HERE / "filesystem-fixture.py").read_text()}})
    create(lab, "writable-fixture", readonly=False)
    create(lab, "readonly-fixture", readonly=True)
    mutable = observations(lab, "writable-fixture")
    protected = observations(lab, "readonly-fixture")
    expected = hashlib.sha256((HERE / "drift-marker.txt").read_bytes()).hexdigest()
    changed = mutable["initial_sha256"] == expected and mutable["observed_sha256"] != expected and mutable["root_write"] == "ok"
    lab.check("red", "The approved digest matches initially and the comparator detects a real content change on the writable root",
              changed, {"root_drift_detected": changed})
    intact = protected["initial_sha256"] == protected["observed_sha256"] == expected and protected["root_write"] == "readonly"
    lab.check("green", "The read-only root refuses the same write and its approved digest remains intact",
              intact, {"protected_content_preserved": intact})
    samples = {"mutable": mutable, "protected": protected}
    allowed = all(row["state_initial_sha256"] != row["state_sha256"] for row in samples.values())
    same_image = bool(mutable["image_id"]) and mutable["image_id"] == protected["image_id"]
    runtime = lab.command("docker", "exec", mutable["node"], "crictl", "inspecti", IMAGE).stdout
    imported = json.loads(runtime)
    image = imported["status"]
    image_spec = imported["info"]["imageSpec"]
    runtime_digests = set(image.get("repoDigests") or ()) | {image["id"]}
    layers_match = image_spec["rootfs"]["diff_ids"] == built["RootFS"]["Layers"]
    platform_matches = (image_spec["os"], image_spec["architecture"]) == (built["Os"], built["Architecture"])
    labels_match = image_spec["config"]["Labels"].get(LABEL) == SOURCE
    bound = (layers_match and platform_matches and labels_match and mutable["image_id"] in runtime_digests
             and mutable["node"] == protected["node"])
    lab.check("positive", "CRI identifies the same approved built image for both comparisons and each retains writable state",
              allowed and same_image and bound, {"state_changed_in_both_jobs": allowed, "runtime_bound_to_approved_build": bound})
    detector, received = collect_alerts(lab, expected, mutable["image_id"], samples)
    comparisons = detector["comparisons"]
    expected_comparisons = {label: {"same_bytes_match": True, "approved_volume_changed": True, "drift": label == "mutable"}
                            for label in samples}
    lab.check("green", "The independent comparator distinguishes changed image content from same bytes and allowed state",
              comparisons == expected_comparisons, {"mutable_only_classified_as_drift": comparisons == expected_comparisons})
    event_id = mutable["pod_uid"] + ":image-file"
    expected_alert = {event_id: {"fixture_event_id": event_id, "pod_uid": mutable["pod_uid"], "image_id": mutable["image_id"],
                                 "path": mutable["path"], "baseline_sha256": expected, "observed_sha256": mutable["observed_sha256"]}}
    delivery = received == expected_alert and detector["delivery_acks"] == {"mutable": event_id}
    lab.check("positive", "The independent receiver acknowledges exactly the drift alert tied to its Pod and image",
              delivery, {"exact_attributed_alert_received": delivery})
    (lab.evidence / "filesystem-drift-observations.json").write_text(json.dumps({
        "approved_digest": expected, "build_image_id": built["Id"], "runtime_identity": image["id"],
        "approved_root_layers": built["RootFS"]["Layers"], "runtime_root_layers": image_spec["rootfs"]["diff_ids"],
        "build_source_sha256": SOURCE, "runtime_source_sha256": image_spec["config"]["Labels"][LABEL],
        "mutable": mutable, "protected": protected, "comparison": detector, "received_alerts": received,
    }, indent=2) + "\n")
