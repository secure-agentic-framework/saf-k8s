"""Collect selected real syscalls from an owned child and confirm attributed delivery to an independent Kind receiver."""

from decimal import Decimal
import hashlib
import json
from pathlib import Path

from fixtures import container, pod, ready

SCOPE = "Collect selected real syscalls from an owned child and confirm attributed delivery to an independent Kind receiver."
HERE = Path(__file__).resolve().parent
SOURCE = hashlib.sha256((HERE / "Dockerfile").read_bytes()).hexdigest()
TOOLS = "saf-lab-runtime-observation:source-" + SOURCE[:24]
LABEL = "org.saf.fixture.runtime-source"
NAME = "fixture-runtime-events"
RECEIVER = "fixture-runtime-receiver"
FIELDS = {"POD_UID": "metadata.uid", "POD_NAME": "metadata.name",
          "POD_NAMESPACE": "metadata.namespace", "NODE_NAME": "spec.nodeName"}


def image(lab):
    checked = lab.command("docker", "image", "inspect", TOOLS, allow_failure=True)
    if checked.returncode:
        lab.command("docker", "build", "-q", "-t", TOOLS, "--label", f"{LABEL}={SOURCE}",
                    "-f", str(HERE / "Dockerfile"), str(HERE), timeout=420)
        checked = lab.command("docker", "image", "inspect", TOOLS)
    record, = json.loads(checked.stdout)
    if record["Config"]["Labels"].get(LABEL) != SOURCE:
        lab.block("The local guest fixture image does not match the tested build recipe")
    return record["Id"]


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    expected_image = image(lab)
    lab.command("kind", "load", "docker-image", TOOLS, "--name", lab.cluster, timeout=210)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME},
                "immutable": True, "data": {"probe.py": (HERE / "runtime-fixture.py").read_text(),
                                            "receiver.py": (HERE / "runtime-receiver.py").read_text()}})
    receiver = pod(RECEIVER, [container("receiver", image=TOOLS, imagePullPolicy="Never",
                   command=["python", "/test/receiver.py"], readinessProbe={"tcpSocket": {"port": 18082}},
                   volumeMounts=[{"name": "fixture", "mountPath": "/test", "readOnly": True}])],
                   automountServiceAccountToken=False, volumes=[{"name": "fixture", "configMap": {"name": NAME}}])
    receiver["metadata"]["labels"] = {"app": RECEIVER}
    lab.create(receiver)
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": RECEIVER},
                "spec": {"selector": {"app": RECEIVER}, "ports": [{"port": 18082}]}})
    ready(lab, RECEIVER)
    unit = {"name": "guest", "image": TOOLS, "imagePullPolicy": "Never",
            "command": ["python", "/test/probe.py"],
            "env": [{"name": name, "valueFrom": {"fieldRef": {"fieldPath": field}}} for name, field in FIELDS.items()],
            "volumeMounts": [{"name": "fixture", "mountPath": "/test", "readOnly": True},
                             {"name": "temporary", "mountPath": "/tmp"}],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "25m", "memory": "24Mi"},
                          "limits": {"cpu": "150m", "memory": "96Mi"}}}
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": NAME},
                "spec": {"backoffLimit": 0, "template": {"spec": {
                    "restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [unit], "volumes": [
                        {"name": "fixture", "configMap": {"name": NAME}}, {"name": "temporary", "emptyDir": {}}],
                }}}})
    completion = lab.kubectl("wait", "--for=condition=Complete", "job/" + NAME,
                             "--timeout=135s", timeout=145, allow_failure=True)
    logs = lab.kubectl("logs", "job/" + NAME, allow_failure=True)
    if completion.returncode or logs.returncode:
        lab.block("The scoped runtime observation fixture did not complete; inspect its owned Job result")
    observations = json.loads(logs.stdout)
    lab.check("red", "The public workload completes without creating a trace when collection is disabled",
              observations["workload_without_capture_emits_no_record"],
              {"disabled_capture_observed": observations["workload_without_capture_emits_no_record"]})
    required = {"owned_file_open", "loopback_connection", "known_child_executed"}
    sender = observations["sender"]
    emitted = {row["signal"] for row in sender["events"]}
    timestamps = [Decimal(row["time_unix"]) for row in sender["events"]]
    lab.check("green", "Native tracing observes the three selected actions and timestamps each",
              emitted == required and len(timestamps) == 3 and all(stamp > 0 for stamp in timestamps),
              {"all_three_selected_signals": emitted == required, "source_timestamps_present": len(timestamps) == 3})
    scoped = observations["out_of_scope_open_observed_locally"] and emitted == required
    lab.check("positive", "The workload completes and its out-of-scope file open is excluded from forwarded telemetry",
              observations["workload_with_capture_completed"] and scoped, {"delivery_scope_respected": scoped})
    rows = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={NAME}", "-o", "json").stdout)["items"]
    worker, = rows
    status, = worker["status"]["containerStatuses"]
    peer = lab.kubectl("exec", "pod/" + RECEIVER, "--", "python", "-c",
                        "from urllib.request import urlopen; print(urlopen('http://127.0.0.1:18082/state', timeout=4).read().decode())")
    state = json.loads(peer.stdout)
    metadata = worker["metadata"]
    identity_matches = (sender["pod_uid"], sender["pod_name"], sender["namespace"], sender["node_name"]) == (
        metadata["uid"], metadata["name"], metadata["namespace"], worker["spec"]["nodeName"])
    retry_ok = observations["initial_delivery_status"] == 503 and state["http_rejections"] == 1
    lab.check("green", "The collector observes the receiver outage and retries the same scoped batch",
              retry_ok, {"failed_delivery_visible": retry_ok})
    received = state["receipts"] == {metadata["uid"]: sender}
    ack = observations["ack"] == {"accepted": 3, "pod_uid": metadata["uid"]}
    lab.check("positive", "The separate receiver confirms every event exactly once with the actual Kubernetes workload identity",
              identity_matches and received and ack, {"identity_matches_pod": identity_matches,
                                                      "all_events_accepted_once": received and ack})
    (lab.evidence / "runtime-visibility-observations.json").write_text(json.dumps({
        "build_image": expected_image, "running_image": status["imageID"],
        **observations, "receiver": state,
    }, indent=2) + "\n")
