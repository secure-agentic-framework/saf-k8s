"""Live Kubernetes check for typed defensive RAG request assembly."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
NS = "saf-test"  # runner-managed namespace
CODE = "fixture-rag-context-code"
SOURCE = "fixture-rag-context-source"
APPROVAL = "fixture-rag-context-approval"
CONSUMER = "fixture-rag-context-consumer"
DRIVER = "fixture-rag-context-driver"
SERVICE = CONSUMER
PORT = 8080
ANSWER = "Cedar sample color is amber."
NOTE = {
    "record_id": "note-cedar-v1",
    "source_id": "synthetic://approved/field-guide",
    "version": 1,
    "text": ANSWER,
    "metadata": {"topic": "sample-facts", "visibility": "public"},
}
SCOPE = (
    "Compare one fixed benign synthetic RAG record in two request-assembly modes. The baseline "
    "places the record in a system-role message. Governed middleware validates exact schema, "
    "approved source/version, metadata, and digest, keeps the record in a typed data field, and "
    "uses application-owned message roles. A separate local consumer observes roles and exact "
    "records and returns a deterministic approved answer. No model or tools are involved."
)


def load_runtime(lab):
    source = HERE.parent / "SAF-K8S-0908-001" / "case.py"
    if not source.is_file():
        lab.block("Actual adjacent SAF-K8S-0908-001/case.py runtime helper is unavailable")
    spec = importlib.util.spec_from_file_location("saf_k8s_0908_001_runtime", source)
    if spec is None or spec.loader is None:
        lab.block("Could not import the actual adjacent runtime helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_runtime(lab)


def create(lab, kind, name, **fields):
    return lab.create({"apiVersion": "v1", "kind": kind,
                       "metadata": {"name": name, "namespace": NS}, **fields})


def fixture_pod(lab, image, name, command, *, expose=False, source=False, approval=False):
    mounts = [{"name": "code", "mountPath": "/fixture", "readOnly": True}]
    volumes = [{"name": "code", "configMap": {"name": CODE}}]
    if source:
        mounts.append({"name": "source", "mountPath": "/source", "readOnly": True})
        volumes.append({"name": "source", "configMap": {"name": SOURCE}})
    if approval:
        mounts.append({"name": "approval", "mountPath": "/approval", "readOnly": True})
        volumes.append({"name": "approval", "configMap": {"name": APPROVAL}})
    container = {
        "name": "fixture", "image": image, "imagePullPolicy": "Never", "command": command,
        "volumeMounts": mounts,
        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True,
                            "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
        "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                      "limits": {"cpu": "200m", "memory": "128Mi"}},
    }
    if expose:
        container["ports"] = [{"containerPort": PORT}]
        container["readinessProbe"] = {"tcpSocket": {"port": PORT}, "periodSeconds": 1}
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": name, "namespace": NS, "labels": {"app": name}},
           "spec": {"restartPolicy": "Always" if expose else "Never",
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [container], "volumes": volumes}}
    lab.create(pod)
    if expose:
        create(lab, "Service", SERVICE,
               spec={"selector": {"app": name}, "ports": [{"port": PORT, "targetPort": PORT}]})


def observe(lab, mode):
    raw = lab.kubectl("exec", "pod/" + DRIVER, "--", "python", "/fixture/context_fixture.py",
                      "exercise", f"http://{SERVICE}:{PORT}", mode, timeout=20).stdout
    return json.loads(raw)


def run(lab):
    image = load_runtime(lab)
    fixture = (HERE / "context_fixture.py").read_text(encoding="utf-8")
    create(lab, "ConfigMap", CODE, immutable=True, data={"context_fixture.py": fixture})
    create(lab, "ConfigMap", SOURCE, immutable=True,
           data={"note.json": json.dumps(NOTE, sort_keys=True, separators=(",", ":"))})
    approval = {"source_id": NOTE["source_id"], "version": NOTE["version"], "record": NOTE}
    canonical = json.dumps(NOTE, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    import hashlib
    approval["sha256"] = hashlib.sha256(canonical).hexdigest()
    create(lab, "ConfigMap", APPROVAL, immutable=True,
           data={"approved.json": json.dumps(approval, sort_keys=True, separators=(",", ":"))})

    fixture_pod(lab, image, CONSUMER, ["python", "/fixture/context_fixture.py", "serve"], expose=True)
    fixture_pod(lab, image, DRIVER, ["sleep", "3600"], source=True, approval=True)
    for name in (CONSUMER, DRIVER):
        lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=95s", timeout=105)

    baseline = observe(lab, "baseline")
    red = {
        "same_fixed_record_observed": baseline["consumer"]["records"] == [NOTE],
        "baseline_places_record_in_system_role": baseline["consumer"]["message_roles"] == ["system"]
            and baseline["consumer"]["baseline_record_in_system"],
        "baseline_returns_benign_deterministic_answer": baseline["consumer"]["output"] == ANSWER,
    }
    lab.check("red", "The benign baseline places retrieved data in the authority-bearing system role",
              all(red.values()), red)

    governed = observe(lab, "governed")
    expected_roles = ["system", "user"]
    green = {
        "approved_schema_provenance_and_digest_validate": all(governed["checks"].values()),
        "source_record_is_observed_exactly": governed["consumer"]["records"] == [NOTE],
        "roles_are_application_owned": governed["consumer"]["message_roles"] == expected_roles,
        "messages_are_exact_application_text": governed["consumer"]["fixed_application_messages"],
        "metadata_is_not_rendered_as_messages": governed["consumer"]["records"][0]["metadata"] == NOTE["metadata"],
        "stable_benign_answer": governed["consumer"]["output"] == ANSWER,
        "benign_content_change_is_rejected": governed["negative_validation"]["benign_content_change_rejected"],
        "unapproved_source_is_rejected": governed["negative_validation"]["unapproved_source_rejected"],
        "extra_metadata_field_is_rejected": governed["negative_validation"]["extra_metadata_field_rejected"],
        "no_rejected_record_reaches_consumer": governed["negative_validation"]["consumer_count_unchanged"],
    }
    lab.check("green", "Governed assembly validates provenance and keeps record data outside role authority",
              all(green.values()), {"governed": green,
                                    "schema_checks": governed["checks"],
                                    "negative_validation": governed["negative_validation"]})

    positive_result = observe(lab, "governed")
    positive = {
        "approved_lookup_remains_useful": positive_result["consumer"]["output"] == ANSWER,
        "approved_record_still_available": positive_result["consumer"]["records"] == [NOTE],
        "request_result_is_stable": positive_result["consumer"] == governed["consumer"],
    }
    lab.check("positive", "The approved ordinary question still returns its useful synthetic answer",
              all(positive.values()), positive)

    receipt = {
        "scope": "fixed-benign-synthetic-rag-note",
        "namespace": NS,
        "record": NOTE,
        "answer": ANSWER,
        "red": red,
        "green": green,
        "positive": positive,
        "observed_roles": {"baseline": baseline["consumer"]["message_roles"],
                           "governed": governed["consumer"]["message_roles"]},
    }
    (lab.evidence / "rag-context-boundary.json").write_text(
        json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
