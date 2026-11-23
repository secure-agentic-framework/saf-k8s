"""Exercise retrieval metadata and measured relevance before a separate consumer."""
import hashlib
import importlib.util
import json
from pathlib import Path

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
CONSUMER = "retrieval-consumer"
RETRIEVAL = "retrieval-validator"
CODE = "retrieval-code"
APPROVAL = "retrieval-approved"
RESULTS = "retrieval-candidates"
SCOPE = (
    "An owned fixed index supplies benign retrieved chunks. A separate approved record binds "
    "each chunk to its source, version and digest. The governed workload computes token relevance "
    "before forwarding, limits the accepted count, and records decisions and mutations observed "
    "at an independent consumer Service."
)
GOOD = {"id": "cedar", "source": "synthetic://cedar", "version": "v1", "text": "cedar amber field"}
SECOND = {"id": "maple", "source": "synthetic://maple", "version": "v1", "text": "maple amber field"}


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def resource(lab, kind, name, **fields):
    return lab.create({"apiVersion": "v1", "kind": kind, "metadata": {"name": name}, **fields})


def start(lab, image, name, command, configmaps, port=None):
    volumes = [{"name": name, "configMap": {"name": name}} for name, _ in configmaps]
    mounts = [{"name": name, "mountPath": path, "readOnly": True} for name, path in configmaps]
    work = container("fixture", image=image, imagePullPolicy="Never", command=command, volumeMounts=mounts)
    if port:
        work["readinessProbe"] = {"tcpSocket": {"port": port}, "periodSeconds": 1}
    request = pod(name, [work], automountServiceAccountToken=False, volumes=volumes)
    request["metadata"]["labels"] = {"app": name}
    lab.create(request)


def run(lab):
    spec = importlib.util.spec_from_file_location("saf_fixture_runtime", HERE.parent / "SAF-K8S-0908-001" / "case.py")
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    image = runtime.load_runtime(lab)
    resource(lab, "ConfigMap", CODE, immutable=True, data={"fixture.py": (HERE/"fixture.py").read_text()})
    pins = {chunk["id"]: {"sha256": sha(chunk["text"]), "source": chunk["source"], "version": chunk["version"]}
            for chunk in (GOOD, SECOND)}
    resource(lab, "ConfigMap", APPROVAL, immutable=True, data={"chunks.json": json.dumps(pins, sort_keys=True)})
    scenarios = {
        "baseline": {"query": "cedar amber field", "candidates": [{**GOOD, "version": "v0", "text": "cedar blue field"}]},
        "rejected": {"query": "cedar amber field", "candidates": [
            {**GOOD, "source": "synthetic://other"},
            {**GOOD, "version": "v0"},
            {**GOOD, "text": "cedar blue field"},
            {**GOOD, "version": None},
            SECOND,
        ]},
        "accepted": {"query": "amber field", "candidates": [SECOND, GOOD]},
    }
    resource(lab, "ConfigMap", RESULTS, immutable=True, data={"chunks.json": json.dumps(scenarios, sort_keys=True)})
    start(lab, image, CONSUMER, ["python", "/fixture/fixture.py", "consumer"], [(CODE, "/fixture")], port=8081)
    resource(lab, "Service", CONSUMER, spec={"selector": {"app": CONSUMER}, "ports": [{"port": 8081}]})
    start(lab, image, RETRIEVAL, ["sleep", "300"],
          [(CODE, "/fixture"), (APPROVAL, "/trusted"), (RESULTS, "/indexed")])
    for name in (CONSUMER, RETRIEVAL):
        ready(lab, name)

    def observe(scenario):
        outcome = lab.kubectl("exec", RETRIEVAL, "--", "python", "/fixture/fixture.py", scenario, timeout=25)
        return json.loads(outcome.stdout)

    baseline = observe("baseline")
    red = {"stale_owned_bytes_reached_consumer": baseline["consumer_delta"] == 1 and baseline["receipts"] == [
        {"received": True, "chunk_id": "cedar", "text_sha256": sha("cedar blue field")}]}
    lab.check("red", "The ungoverned retrieval path sends a stale benign candidate", all(red.values()), red)
    rejected = observe("rejected")
    green = {
        "source_version_digest_metadata_and_score_all_checked":
            [item["decision"] for item in rejected["decisions"]] ==
            ["source_or_version_unapproved", "source_or_version_unapproved", "digest_mismatch",
             "invalid_metadata", "below_threshold"],
        "low_relevance_was_measured": abs(rejected["decisions"][-1]["score"] - 2/3) < 1e-9,
        "consumer_received_no_rejected_candidate": rejected["consumer_delta"] == 0 and rejected["receipts"] == [],
    }
    lab.check("green", "The governed retrieval path rejects each fixed invalid or low-relevance candidate",
              all(green.values()), green)
    accepted = observe("accepted")
    positive = {
        "two_valid_chunks_met_threshold": [item["decision"] for item in accepted["decisions"]] == ["accepted", "accepted"],
        "top_one_forwards_only_the_expected_bound_chunk": accepted["consumer_delta"] == 1 and accepted["receipts"] == [
            {"received": True, "chunk_id": "cedar", "text_sha256": sha(GOOD["text"])}],
    }
    lab.check("positive", "The separate consumer receives the exact approved top result",
              all(positive.values()), positive)
    (lab.evidence/"retrieval-validation.json").write_text(json.dumps(
        {"red": red, "green": green, "positive": positive, "rejected_decisions": rejected["decisions"]},
        sort_keys=True, indent=2) + "\n")
