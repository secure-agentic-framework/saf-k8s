"""Live Kubernetes Jobs gate publication of fixed synthetic feature records."""
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CLAIM = "fixture-feature-publication"
CODE = "fixture-feature-publication-code"
REASONS = {
    "direct-id": "direct-identifier-feature",
    "target-derived": "deterministic-target-derived-feature",
    "after-cutoff": "temporal-cutoff",
}
SCOPE = (
    "Local Kind Jobs run fixed invented records through a baseline and a publication gate. "
    "The gate rejects a direct identifier in features, a known target-derived feature, and "
    "a record at or after the cutoff. A separate read-only Job verifies the exact approved "
    "output on the claim. Production feature lineage and audit retention need separate evidence."
)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def create(lab, kind, name, **fields):
    return lab.create({"apiVersion": "v1", "kind": kind, "metadata": {"name": name}, **fields})


def completed(lab, name, wanted="Complete"):
    lab.kubectl("wait", f"--for=condition={wanted}", f"job/{name}", "--timeout=90s", timeout=100)
    result = json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)["status"]
    event = json.loads(lab.kubectl("logs", f"job/{name}").stdout)
    ready = any(condition["type"] == wanted and condition["status"] == "True"
                for condition in result["conditions"])
    return {"terminal": wanted, "observed": ready,
            "count": result.get("succeeded" if wanted == "Complete" else "failed", 0),
            "event": event}


def run(lab):
    runtime = load(HERE.parent / "SAF-K8S-0908-001" / "case.py", "saf_feature_runtime")
    publication = load(HERE / "publication_job.py", "saf_feature_job")
    image = runtime.load_runtime(lab)
    create(lab, "ConfigMap", CODE, immutable=True, data={
        name: (HERE / name).read_text() for name in ("feature_fixture.py", "pipeline_fixture.py")
    })
    create(lab, "PersistentVolumeClaim", CLAIM, spec={
        "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "64Mi"}}
    })

    def submit(name, *command):
        lab.create(publication.job(name, image, command, code_config=CODE, claim=CLAIM))

    def producer_result(kind, case, rejected=False):
        return completed(lab, kind + "-" + case, "Failed" if rejected else "Complete")

    for case in REASONS:
        submit("baseline-" + case, "baseline", case)
    baseline_jobs = {case: producer_result("baseline", case) for case in REASONS}
    submit("observe-baseline", "inspect-baseline")
    baseline_observer = completed(lab, "observe-baseline")
    baseline_event = baseline_observer["event"]
    red = {
        "all_unchecked_jobs_published": all(item["observed"] and item["count"] == 1
                                             and item["event"]["persisted"] for item in baseline_jobs.values()),
        "independent_reader_saw_all_three_defects": baseline_observer["observed"] and baseline_event == {
            "baseline_retained_identifier_feature": True, "baseline_retained_label_derived_feature": True,
            "baseline_retained_future_record": True,
        },
    }
    lab.check("red", "Unchecked publication persists all three synthetic defects", all(red.values()), red)

    for case in (*REASONS, "valid"):
        submit("governed-" + case, "produce", case)
    denied = {case: producer_result("governed", case, rejected=True) for case in REASONS}
    valid = producer_result("governed", "valid")
    submit("observe-governed", "consume")
    governed_observer = completed(lab, "observe-governed")
    observed = governed_observer["event"]
    green = {
        case: row["observed"] and row["count"] == 1 and row["event"] == {
            "event": "publication-decision", "case": case, "decision": "rejected",
            "reason": REASONS[case], "persisted": False,
        } for case, row in denied.items()
    }
    green["no_rejected_outputs_on_claim"] = observed.get("candidate_outputs_absent") is True
    lab.check("green", "Each producer rejects its own reason and leaves no published output",
              all(green.values()), green)
    positive = {
        "approved_producer_succeeded": valid["observed"] and valid["count"] == 1
        and valid["event"] == {"event": "publication-decision", "case": "valid",
                               "decision": "published", "reason": None, "persisted": True},
        "read_only_consumer_verified_minimized_output": governed_observer["observed"]
        and observed.get("observed_files") == ["valid.json"]
        and observed.get("valid_output_matches_contract") is True,
    }
    lab.check("positive", "A separate read-only consumer accepts the exact minimized features",
              all(positive.values()), positive)
    (lab.evidence / "feature-publication-observations.json").write_text(json.dumps({
        "baseline_jobs": baseline_jobs, "baseline_observer": baseline_observer, "denied_jobs": denied,
        "valid_job": valid, "governed_observer": governed_observer,
        "checks": {"red": red, "green": green, "positive": positive},
    }, indent=2, sort_keys=True) + "\n")
