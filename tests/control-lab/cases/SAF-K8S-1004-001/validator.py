"""Review worksheet links and classify abstract, case-owned observations."""
import copy
import json
from pathlib import Path

RULES = {
    ("training-data-digest-departure", "training-data storage"): "control.data_poisoning",
    ("privacy-evaluation-signal", "inference service"): "control.data_disclosure",
    ("resource-budget-alert", "GPU scheduling"): "control.computational_dos",
    ("model-provenance-review-signal", "model registry"): "control.model_poisoning",
}
REQUIRED_LINKS = ("surfaces", "controls", "detections", "owner", "source")


def evaluate(record, worksheet, evidence):
    key = (record["signal"], record["observed_surface"])
    if evidence.get(record["evidence_ref"]) != list(key):
        return None
    label = RULES.get(key)
    entry = worksheet.get(label)
    if entry and record["observed_surface"] in entry["surfaces"]:
        return label
    return None


def review(worksheet, submissions, records, evidence):
    invalid = []
    for record in records:
        expected = evaluate(record, worksheet, evidence)
        if expected is None or submissions.get(record["id"]) != expected:
            invalid.append(record["id"])
    missing = [label for label, entry in worksheet.items()
               if any(not entry.get(link) for link in REQUIRED_LINKS)]
    return {"missing_class_links": sorted(missing), "invalid_records": sorted(invalid)}


fixture = json.loads(Path("/fixture/fixture.json").read_text())
worksheet = {entry["id"]: entry for entry in fixture["classes"]}
baseline_worksheet = copy.deepcopy(worksheet)
baseline_worksheet["control.data_poisoning"]["controls"] = []
baseline_worksheet["control.model_poisoning"]["owner"] = ""
baseline_submissions = dict(fixture["submissions"])
baseline_submissions["INC-ABSTRACT-01"] = "control.model_poisoning"
baseline_submissions.pop("INC-ABSTRACT-02")
baseline_evidence = dict(fixture["evidence"])
baseline_evidence["fixture:evidence-03"] = ["unrelated-observation", "GPU scheduling"]
positive_label = evaluate(fixture["positive_record"], worksheet, fixture["evidence"])
report = {
    "baseline": review(baseline_worksheet, baseline_submissions,
                       fixture["incident_records"], baseline_evidence),
    "candidate": review(worksheet, fixture["submissions"],
                        fixture["incident_records"], fixture["evidence"]),
    "positive": {"class": positive_label, "owner": worksheet[positive_label]["owner"]},
    "cta_attribution": "unverified" if all("unverified" in entry["source"]
                                         for entry in worksheet.values()) else "unsupported",
}
print(json.dumps(report, sort_keys=True))
