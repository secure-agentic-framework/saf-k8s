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


FIXTURE_DIR = Path(__file__).resolve().parent
fixture_path = FIXTURE_DIR / "fixture.json"
if not fixture_path.exists():
    fixture_path = FIXTURE_DIR / "fixtures.json"
fixture = json.loads(fixture_path.read_text())
expected_section9 = json.loads((FIXTURE_DIR / "expected_section9_classes.json").read_text())["classes"]
worksheet = {entry["id"]: entry for entry in fixture["classes"]}


def exact_label_coverage(classes, expected):
    expected_ids = set(expected)
    actual = {}
    duplicates = []
    for entry in classes:
        class_id = entry.get("id")
        label = entry.get("label")
        if class_id in actual:
            duplicates.append(class_id)
        else:
            actual[class_id] = label
    actual_ids = set(actual)
    missing_ids = sorted(expected_ids - actual_ids)
    unexpected_ids = sorted(actual_ids - expected_ids)
    stale_labels = [
        {"id": class_id, "expected": expected[class_id], "actual": actual[class_id]}
        for class_id in sorted(expected_ids & actual_ids)
        if actual[class_id] != expected[class_id]
    ]
    duplicates = sorted(set(duplicates))
    return {
        "exact_match": not (missing_ids or unexpected_ids or stale_labels or duplicates),
        "missing_ids": missing_ids,
        "unexpected_ids": unexpected_ids,
        "stale_labels": stale_labels,
        "duplicate_ids": duplicates,
    }


baseline_worksheet = copy.deepcopy(worksheet)
baseline_worksheet["control.data_poisoning"]["controls"] = []
baseline_worksheet["control.model_poisoning"]["owner"] = ""
baseline_submissions = dict(fixture["submissions"])
baseline_submissions["INC-ABSTRACT-01"] = "control.model_poisoning"
baseline_submissions.pop("INC-ABSTRACT-02")
baseline_evidence = dict(fixture["evidence"])
baseline_evidence["fixture:evidence-03"] = ["unrelated-observation", "GPU scheduling"]
positive_label = evaluate(fixture["positive_record"], worksheet, fixture["evidence"])
baseline_classes = copy.deepcopy(fixture["classes"])
baseline_classes = [entry for entry in baseline_classes
                    if entry["id"] != "control.poisoning_attacks"]
for entry in baseline_classes:
    if entry["id"] == "control.evasion":
        entry["label"] = "Evasion"
        break
report = {
    "baseline": review(baseline_worksheet, baseline_submissions,
                       fixture["incident_records"], baseline_evidence),
    "candidate": review(worksheet, fixture["submissions"],
                        fixture["incident_records"], fixture["evidence"]),
    "positive": {"class": positive_label, "owner": worksheet[positive_label]["owner"]},
    "section9_label_gate": {
        "baseline": exact_label_coverage(baseline_classes, expected_section9),
        "candidate": exact_label_coverage(fixture["classes"], expected_section9),
    },
    "cta_conformance": "not_established",
}
print(json.dumps(report, sort_keys=True))
