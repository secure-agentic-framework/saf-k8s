"""SAF-K8S-0905-028: offline, metadata-only dependency gate exercise."""
import json
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
PYTHON = ("docker.io/library/python:3.13.2-alpine@sha256:"
          "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352")
ADVISORY = "SAF-FAB-2026-0905-028-001"
DIRECT = "saf-ml-fixture"
TRANSITIVE = "saf-fixture-core"
VULNERABLE_VERSION = "0.4.0"
PATCHED_VERSION = "0.4.1"

SCOPE = (
    "One disposable Kubernetes cluster job builds tiny metadata-only wheels for two fictitious "
    "packages, installs them with pip --no-index from local wheelhouse directories, and inspects "
    "installed metadata. The red observation records the same flagged installation as promotable "
    "under an explicitly inactive gate; green blocks it; positive installs a fresh patched fixture "
    "and confirms its direct-to-transitive dependency path. No real third-party package, CVE, "
    "package code, vulnerability behavior, or production promotion system is involved."
)


def _job(lab):
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "dependency-gate-worker"}, "immutable": True,
        "data": {"worker.py": (HERE / "worker.py").read_text()},
    })
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": "dependency-gate"},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 120,
                 "template": {"metadata": {"labels": {"app": "dependency-gate"}}, "spec": {
                     "restartPolicy": "Never", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                         "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "worker", "image": PYTHON,
                                     "imagePullPolicy": "IfNotPresent",
                                     "command": ["python", "-B", "/worker/worker.py"],
                                     "resources": {"requests": {"cpu": "10m", "memory": "48Mi"},
                                                   "limits": {"cpu": "200m", "memory": "128Mi"}},
                                     "securityContext": {"allowPrivilegeEscalation": False,
                                                         "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}},
                                     "volumeMounts": [
                                         {"name": "worker", "mountPath": "/worker", "readOnly": True},
                                         {"name": "scratch", "mountPath": "/tmp"}]}],
                     "volumes": [
                         {"name": "worker", "configMap": {"name": "dependency-gate-worker",
                                                               "defaultMode": 292}},
                         {"name": "scratch", "emptyDir": {"sizeLimit": "32Mi"}}]}}}})
    deadline = time.monotonic() + 135
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", "job", "dependency-gate", "-o", "json").stdout)
        states = {x["type"] for x in job.get("status", {}).get("conditions", [])
                  if x["status"] == "True"}
        if "Failed" in states:
            lab.kubectl("logs", "job/dependency-gate", allow_failure=True)
            lab.block("Dependency-gate fixture job failed")
        if "Complete" in states:
            return lab.kubectl("logs", "job/dependency-gate").stdout
        time.sleep(0.5)
    lab.block("Dependency-gate fixture job timed out")


def check_observations(lab, observations):
    original = {DIRECT: {"version": "1.0.0", "requires": [f"{TRANSITIVE}>=0.4,<1"]},
                TRANSITIVE: {"version": VULNERABLE_VERSION, "requires": []}}
    patched = {**original, TRANSITIVE: {"version": PATCHED_VERSION, "requires": []}}
    finding = {"id": ADVISORY, "package": TRANSITIVE, "version": VULNERABLE_VERSION}

    disabled = observations["disabled"]
    lab.check("red", "The inactive gate writes a promotion record for the pinned dependency with a fixture advisory",
              disabled == {"installed": original, "matches": [finding], "enforced": False,
                           "decision": "accepted", "promoted_record": {"installed": original}},
              disabled)
    blocked = observations["blocked"]
    lab.check("green", "The active gate withholds promotion of the same installed dependency and records the exact match",
              blocked == {"installed": original, "matches": [finding], "enforced": True,
                          "decision": "blocked", "promoted_record": None},
              blocked)
    accepted = observations["patched"]
    lab.check("positive", "A fresh installation replaces the flagged transitive dependency and produces a promotion record",
              accepted == {"installed": patched, "matches": [], "enforced": True,
                           "decision": "accepted", "promoted_record": {"installed": patched}},
              accepted)



def _numeric_version(value):
    parts = value.split(".")
    if not parts or any(not part.isdigit() for part in parts):
        raise ValueError("The pinned advisory fixture contains a non-numeric version")
    return tuple(int(part) for part in parts)


def _version_in_range(version, expression):
    candidate = _numeric_version(version)
    for clause in expression.split(","):
        clause = clause.strip()
        operator = next((op for op in (">=", "<=", ">", "<", "==") if clause.startswith(op)), None)
        if operator is None:
            raise ValueError("Unsupported version-range syntax in pinned source snapshot")
        bound = _numeric_version(clause[len(operator):].strip())
        width = max(len(candidate), len(bound))
        left = candidate + (0,) * (width - len(candidate))
        right = bound + (0,) * (width - len(bound))
        if operator == ">=" and not left >= right:
            return False
        if operator == "<=" and not left <= right:
            return False
        if operator == ">" and not left > right:
            return False
        if operator == "<" and not left < right:
            return False
        if operator == "==" and not left == right:
            return False
    return True


def check_offline_advisory_reference(lab):
    # This is a normalized subset of an upstream record identified by its exact Git blob and raw digest.
    advisory_path = HERE / "fixtures" / "advisory-reference.json"
    provenance_path = HERE / "fixtures" / "source-provenance.json"
    inventory_path = HERE / "fixtures" / "synthetic-inventory.json"
    advisory_bytes = advisory_path.read_bytes()
    advisory = json.loads(advisory_bytes)
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    snapshot_digest, source_pinned = _source_identity(advisory, provenance)
    lab.check("positive", "The normalized advisory fixture is bound to the frozen official CVE record identity",
              source_pinned, {"record_id": advisory.get("cve_id"),
                              "upstream_git_blob_sha1_matches": provenance.get("git_blob_sha1") == "8774a806fca4a0c5d3474e7671a609cd8c8ee5b2",
                              "normalized_snapshot_sha256": snapshot_digest})

    evaluation = _evaluate_pinned_advisory(advisory, provenance, inventory)
    if evaluation["source_pinned"]:
        affected = [item for item in advisory.get("affected_versions", []) if item.get("status") == "affected"]
        expected_ranges = {">= 2.0.0, < 2.0.7", "< 1.26.18"}
        parsed_ranges = {item.get("range") for item in affected}
    else:
        # Do not interpret version ranges from an untrusted source fixture.
        expected_ranges = parsed_ranges = set()
    matches = evaluation["matching_synthetic_row_indexes"]
    range_match = (evaluation["source_pinned"] and evaluation["comparison_performed"]
                   and parsed_ranges == expected_ranges
                   and matches == inventory.get("expected_matching_rows") == [0, 2]
                   and inventory.get("inventory_kind") == "synthetic package metadata only; no distribution files or package code")
    lab.check("green", "The pinned advisory ranges match only the two expected synthetic urllib3 inventory rows",
              range_match, {"matching_synthetic_row_indexes": matches,
                            "expected_matching_synthetic_row_indexes": [0, 2],
                            "range_count": len(parsed_ranges)})

    decisions = evaluation["decisions"]
    rows = inventory.get("rows", [])
    triage_review = (evaluation["source_pinned"] and evaluation["comparison_performed"]
                     and all(item["disposition"] == "context_review_required" for item in decisions if item["matched_advisory"])
                     and all(item["disposition"] == "outside_pinned_advisory_ranges" for item in decisions if not item["matched_advisory"])
                     and all("exploitability" not in item for item in decisions))
    lab.check("green", "A version match remains a review-needed finding without an exploitability conclusion",
              triage_review, {"matched_findings_require_review": True, "exploitability_assessed": False,
                              "package_code_present": False, "synthetic_inventory_rows": len(rows)})
    (lab.evidence / "advisory-reference-matching.json").write_text(
        json.dumps({"source_record": advisory["cve_id"], "source_blob_sha1": provenance["git_blob_sha1"],
                    "source_record_sha256": provenance["raw_record_sha256"],
                    "normalized_snapshot_sha256": snapshot_digest, "decisions": decisions,
                    "inventory_kind": inventory["inventory_kind"],
                    "packages_installed_or_executed": False}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")

    # A harmless provenance-field mismatch must stop the same business path before range parsing.
    untrusted_provenance = dict(provenance)
    untrusted_provenance["repository"] = "untrusted.example/fixture"
    untrusted = _evaluate_pinned_advisory(advisory, untrusted_provenance, inventory)
    closed = (not untrusted["source_pinned"] and not untrusted["comparison_performed"]
              and untrusted["decision"] == "not_evaluated_untrusted_source"
              and untrusted["matching_synthetic_row_indexes"] == []
              and untrusted["decisions"] == [])
    lab.check("green", "A source-identity mismatch stops advisory matching before producing findings or dispositions",
              closed, {"source_pinned": untrusted["source_pinned"],
                       "comparison_performed": untrusted["comparison_performed"],
                       "decision": untrusted["decision"],
                       "matching_row_count": len(untrusted["matching_synthetic_row_indexes"]),
                       "disposition_count": len(untrusted["decisions"])})


def _source_identity(advisory, provenance):
    snapshot_digest = __import__("hashlib").sha256(
        json.dumps(advisory, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    source_pinned = (
        snapshot_digest == "0bcc64f4bce24ed35da702708e857a90e5a82513e59b202e21b36b4e338cc708"
        and advisory.get("cve_id") == "CVE-2023-45803"
        and provenance.get("record_id") == advisory.get("cve_id")
        and provenance.get("repository") == "CVEProject/cvelistV5"
        and provenance.get("path") == "cves/2023/45xxx/CVE-2023-45803.json"
        and provenance.get("git_blob_sha1") == "8774a806fca4a0c5d3474e7671a609cd8c8ee5b2"
        and provenance.get("raw_record_sha256") == "d0233f8d7c5614e1ae54db79c32ae2b166cd8801c8ef463e65fbe349b52f1e44"
    )
    return snapshot_digest, source_pinned


def _evaluate_pinned_advisory(advisory, provenance, inventory):
    """The range matcher only runs for the exact pinned normalized source fixture."""
    _, source_pinned = _source_identity(advisory, provenance)
    if not source_pinned:
        return {"source_pinned": False, "comparison_performed": False,
                "decision": "not_evaluated_untrusted_source",
                "matching_synthetic_row_indexes": [], "decisions": []}
    affected = [item for item in advisory.get("affected_versions", []) if item.get("status") == "affected"]
    ranges = {item.get("range") for item in affected}
    rows = inventory.get("rows", [])
    matches = []
    for index, row in enumerate(rows):
        if row.get("ecosystem") != "PyPI" or row.get("name", "").lower() != "urllib3":
            continue
        if any(_version_in_range(row.get("version", ""), expression) for expression in ranges):
            matches.append(index)
    decisions = [{"row_index": index, "package": row.get("name"), "version": row.get("version"),
                  "matched_advisory": index in matches,
                  "disposition": "context_review_required" if index in matches else "outside_pinned_advisory_ranges"}
                 for index, row in enumerate(rows)]
    return {"source_pinned": True, "comparison_performed": True, "decision": "comparison_complete",
            "matching_synthetic_row_indexes": matches, "decisions": decisions}


def run(lab):
    try:
        observations = json.loads(_job(lab))
    except json.JSONDecodeError as error:
        lab.block(f"Dependency gate worker returned invalid evidence: {error}")
    (lab.evidence / "dependency-gate.json").write_text(json.dumps(observations, indent=2, sort_keys=True) + "\n")
    check_observations(lab, observations)
    check_offline_advisory_reference(lab)
