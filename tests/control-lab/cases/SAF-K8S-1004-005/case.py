"""Check evidence-backed, bounded synthetic AML review records."""
import json
from pathlib import Path

NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
PYTHON_IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
HERE = Path(__file__).resolve().parent
NS = "saf-test"
APP = r'''import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from validator import _validation

with open("/fixture/fixtures.json", encoding="utf-8") as source:
    document = json.load(source)
evaluated = {record["record_id"]: _validation(record, document) for record in document["records"]}
body = json.dumps({"fixture": document, "results": evaluated}, sort_keys=True).encode()

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/records":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''

SCOPE = (
    "A disposable Kubernetes v1.36.1 Kind cluster runs one digest-pinned Python mock workload "
    "that serves only checked-in synthetic review metadata. The case validates namespace, "
    "freshness, evidence references, predictive and generative classification metadata, and five "
    "NIST AI 100-2e2025 review dimensions; it detects "
    "a synthetic marker-only overclaim, rejects stale/incomplete records, and preserves unknowns "
    "without assigning an attack class. It does not connect to feeds or external targets, run an "
    "AI model, establish an actual incident, prove deployed controls, or validate a production "
    "classification workflow."
)


def _security():
    return {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "capabilities": {"drop": ["ALL"]},
        "runAsNonRoot": True,
        "runAsUser": 65534,
        "seccompProfile": {"type": "RuntimeDefault"},
    }


def _observe(lab):
    script = (
        "import urllib.request; "
        "print(urllib.request.urlopen('http://saf-aml-review:8080/records', timeout=5)"
        ".read().decode())"
    )
    result = lab.kubectl("exec", "deployment/saf-aml-review", "--", "python", "-c", script,
                         timeout=20)
    return json.loads(result.stdout)


def run(lab):
    fixtures = json.loads((HERE / "fixtures.json").read_text())
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": "saf-aml-review-fixtures"},
                "data": {"fixtures.json": json.dumps(fixtures, sort_keys=True), "app.py": APP,
                         "validator.py": (HERE / "validator.py").read_text()}})
    labels = {"app": "saf-aml-review", "saf.synthetic": "true"}
    lab.create({"apiVersion": "apps/v1", "kind": "Deployment",
                "metadata": {"name": "saf-aml-review"},
                "spec": {"replicas": 1, "selector": {"matchLabels": labels},
                         "template": {"metadata": {"labels": labels}, "spec": {
                             "automountServiceAccountToken": False,
                             "containers": [{"name": "mock-review", "image": PYTHON_IMAGE,
                                 "command": ["python", "/fixture/app.py"],
                                 "ports": [{"name": "http", "containerPort": 8080}],
                                 "readinessProbe": {"httpGet": {"path": "/records", "port": "http"},
                                                    "periodSeconds": 2},
                                 "resources": {"requests": {"cpu": "5m", "memory": "16Mi"},
                                               "limits": {"cpu": "100m", "memory": "64Mi"}},
                                 "volumeMounts": [{"name": "fixtures", "mountPath": "/fixture",
                                                   "readOnly": True}],
                                 "securityContext": _security()}],
                             "volumes": [{"name": "fixtures",
                                          "configMap": {"name": "saf-aml-review-fixtures"}}]}}}})
    lab.create({"apiVersion": "v1", "kind": "Service",
                "metadata": {"name": "saf-aml-review", "labels": labels},
                "spec": {"selector": labels,
                         "ports": [{"name": "http", "port": 8080, "targetPort": "http"}]}})
    lab.kubectl("rollout", "status", "deployment/saf-aml-review", "--timeout=90s", timeout=100)

    response = _observe(lab)
    raw = response["fixture"]
    if raw != fixtures:
        lab.block("The in-cluster mock workload did not return the checked-in synthetic fixture")
    results = response["results"]
    by_id = {record["record_id"]: record for record in raw["records"]}
    rejected = {name: results[name]["errors"] for name in (
        "draft-reference-004", "unsupported-claim-005",
        "contradictory-evidence-006", "foreign-evidence-007",
    )}
    lab.check("red", "The in-cluster review rejects a draft source and invalid evidence or assertions",
              rejected["draft-reference-004"] == ["taxonomy_id_mismatch"]
              and "incident_status_not_bounded" in rejected["unsupported-claim-005"]
              and "unsupported_attack_class_assignment" in rejected["unsupported-claim-005"]
              and "unsupported_actor_inference:attacker_knowledge" in rejected["unsupported-claim-005"]
              and rejected["contradictory-evidence-006"] == ["evidence_value_mismatch:system_type"]
              and len(rejected["foreign-evidence-007"]) == 5
              and all(item.startswith("evidence_scope_mismatch:")
                      for item in rejected["foreign-evidence-007"]), rejected)

    stale = results["stale-abstract-002"]
    incomplete = results["incomplete-abstract-003"]
    valid = results["reviewable-abstract-001"]
    lab.check("green", "Structured review rejects stale and incomplete records and accepts a fully evidenced candidate",
              "stale_record" in stale["errors"] and "dimension_set_incomplete" in stale["errors"]
              and "dimension_set_incomplete" in incomplete["errors"]
              and not valid["errors"] and valid["accepted_for_review"],
              {"stale": stale, "incomplete": incomplete, "reviewable": valid})

    candidate = by_id["reviewable-abstract-001"]
    unknowns = {
        name: candidate["dimensions"][name]["value"]
        for name in ("attacker_goals_and_objectives", "attacker_capabilities_and_access",
                     "attacker_knowledge")
    }
    positive = (candidate["tenant"] == "synthetic-team-a" and candidate["namespace"] == NS
                and candidate["candidate_attack_class"] is None
                and candidate["actual_incident"] is False
                and unknowns["attacker_goals_and_objectives"] == "undetermined_from_observation"
                and unknowns["attacker_capabilities_and_access"] == "unknown"
                and unknowns["attacker_knowledge"] == "unknown"
                and all(candidate["dimensions"][dimension]["evidence"]
                        for dimension in raw["taxonomy"]["classification_dimensions"]))
    lab.check("positive", "Namespaced evidence preserves unknowns and leaves incident/classification unresolved",
              positive,
              {"tenant": candidate["tenant"], "namespace": candidate["namespace"],
               "review_state": valid["review_state"], "unknown_dimensions": unknowns,
               "actual_incident": candidate["actual_incident"],
               "candidate_attack_class": candidate["candidate_attack_class"]})

    both = {name: by_id[name]["dimensions"]["system_type"]["value"] for name in
            ("reviewable-abstract-001", "reviewable-generative-008")}
    covered = (set(both.values()) == {"predictive", "generative"}
               and all(results[name]["review_state"] == "pending_human_review" for name in both))
    lab.check("positive", "Predictive and generative evidence records both reach pending human review",
              covered, {"both_system_types_reviewable": covered})
    concrete = results["conflicting-branch-009"]
    explicit_unknown = results["reviewable-ambiguous-010"]
    conflict_detected = concrete["errors"] == ["conflicting_system_type_evidence"]
    pending_unknown = (explicit_unknown["review_state"] == "pending_human_review"
                       and by_id["reviewable-ambiguous-010"]["dimensions"]["system_type"]["value"] == "unknown"
                       and by_id["reviewable-ambiguous-010"]["actual_incident"] is False)
    lab.check("green", "Conflicting type evidence rejects a concrete claim and preserves an explicit unknown for review",
              conflict_detected and pending_unknown,
              {"unsupported_concrete_type_rejected": conflict_detected, "ambiguous_record_pending": pending_unknown})

    evidence = {"fixture_id": raw["fixture_id"], "taxonomy": raw["taxonomy"],
                "freshness_policy_days": raw["freshness_policy_days"],
                "raw_mock_response": raw, "validation_results": results,
                "boundary": "synthetic fixture metadata only; no actual incident or attack is established"}
    (lab.evidence / "aml-review-observations.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n")
