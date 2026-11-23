"""Apply a conservative review policy to this fixture's fictional advisories."""
import base64
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import tempfile

CONTEXT = "https://openvex.dev/ns/v0.2.0"
STATES = ("affected", "not_affected", "fixed", "under_investigation")
DOCUMENT_ID = "https://saf-vex.example.test/reviews/synthetic"
PUBLISHER = "synthetic-review@saf-vex.example.test"
ARTIFACT_PREFIX = "https://saf-vex.example.test/releases/sha256/"


def signature_valid(raw, encoded, public_key):
    with tempfile.TemporaryDirectory() as path:
        file = Path(path) / "signature.der"
        file.write_bytes(base64.b64decode(encoded, validate=True))
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(public_key), "-signature", str(file)],
            input=raw.encode(), capture_output=True, timeout=8,
        )
        return result.returncode == 0 and result.stdout.strip() == b"Verified OK"


def authorized(raw, signature, key, at):
    if raw is None:
        return None, "document-unavailable"
    if not signature_valid(raw, signature, key):
        return None, "signature-invalid"
    try:
        doc = json.loads(raw)
        fields = doc.get("@context"), doc.get("@id"), doc.get("author")
        if fields != (CONTEXT, DOCUMENT_ID, PUBLISHER):
            return None, "issuer-or-format-mismatch"
        published = datetime.fromisoformat(doc["timestamp"])
        if doc["version"] < 2 or not 0 <= (at - published).total_seconds() <= 14 * 86400:
            return None, "document-outside-release-window"
        if not doc["statements"]:
            return None, "empty-statements"
        for statement in doc["statements"]:
            if not isinstance(statement["vulnerability"]["name"], str) or not statement["products"]:
                return None, "invalid-statement-scope"
            for product in statement["products"]:
                if not isinstance(product["@id"], str) or not all(
                    isinstance(component["@id"], str) for component in product["subcomponents"]
                ):
                    return None, "invalid-statement-scope"
            status = statement.get("status")
            if status not in STATES:
                return None, "unsupported-status"
            if status == "affected" and not statement.get("action_statement"):
                return None, "missing-action-statement"
            if status == "not_affected" and not (statement.get("justification") or statement.get("impact_statement")):
                return None, "missing-impact-explanation"
    except (TypeError, KeyError, ValueError, AttributeError):
        return None, "invalid-document"
    return doc, "accepted"


def assessment(finding, statements, checked_inventory):
    matches = [item for item in statements if item["vulnerability"]["name"] == finding["advisory"]
               and any(product["@id"] == finding["artifact"] and any(
                       component["@id"] == finding["component"] for component in product["subcomponents"]
                   ) for product in item["products"])]
    if len(matches) != 1:
        return "ambiguous" if matches else "no-exact-match", True
    statement, = matches
    state = statement["status"]
    # The lab supports only one evidence type for lowering review priority. Inventory
    # scope and actual remediation need their own checks for each deployed workflow.
    if (state == "not_affected" and statement.get("justification") == "component_not_present"
            and checked_inventory is not None and finding["component"] not in checked_inventory):
        return "not_affected", False
    return state, True


def evaluate(bundle, public_key):
    raw_findings = bundle["findings"]
    at = datetime.fromisoformat(bundle["evaluation_time"])
    inventory = {}
    for raw_release in bundle["release_manifests"]:
        digest = ARTIFACT_PREFIX + sha256(raw_release.encode()).hexdigest()
        inventory[digest] = json.loads(raw_release)["packages"]
    reports = {}
    for variant, document in bundle["documents"].items():
        raw, signature = document
        doc, verdict = authorized(raw, signature, public_key, at)
        decisions = {}
        for finding in raw_findings:
            disposition, active = (verdict, True) if doc is None else assessment(
                finding, doc["statements"], inventory.get(finding["artifact"])
            )
            decisions[finding["key"]] = {"disposition": disposition, "needs_review": active}
        reports[variant] = {"source": verdict, "decisions": decisions}
    return {"raw_findings": raw_findings, "reviews": reports}


if __name__ == "__main__":
    root = Path("/fixture")
    print(json.dumps(evaluate(json.loads((root / "inputs.json").read_text()), root / "review.pub"),
                     sort_keys=True))
