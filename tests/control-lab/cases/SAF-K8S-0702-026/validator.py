"""Report shape and ambiguity checks for the mounted synthetic taxonomy."""
from datetime import date
import json
from pathlib import Path
import re


def validate(document):
    """Return structural defects; intentionally has no policy or identity authority."""
    issues = []
    if not isinstance(document, dict):
        return ["document must be an object"]

    version = document.get("taxonomyVersion")
    numeric = r"(?:0|[1-9]\d*)"
    if not isinstance(version, str) or not re.fullmatch(rf"{numeric}\.{numeric}\.{numeric}", version):
        issues.append("taxonomyVersion must use MAJOR.MINOR.PATCH numeric form")

    governance_record = document.get("governance")
    required_governance = ("ownerRole", "reviewerRole", "reviewedOn", "approvalRecord")
    if not isinstance(governance_record, dict):
        issues.append("governance metadata must be an object")
    else:
        for field in required_governance:
            if not isinstance(governance_record.get(field), str) or not governance_record[field].strip():
                issues.append(f"governance.{field} is required")
        reviewed_on = governance_record.get("reviewedOn", "")
        try:
            if date.fromisoformat(reviewed_on).isoformat() != reviewed_on:
                raise ValueError("date is not canonical")
        except (ValueError, TypeError):
            issues.append("governance.reviewedOn must be a valid YYYY-MM-DD date")

    categories = document.get("categories")
    if not isinstance(categories, list) or not categories:
        issues.append("categories must be a non-empty list")
        return issues

    terms = {}
    for index, item in enumerate(categories):
        prefix = f"categories[{index}]"
        if not isinstance(item, dict):
            issues.append(f"{prefix} must be an object")
            continue
        for field in ("name", "definition"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                issues.append(f"{prefix}.{field} is required")
        name = item.get("name")
        synonyms = item.get("synonyms")
        if not isinstance(synonyms, list) or any(not isinstance(value, str) or not value.strip()
                                                 for value in synonyms):
            issues.append(f"{prefix}.synonyms must be a list of non-empty strings")
            synonyms = []
        for term in ([name] if isinstance(name, str) else []) + synonyms:
            normalized = term.strip().casefold()
            if normalized in terms:
                issues.append(
                    f"ambiguous classification term {term!r} appears in "
                    f"categories[{terms[normalized]}] and {prefix}"
                )
            else:
                terms[normalized] = index

        handling = item.get("handling")
        handling_fields = ("storage", "access", "sharing", "retention")
        if not isinstance(handling, dict):
            issues.append(f"{prefix}.handling is required")
        else:
            for field in handling_fields:
                if not isinstance(handling.get(field), str) or not handling[field].strip():
                    issues.append(f"{prefix}.handling.{field} is required")
    return issues


if __name__ == "__main__":
    document = json.loads(Path("/taxonomy/taxonomy.json").read_text())
    defects = validate(document)
    result = {"taxonomy_version": document.get("taxonomyVersion"),
              "category_count": len(document.get("categories", [])),
              "governance": document.get("governance"),
              "defects": defects}
    print(json.dumps(result, sort_keys=True), flush=True)
    raise SystemExit(int(bool(defects)))
