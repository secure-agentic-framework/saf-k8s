"""Process only the synthetic advisory and inventory fixture."""
import json
from pathlib import Path
import re
import sys


def version_tuple(value):
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise ValueError(f"Expected a numeric three-part version, got {value!r}")
    return tuple(int(part) for part in match.groups())


def cpe_parts(value):
    parts = value.split(":")
    if len(parts) != 13 or parts[:2] != ["cpe", "2.3"]:
        raise ValueError(f"Expected a CPE 2.3 URI, got {value!r}")
    return parts


def matching_interval(nvd_record, inventory_item):
    installed = cpe_parts(inventory_item["cpe23Uri"])
    for configuration in nvd_record["configurations"]:
        if configuration.get("operator", "OR") != "OR" or configuration.get("negate"):
            raise ValueError("fixture supports only simple nonnegated OR configurations")
        for node in configuration["nodes"]:
            if node["operator"] != "OR" or node.get("negate"):
                raise ValueError("fixture supports only simple nonnegated OR nodes")
            for match in node["cpeMatch"]:
                criteria = cpe_parts(match["criteria"])
                if not match["vulnerable"] or installed[2:5] != criteria[2:5]:
                    continue
                if criteria[5] != "*" or match.keys() & {"versionStartExcluding", "versionEndIncluding"}:
                    raise ValueError("fixture requires an inclusive start and an exclusive end")
                lower, upper = match["versionStartIncluding"], match["versionEndExcluding"]
                version = version_tuple(installed[5])
                if version_tuple(lower) <= version < version_tuple(upper):
                    return {"versionStartIncluding": lower, "versionEndExcluding": upper}
    return None


def base_score(nvd_record):
    metrics = nvd_record["metrics"]["cvssMetricV31"]
    return max(row["cvssData"]["baseScore"] for row in metrics)


def triage(fixtures):
    nvd_by_id = {row["id"]: row for row in fixtures["nvd_cve_records"]}
    kev_ids = {row["cveID"] for row in fixtures["cisa_kev_records"]["vulnerabilities"]}
    findings = []
    for component in fixtures["synthetic_inventory"]:
        for feed_item in fixtures["kubernetes_official_feed_items"]:
            record = nvd_by_id[feed_item["id"]]
            interval = matching_interval(record, component)
            if interval is None:
                continue
            score = base_score(record)
            known_exploited = feed_item["id"] in kev_ids
            exposed = component["internet_exposed"]
            if known_exploited and exposed:
                priority = "P1"
            elif score >= 9.0 or (score >= 7.0 and exposed and component["criticality"] == "high"):
                priority = "P2"
            else:
                priority = "P3"
            findings.append({
                "id": feed_item["id"],
                "title": feed_item["summary"],
                "component": component["name"],
                "version": cpe_parts(component["cpe23Uri"])[5],
                "affected": True,
                "affected_range": interval,
                "cvss_v31_base_score": score,
                "known_exploited": known_exploited,
                "internet_exposed": exposed,
                "asset_criticality": component["criticality"],
                "priority": priority,
            })
    return sorted(findings, key=lambda row: (row["priority"], -row["cvss_v31_base_score"], row["id"]))


if __name__ == "__main__":
    files = json.loads(Path("/fixture/fixtures.json").read_text())
    candidates = triage(files)
    mode = sys.argv[1]
    if mode == "severity-only":
        candidates.sort(key=lambda row: -row["cvss_v31_base_score"])
    elif mode != "context-aware":
        raise ValueError("unknown fixture mode")
    print(json.dumps(candidates, sort_keys=True))
