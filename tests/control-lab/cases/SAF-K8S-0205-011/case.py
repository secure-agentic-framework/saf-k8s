"""Reconcile a live case-owned kernel rule table to an immutable approved baseline."""

from hashlib import sha256
import json

SCOPE = "Read-only comparison of a case-owned detached nftables table in one Kind node against immutable approval records."
TABLE = "saf_fixture_011"
CHAIN = "fixture_unhooked"
PREVIEW = "saf_preview_011"
VALUES = {"approved-initial": 18084, "observed-unapproved": 18085, "approved-change": 18086}


def command(lab, node, *argv, **kwargs):
    return lab.command("docker", "exec", "-i", node, "nft", *argv, **kwargs)


def program(revision, previous_exists, table=TABLE):
    port = VALUES[revision]
    remove = f"delete table ip {table}\n" if previous_exists else ""
    return remove + f"""table ip {table} {{
    chain {CHAIN} {{
        tcp dport {port} counter comment "{revision}"
    }}
}}
"""


def normalize(value, name):
    if isinstance(value, dict):
        return {key: normalize(child, name) for key, child in value.items() if key not in ("handle", "packets", "bytes")}
    if isinstance(value, list):
        return [normalize(child, name) for child in value]
    return TABLE if value == name else value


def snapshot(lab, node, name=TABLE):
    raw = command(lab, node, "-j", "list", "table", "ip", name).stdout
    items = json.loads(raw)["nftables"]
    observed = [normalize(item, name) for item in items if "metainfo" not in item]
    rules = [item["rule"] for item in observed if "rule" in item]
    chain, = (item["chain"] for item in observed if "chain" in item)
    if "hook" in chain or chain["name"] != CHAIN:
        lab.block("The governance fixture may only use a detached chain")
    canonical = json.dumps(observed, sort_keys=True, separators=(",", ":")).encode()
    return {"sha256": sha256(canonical).hexdigest(), "rule_comments": [rule["comment"] for rule in rules]}


def approve(lab, name, observed):
    records = {"ruleset_sha256": observed["sha256"], "approval_id": name, "scope": "owned detached table"}
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                "immutable": True, "data": records})
    return json.loads(lab.kubectl("get", "configmap", name, "-o", "json").stdout)["data"]


def matches(current, approved, marker):
    return current["sha256"] == approved["ruleset_sha256"] and current["rule_comments"] == [marker]


def run(lab):
    node = lab.cluster + "-control-plane"
    if lab.command("kind", "get", "nodes", "--name", lab.cluster).stdout.splitlines() != [node]:
        lab.block("The audit fixture requires one known disposable Kind node")
    command(lab, node, "-f", "-", payload=program("approved-initial", False))
    try:
        initial = snapshot(lab, node)
        baseline = approve(lab, "fixture-firewall-v1", initial)
        command(lab, node, "-f", "-", payload=program("observed-unapproved", True))
        drift = snapshot(lab, node)
        mismatch = (matches(initial, baseline, "approved-initial") and not matches(drift, baseline, "approved-initial")
                    and drift["rule_comments"] == ["observed-unapproved"])
        lab.check("red", "A changed live rule is detected against the immutable approved snapshot",
                  mismatch, {"unapproved_rule_detected": mismatch})

        patch = json.dumps({"data": {"ruleset_sha256": drift["sha256"]}})
        rewrite = lab.kubectl("patch", "configmap", "fixture-firewall-v1", "--type=merge", "-p", patch, allow_failure=True)
        baseline_stable = rewrite.returncode != 0 and "immutable" in rewrite.stderr.lower()
        lab.check("green", "The observed drift cannot silently replace the stored approved digest",
                  baseline_stable, {"approved_snapshot_immutable": baseline_stable})

        approved_change = program("approved-change", True)
        command(lab, node, "-c", "-f", "-", payload=approved_change)
        check_unchanged = snapshot(lab, node) == drift
        command(lab, node, "-f", "-", payload=program("approved-change", False, PREVIEW))
        try:
            preview = snapshot(lab, node, PREVIEW)
        finally:
            command(lab, node, "delete", "table", "ip", PREVIEW)
        approved = approve(lab, "fixture-firewall-v2", preview)
        if snapshot(lab, node) != drift:
            lab.block("Preview and approval must leave the effective live rules unchanged")
        command(lab, node, "-f", "-", payload=approved_change)
        applied = snapshot(lab, node)
        matching = matches(applied, approved, "approved-change") and approved["ruleset_sha256"] != baseline["ruleset_sha256"]
        command(lab, node, "-f", "-", payload=program("approved-initial", True))
        rollback = matches(snapshot(lab, node), baseline, "approved-initial")
        lab.check("positive", "A checked rule change records the new exact snapshot and rollback reconciles to the first approval",
                  check_unchanged and matching and rollback,
                  {"check_did_not_apply": check_unchanged, "new_approved_state_reconciles": matching, "rollback_matches": rollback})
        (lab.evidence / "firewall-governance-observations.json").write_text(json.dumps({
            "old_approval": baseline, "unapproved_observation": drift, "new_approval": approved,
            "observed_approved_change": applied, "rollback_matches": rollback, "checked_without_applying": check_unchanged,
            "scope": "live detached table, no packet hook",
        }, indent=2) + "\n")
    finally:
        command(lab, node, "delete", "table", "ip", TABLE)
