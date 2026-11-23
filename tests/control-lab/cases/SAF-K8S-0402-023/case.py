"""Track long-lived service-account token classes and their governed retirement."""

from datetime import datetime, timedelta, timezone
import json

from fixtures import container, pod

NS = "saf-test"
ACCOUNT = "fixture-inventory-account"
TOKEN_TYPE = "kubernetes.io/service-account-token"
LEGACY = "fixture-legacy-linked"
MANUAL = "fixture-manual-unlinked"
OWNED = {LEGACY, MANUAL}
LABEL = "saf.example.org/token-review"
SCOPE = (
    "Use metadata from two owned Kubernetes Secret-backed token fixtures, an inert projected "
    "token declaration and separate approval records to distinguish token classes, overdue "
    "review and actual retirement. No token bytes are retrieved into evidence."
)


def create_token_fixture(lab, name):
    spec = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name, "annotations": {
                "kubernetes.io/service-account.name": ACCOUNT}}, "type": TOKEN_TYPE}
    # Name output remains safe even if the controller fills the Secret concurrently.
    lab.kubectl("create", "-f", "-", "-o", "name", payload=json.dumps(spec))


def inventory(lab):
    fields = (r'{range .items[*]}{.metadata.name}{"\t"}'
              r'{.metadata.annotations.kubernetes\.io/service-account\.name}{"\n"}{end}')
    raw = lab.kubectl("get", "secrets", "--field-selector", f"type={TOKEN_TYPE}",
                      "-o", "jsonpath=" + fields).stdout
    memberships = set(lab.kubectl("get", "serviceaccount/" + ACCOUNT,
                                 "-o", "jsonpath={.secrets[*].name}").stdout.split())
    records = {}
    for line in raw.splitlines():
        name, subject = line.split("\t")
        if name not in OWNED or subject != ACCOUNT:
            lab.block("Unexpected object in the owned metadata fixture inventory")
        records[name] = "legacy-linked" if name in memberships else "manual-unlinked"
    return records


def exception(lab, name, classification, deadline):
    data = {"namespace": NS, "account": ACCOUNT, "secret": name,
            "class": classification, "owner": "fixture-owner", "approval": "fixture-approval",
            "reason": "synthetic migration compatibility", "reviewBy": deadline.isoformat(),
            "retireBy": (deadline + timedelta(days=10)).isoformat()}
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name,
                "labels": {LABEL: "true"}}, "immutable": True, "data": data})


def classify(lab, records, now):
    listed = json.loads(lab.kubectl("get", "configmaps", "-l", LABEL + "=true", "-o", "json").stdout)
    approvals = {item["metadata"]["name"]: item["data"] for item in listed["items"]}
    decisions = {}
    for name, category in records.items():
        record = approvals.get(name, {})
        if (not all(record.get(field) for field in ("owner", "approval", "reason", "reviewBy", "retireBy"))
                or (record.get("namespace"), record.get("account"), record.get("secret"), record.get("class"))
                != (NS, ACCOUNT, name, category)):
            decisions[name] = "missing-or-mismatched"
            continue
        review_by = datetime.fromisoformat(record["reviewBy"])
        retire_by = datetime.fromisoformat(record["retireBy"])
        decisions[name] = "action-due" if min(review_by, retire_by) <= now else "current-exception"
    return decisions


def run(lab):
    now = datetime.now(timezone.utc)
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": ACCOUNT},
                "automountServiceAccountToken": False})
    for name in (LEGACY, MANUAL):
        create_token_fixture(lab, name)
    # An explicit backlink creates the same classifier input used to
    # identify historical automatically generated objects on modern Kind.
    lab.kubectl("patch", "serviceaccount/" + ACCOUNT, "--type=merge", "-p",
                json.dumps({"secrets": [{"name": LEGACY}]}), "-o", "name")
    projected = pod("fixture-projected-declaration", [container("marker")],
                    schedulingGates=[{"name": "saf.example.org/hold-inventory-probe"}],
                    serviceAccountName=ACCOUNT, automountServiceAccountToken=False,
                    volumes=[{"name": "fixture-assertion", "projected": {"sources": [{"serviceAccountToken": {
                        "path": "assertion", "audience": "https://identity.fixture.invalid", "expirationSeconds": 600
                    }}]}}])
    lab.create(projected)
    path = "{.spec.volumes[0].projected.sources[0].serviceAccountToken.expirationSeconds}"
    requested = lab.kubectl("get", "pod/fixture-projected-declaration", "-o", "jsonpath=" + path).stdout.strip()
    initial = inventory(lab)
    expected = {LEGACY: "legacy-linked", MANUAL: "manual-unlinked"}
    before = classify(lab, initial, now)
    lab.check("red", "Metadata distinguishes the two Secret classes, neither had an exception, and projected intent stays separate",
              initial == expected and len(before) == 2 and set(before.values()) == {"missing-or-mismatched"}
              and requested == "600", {"secret_classes": initial, "initial_decisions": before, "projected_requested_seconds": requested})

    exception(lab, LEGACY, expected[LEGACY], now - timedelta(days=1))
    exception(lab, MANUAL, expected[MANUAL], now + timedelta(days=1))
    reviewed = classify(lab, inventory(lab), now)
    lab.check("green", "The review identifies the overdue exception and preserves the current, exact exception",
              reviewed == {LEGACY: "action-due", MANUAL: "current-exception"}, reviewed)
    lab.kubectl("delete", "secret/" + LEGACY, "--wait=true")
    after = inventory(lab)
    remaining = classify(lab, after, now)
    lab.check("positive", "Retirement removes the exact Secret from the inventory and leaves the separate current exception",
              after == {MANUAL: "manual-unlinked"} and remaining == {MANUAL: "current-exception"},
              {"remaining_classes": after, "remaining_decisions": remaining})
    (lab.evidence / "token-governance-observations.json").write_text(json.dumps({
        "inventory_before": initial, "before_exceptions": before, "reviewed_exceptions": reviewed,
        "inventory_after": after, "remaining_exceptions": remaining,
        "projected_requested_seconds": int(requested), "actual_token_lifetimes_tested": False,
    }, indent=2) + "\n")
