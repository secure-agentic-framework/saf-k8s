"""Evaluate scoped Kubernetes audit events with an explicit denial rule."""
import ipaddress
import json
from pathlib import Path
import time

from lab import NODE_IMAGE

ROOT = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
ROUTINE = "routine-included"
EXCLUDED = "routine-excluded"
DENIED = "limited-denial"
IDENTITY = "system:serviceaccount:saf-test:audit-limited"
RULES = (("expected-rbac-denial", DENIED, 403),)
SCOPE = (
    "One isolated Kubernetes v1.36.1 API server with a blocking Metadata audit policy. "
    "Three exact-name, case-owned ConfigMap reads use the same scoped ServiceAccount via "
    "Kubernetes impersonation. The ordinary and role-denied reads produce completed "
    "metadata events. An explicitly omitted successful read produces no event. A local "
    "detector evaluates only the collected metadata and correlates one 403 with the "
    "effective identity and recorded source path. Forwarded addresses remain context. "
    "Production collection, origin verification and alert delivery need separate evidence."
)


def prepare_kind(lab, temporary):
    audit = temporary / "audit"
    audit.mkdir(mode=0o700)
    lab.audit_file = audit / "audit.log"
    content = (ROOT / "kind.yaml.in").read_text()
    config = temporary / "kind.yaml"
    config.write_text(content.replace("@POLICY_PATH@", json.dumps(str(ROOT / "audit-policy.yaml")))
                      .replace("@AUDIT_DIR@", json.dumps(str(audit))))
    return config


def load_case_events(lab):
    events = {}
    if not lab.audit_file.is_file():
        return events
    for line in lab.audit_file.read_text().splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue  # Last line may still be written.
        reference = row.get("objectRef", {})
        if row.get("verb") == "get" and reference.get("namespace") == NAMESPACE and (
            reference.get("resource") == "configmaps" and reference.get("name") in {ROUTINE, EXCLUDED, DENIED}
        ):
            name = reference["name"]
            events.setdefault(name, []).append(row)
    return events


def collect(lab):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        events = load_case_events(lab)
        if all(events.get(name) for name in (ROUTINE, DENIED)):
            return events
        time.sleep(0.25)
    lab.block("The expected completed API reads did not arrive in the scoped audit file")


def peer_recorded(event):
    source_ips = event.get("sourceIPs") or []
    if not source_ips:
        return False
    try:
        ipaddress.ip_address(source_ips[-1])
    except ValueError:
        return False
    return True


def effective_user(event):
    return (event.get("impersonatedUser") or event.get("user") or {}).get("username")


def detect(events, rules):
    return [
        (rule, event["auditID"])
        for rule, name, code in rules
        for event in events.get(name, [])
        if event.get("stage") == "ResponseComplete"
        and event.get("responseStatus", {}).get("code") == code
        and effective_user(event) == IDENTITY
        and peer_recorded(event)
    ]


def run(lab):
    for name in (ROUTINE, EXCLUDED, DENIED):
        lab.kubectl("create", "configmap", name, "--from-literal=fixture=inert")
    lab.kubectl("create", "serviceaccount", "audit-limited")
    lab.create({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": "audit-limited"},
        "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"],
                   "resourceNames": [ROUTINE, EXCLUDED]}],
    })
    lab.kubectl("create", "rolebinding", "audit-limited", "--role=audit-limited",
                f"--serviceaccount={NAMESPACE}:audit-limited")

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        allowed = lab.kubectl("auth", "can-i", "get", f"configmap/{ROUTINE}", "--as", IDENTITY,
                              allow_failure=True)
        if allowed.returncode == 0 and allowed.stdout.strip() == "yes":
            break
        time.sleep(0.3)
    else:
        lab.block("The fixture RoleBinding did not become active")

    def read(name):
        return lab.kubectl("get", "configmap", name, "--as", IDENTITY, "-o", "name", allow_failure=True)

    for name in (ROUTINE, EXCLUDED):
        response = read(name)
        lab.check("positive", f"The role permits the ordinary read {name}",
                  response.returncode == 0 and response.stdout.strip() == f"configmap/{name}",
                  {"allowed_by_role": response.returncode == 0})
    denied = read(DENIED)
    forbidden = denied.returncode != 0 and "Forbidden" in denied.stderr and IDENTITY in denied.stderr
    lab.check("red", "The API rejects the exact read outside the fixture Role", forbidden,
              {"forbidden_by_role": forbidden})

    events = collect(lab)
    if any(len(events.get(name, ())) != 1 for name in (ROUTINE, DENIED)):
        lab.block("Expected one audit row per captured fixture request")
    omitted = not events.get(EXCLUDED)
    lab.check("positive", "The blocking audit policy omits its explicit excluded read",
              omitted, {"excluded_request_absent": omitted})

    event_by_code = {200: events[ROUTINE][0], 403: events[DENIED][0]}
    inspected = {}
    for code, event in event_by_code.items():
        inspected[str(code)] = (
            event.get("level") == "Metadata" and event.get("stage") == "ResponseComplete"
            and event.get("responseStatus", {}).get("code") == code
            and effective_user(event) == IDENTITY and peer_recorded(event)
            and event.get("requestObject") is None and event.get("responseObject") is None
            and bool(event.get("auditID"))
        )
    lab.check("positive", "Captured completed metadata records the actor, status, and peer context",
              all(inspected.values()), inspected)
    baseline, result = detect(events, ()), detect(events, RULES)
    lab.check("red", "The captured denial has no alert while the rule is absent",
              baseline == [], {"finding_count": len(baseline)})
    exact_match = result == [("expected-rbac-denial", event_by_code[403]["auditID"])]
    lab.check("green", "The activated rule correlates exactly the captured denial",
              exact_match, {"finding_count": len(result), "matched_exact_audit_id": exact_match})
    ordinary_ignored = all(audit_id != event_by_code[200]["auditID"] for _, audit_id in result)
    lab.check("positive", "The ordinary captured request generates no finding",
              ordinary_ignored, {"ordinary_request_preserved": ordinary_ignored})
    observations = {"read_excluded_by_policy": omitted, "correct_scoped_metadata": inspected,
                    "exact_denial_match": exact_match, "ordinary_request_preserved": ordinary_ignored}
    (lab.evidence / "audit-observations.json").write_text(
        json.dumps(observations, indent=2, sort_keys=True) + "\n")
