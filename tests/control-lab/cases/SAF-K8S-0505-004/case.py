"""Evaluate scoped Kubernetes audit events with an explicit denial rule."""
import base64
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from lab import NODE_IMAGE

ROOT = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
ROUTINE = "routine-included"
EXCLUDED = "routine-excluded"
DENIED = "limited-denial"
AUTH_FAILED = "synthetic-auth-failure"
IDENTITY = "system:serviceaccount:saf-test:audit-limited"
AGGREGATION = "aggregation-fixture"
REPEAT_IDENTITY = "system:serviceaccount:saf-test:audit-repeat-reader"
CONTROL_IDENTITY = "system:serviceaccount:saf-test:audit-control-reader"
AGGREGATION_THRESHOLD = 3
AGGREGATION_WINDOW_SECONDS = 60
RULES = (("expected-rbac-denial", DENIED, 403, IDENTITY),)
AUTH_RULES = (("expected-authentication-failure", AUTH_FAILED, 401, None),)
SCOPE = (
    "One isolated Kubernetes v1.36.1 API server with a blocking Metadata audit policy. "
    "Three exact-name, case-owned ConfigMap reads use the same scoped ServiceAccount via "
    "Kubernetes impersonation. The ordinary and role-denied reads produce completed "
    "metadata events. An explicitly omitted successful read produces no event. A local "
    "detector evaluates only the collected metadata and correlates one 403 with the "
    "effective identity and recorded source path. Forwarded addresses remain context. "
    "A single inert invalid bearer value is sent directly to this disposable API server and "
    "must produce a 401 audit event with no authenticated identity. Production collection, "
    "origin verification and alert delivery need separate evidence. An additive bounded "
    "comparison reads one owned ConfigMap four times as one scoped case identity and once "
    "as a second identity. The detector counts only those actual ResponseComplete metadata "
    "events in one 60-second window; its synthetic threshold is three reads. This does not "
    "model reconnaissance, enumeration, exploitation, production traffic or a universal "
    "anomaly threshold."
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
        request_path = row.get("requestURI", "").split("?", 1)[0]
        if row.get("verb") == "get" and reference.get("namespace") == NAMESPACE and (
            reference.get("resource") == "configmaps" and reference.get("name") in {ROUTINE, EXCLUDED, DENIED}
        ):
            name = reference["name"]
            events.setdefault(name, []).append(row)
        elif (row.get("verb") == "get"
              and reference.get("namespace") == NAMESPACE
              and reference.get("resource") == "configmaps"
              and reference.get("name") == AGGREGATION):
            events.setdefault(AGGREGATION, []).append(row)
        elif (row.get("verb") == "get"
              and request_path == f"/api/v1/namespaces/{NAMESPACE}/configmaps/{AUTH_FAILED}"):
            events.setdefault(AUTH_FAILED, []).append(row)
    return events


def collect(lab, require_aggregation=False):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        events = load_case_events(lab)
        agg = selected_aggregation_events(events)
        agg_repeat = sum(effective_user(event) == REPEAT_IDENTITY for event in agg)
        agg_control = sum(effective_user(event) == CONTROL_IDENTITY for event in agg)
        base_ready = all(events.get(name) for name in (ROUTINE, DENIED, AUTH_FAILED))
        aggregation_ready = agg_repeat >= 4 and agg_control >= 1
        if base_ready and (not require_aggregation or aggregation_ready):
            return events
        time.sleep(0.25)
    lab.block("The expected completed API reads did not arrive in the scoped audit file")


def peer_recorded(event):
    source_ips = event.get("sourceIPs") or []
    if not source_ips:
        return False
    try:
        ipaddress.ip_address(source_ips[-1])
    except (TypeError, ValueError):
        return False
    return True


def effective_user(event):
    return (event.get("impersonatedUser") or event.get("user") or {}).get("username")


def parse_audit_time(event):
    value = event.get("stageTimestamp")
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def selected_aggregation_events(events):
    selected = []
    for event in events.get(AGGREGATION, []):
        ref = event.get("objectRef", {})
        if (event.get("level") == "Metadata"
                and event.get("stage") == "ResponseComplete"
                and event.get("verb") == "get"
                and ref.get("namespace") == NAMESPACE
                and ref.get("resource") == "configmaps"
                and ref.get("name") == AGGREGATION
                and event.get("responseStatus", {}).get("code") == 200
                and effective_user(event) in {REPEAT_IDENTITY, CONTROL_IDENTITY}
                and parse_audit_time(event) is not None):
            selected.append(event)
    return selected


def aggregation_counts(events, enabled=True):
    """Count only selected actual audit events in one first-event-anchored window."""
    selected = selected_aggregation_events(events)
    if not selected:
        return {}, [], False
    times = [parse_audit_time(event) for event in selected]
    start = min(times)
    end = start.timestamp() + AGGREGATION_WINDOW_SECONDS
    inside = all(start.timestamp() <= t.timestamp() < end for t in times)
    counts = {REPEAT_IDENTITY: 0, CONTROL_IDENTITY: 0}
    for event, timestamp in zip(selected, times):
        if start.timestamp() <= timestamp.timestamp() < end:
            counts[effective_user(event)] += 1
    findings = ([actor for actor, count in counts.items() if count >= AGGREGATION_THRESHOLD]
                if enabled else [])
    return counts, findings, inside


def add_aggregation_reader(lab, name, identity):
    lab.kubectl("create", "serviceaccount", name)
    lab.create({
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"name": name},
        "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"],
                   "resourceNames": [AGGREGATION]}],
    })
    lab.kubectl("create", "rolebinding", name, f"--role={name}",
                f"--serviceaccount={NAMESPACE}:{name}")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        allowed = lab.kubectl("auth", "can-i", "get", f"configmap/{AGGREGATION}",
                              "--as", identity, allow_failure=True)
        if allowed.returncode == 0 and allowed.stdout.strip() == "yes":
            return
        time.sleep(0.3)
    lab.block(f"The fixture RoleBinding for {name} did not become active")


def detect(events, rules, stage="ResponseComplete"):
    return [
        (rule, event["auditID"])
        for rule, name, code, username in rules
        for event in events.get(name, [])
        if event.get("stage") == stage
        and event.get("responseStatus", {}).get("code") == code
        and effective_user(event) == username
        and peer_recorded(event)
    ]


def invalid_bearer_read(lab):
    """Send one synthetic invalid token without exposing it in argv or evidence."""
    server_result = lab.kubectl("config", "view", "--minify", "-o",
                                "jsonpath={.clusters[0].cluster.server}")
    ca_result = lab.kubectl("config", "view", "--minify", "--raw", "-o",
                            "jsonpath={.clusters[0].cluster.certificate-authority-data}")
    server = server_result.stdout.strip().rstrip("/")
    endpoint = urllib.parse.urlsplit(server)
    host = endpoint.hostname
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except (TypeError, ValueError):
        loopback = False
    if not loopback or endpoint.scheme != "https" or endpoint.username is not None:
        return {"status": None, "audit_id": "", "transport_error_type": "non_loopback_api_endpoint"}
    ca_data = base64.b64decode(ca_result.stdout.strip()).decode("ascii")
    context = ssl.create_default_context(cadata=ca_data)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(
        server + f"/api/v1/namespaces/{NAMESPACE}/configmaps/{AUTH_FAILED}",
        headers={"Authorization": "Bearer synthetic-invalid-token-not-a-credential"},
        method="GET")
    try:
        with opener.open(request, timeout=5) as response:
            return {"status": response.status, "audit_id": response.headers.get("Audit-Id", "")}
    except urllib.error.HTTPError as response:
        return {"status": response.code, "audit_id": response.headers.get("Audit-Id", "")}
    except Exception as error:
        # Do not serialize exception details that could contain request context.
        return {"status": None, "audit_id": "", "transport_error_type": type(error).__name__}


def run(lab):
    for name in (ROUTINE, EXCLUDED, DENIED, AGGREGATION):
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
    add_aggregation_reader(lab, "audit-repeat-reader", REPEAT_IDENTITY)
    add_aggregation_reader(lab, "audit-control-reader", CONTROL_IDENTITY)

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

    auth_response = invalid_bearer_read(lab)
    auth_request_id = auth_response.pop("audit_id")
    auth_status = auth_response.get("status")
    lab.check("red", "The synthetic invalid bearer request receives HTTP 401 from the owned API server",
              auth_status == 401 and bool(auth_request_id),
              {"http_status": auth_status, "audit_id_returned": bool(auth_request_id)})

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

    auth_events = events.get(AUTH_FAILED, [])
    auth_event = auth_events[0] if len(auth_events) == 1 else {}
    auth_fields = {
        "single_event": len(auth_events) == 1,
        "metadata_level": auth_event.get("level") == "Metadata",
        "response_started_stage": auth_event.get("stage") == "ResponseStarted",
        "status_401": auth_event.get("responseStatus", {}).get("code") == 401,
        "no_authenticated_user": not effective_user(auth_event),
        "audit_id_matches": bool(auth_request_id) and auth_event.get("auditID") == auth_request_id,
        "peer_context_present": peer_recorded(auth_event),
        "request_and_response_objects_absent": auth_event.get("requestObject") is None and auth_event.get("responseObject") is None,
    }
    auth_observed = all(auth_fields.values())
    lab.check("positive", "The API's 401 correlates to one metadata-only failed authentication audit event with peer context",
              auth_observed, auth_fields)
    auth_baseline = detect(events, ())
    auth_findings = detect(events, AUTH_RULES, stage="ResponseStarted")
    lab.check("red", "The authentication failure has no finding while its rule is absent",
              auth_baseline == [], {"finding_count": len(auth_baseline)})
    auth_exact = auth_observed and auth_findings == [("expected-authentication-failure", auth_event["auditID"])]
    lab.check("green", "The activated authentication rule matches exactly the owned 401 event",
              auth_exact, {"finding_count": len(auth_findings), "matched_exact_event": auth_exact})

    # A single fixed, approved object is read using two case-owned identities. The
    # repeat actor performs exactly four GETs; the control actor performs exactly one.
    # The detector consumes only the corresponding native audit events.
    aggregation_requests = []
    sequence = (REPEAT_IDENTITY, REPEAT_IDENTITY, CONTROL_IDENTITY,
                REPEAT_IDENTITY, REPEAT_IDENTITY)
    for identity in sequence:
        response = lab.kubectl("get", "configmap", AGGREGATION, "--as", identity,
                               "-o", "name", allow_failure=True)
        aggregation_requests.append(
            response.returncode == 0 and response.stdout.strip() == f"configmap/{AGGREGATION}")

    events = collect(lab, require_aggregation=True)
    aggregation_events = selected_aggregation_events(events)
    aggregation_times = [parse_audit_time(event) for event in aggregation_events]
    window_start = min(aggregation_times) if aggregation_times else None
    window_end = (window_start.timestamp() + AGGREGATION_WINDOW_SECONDS
                  if window_start else None)
    within_window = bool(aggregation_times) and all(
        window_start.timestamp() <= t.timestamp() < window_end for t in aggregation_times)
    repeat_ids = [event.get("auditID") for event in aggregation_events
                  if effective_user(event) == REPEAT_IDENTITY]
    control_ids = [event.get("auditID") for event in aggregation_events
                   if effective_user(event) == CONTROL_IDENTITY]
    raw_aggregation = {
        "window_start": window_start.isoformat() if window_start else None,
        "window_seconds": AGGREGATION_WINDOW_SECONDS,
        "threshold": AGGREGATION_THRESHOLD,
        "selected_events": aggregation_events,
    }
    (lab.evidence / "api-request-aggregation.raw.json").write_text(
        json.dumps(raw_aggregation, indent=2, sort_keys=True) + "\n")
    request_evidence = (
        all(aggregation_requests)
        and len(aggregation_events) == len(sequence)
        and len(repeat_ids) == 4 and len(control_ids) == 1
        and len(set(repeat_ids + control_ids)) == len(sequence)
        and within_window
    )
    lab.check("positive", "The fixed approved read sequence produces five distinct scoped metadata events",
              request_evidence,
              {"all_reads_permitted": all(aggregation_requests),
               "repeat_actor_event_count": len(repeat_ids),
               "benign_control_event_count": len(control_ids),
               "distinct_audit_events": len(set(repeat_ids + control_ids)) == len(sequence),
               "all_events_within_bounded_window": within_window})
    aggregation_baseline, baseline_findings, baseline_window = aggregation_counts(events, enabled=False)
    lab.check("red", "The repeated-read detector has no finding while its threshold rule is absent",
              baseline_findings == [],
              {"finding_count": len(baseline_findings),
               "repeat_actor_event_count": aggregation_baseline.get(REPEAT_IDENTITY, 0),
               "benign_control_event_count": aggregation_baseline.get(CONTROL_IDENTITY, 0),
               "events_within_bounded_window": baseline_window})
    aggregation_result, findings, result_window = aggregation_counts(events, enabled=True)
    repeat_alert_only = (
        len(aggregation_events) == len(sequence)
        and aggregation_result == {REPEAT_IDENTITY: 4, CONTROL_IDENTITY: 1}
        and findings == [REPEAT_IDENTITY]
        and result_window
        and aggregation_result[REPEAT_IDENTITY] >= AGGREGATION_THRESHOLD
        and aggregation_result[CONTROL_IDENTITY] < AGGREGATION_THRESHOLD
    )
    lab.check("green", "The bounded threshold flags only the repeated actor and leaves the benign control below threshold",
              repeat_alert_only,
              {"repeat_actor_event_count": aggregation_result.get(REPEAT_IDENTITY, 0),
               "benign_control_event_count": aggregation_result.get(CONTROL_IDENTITY, 0),
               "threshold": AGGREGATION_THRESHOLD,
               "window_seconds": AGGREGATION_WINDOW_SECONDS,
               "repeat_actor_fires": REPEAT_IDENTITY in findings,
               "benign_control_fires": CONTROL_IDENTITY in findings,
               "events_within_bounded_window": result_window})

    observations = {"read_excluded_by_policy": omitted, "correct_scoped_metadata": inspected,
                    "exact_denial_match": exact_match, "ordinary_request_preserved": ordinary_ignored,
                    "authenticated_failure_status": auth_status,
                    "auth_failure_audit_match": auth_observed,
                    "auth_failure_exact_rule_match": auth_exact,
                    "aggregation_repeat_actor_count": aggregation_result.get(REPEAT_IDENTITY, 0),
                    "aggregation_benign_control_count": aggregation_result.get(CONTROL_IDENTITY, 0),
                    "aggregation_repeat_actor_only": repeat_alert_only}
    (lab.evidence / "audit-observations.json").write_text(
        json.dumps(observations, indent=2, sort_keys=True) + "\n")
