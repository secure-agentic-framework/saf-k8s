"""Exercise audit levels, ordered rules, stage omission, and a real watch."""
from contextlib import contextmanager
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, urlsplit

from lab import NODE_IMAGE

CASE_DIR = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
AUDIT_NODE_DIR = "/var/log/kubernetes/audit"
AUDIT_FILE = f"{AUDIT_NODE_DIR}/audit.log"
CLUSTER_SUFFIX = "-audit-policy"
SCOPE = (
    "One default runner cluster without audit flags is compared with one case-owned "
    "kind v1.36.1 API server using a case-owned file backend and ordered audit policy. "
    "Synthetic suspended training Job, zero-replica serving Deployment, metadata-only "
    "ConfigMap and empty dummy Secret create requests exercise Request, RequestResponse, "
    "and Metadata levels. A real watch-only ConfigMap request checks ResponseStarted. "
    "All requests are local, successful API object operations. No application containers "
    "are started. This does not establish production policy adequacy, remote retention, "
    "authorization/admission coverage, managed control plane behavior, or load capacity."
)


def load_fixtures():
    return json.loads((CASE_DIR / "fixtures.json").read_text())


def client_args(cluster, kubeconfig):
    args = ["kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
            "--namespace", NAMESPACE, "--request-timeout=15s"]
    return args


def create_object(lab, cluster, kubeconfig, obj):
    result = lab.command(*client_args(cluster, kubeconfig), "create", "-f", "-", "-o", "json", "--v=8",
                         payload=json.dumps(obj), timeout=25)
    created = json.loads(result.stdout)
    meta = created.get("metadata", {})
    return created.get("kind") == obj["kind"] and meta.get("name") == obj["metadata"]["name"], audit_ids(result.stderr)


def audit_ids(headers):
    return set(re.findall(r"(?i)\baudit-id[\s\x22]*:[\s\x22\[]+([a-f\d-]{36})\b", headers))


def create_fixture_set(lab, cluster, kubeconfig, fixtures):
    results = {}
    for name, obj in fixtures.items():
        results[name] = create_object(lab, cluster, kubeconfig, obj)
    return results


def audit_events(audit_dir):
    path = audit_dir / "audit.log"
    if not path.is_file():
        return []
    events = []
    try:
        with path.open() as stream:
            for line in stream:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # Retain parsed events in memory only. Reports below contain fixed metadata
                # and body-field presence; neither body is ever rendered or logged.
                events.append(event)
    except OSError:
        return []
    return events


def matching_events(audit_dir, resource, name, verb):
    found = []
    for event in audit_events(audit_dir):
        ref = event.get("objectRef") or {}
        uri = urlsplit(event.get("requestURI", ""))
        collection = f"/namespaces/{NAMESPACE}/{resource}"
        if verb == "watch":
            query = parse_qs(uri.query)
            correct_path = (uri.path.endswith(collection)
                            and query.get("watch") == ["true"]
                            and query.get("fieldSelector") == [f"metadata.name={name}"])
        else:
            correct_path = uri.path.endswith(collection)
        if (ref.get("namespace") == NAMESPACE and ref.get("resource") == resource
                and ref.get("name") == name and event.get("verb") == verb
                and correct_path):
            found.append(event)
    return found


def wait_for_events(audit_dir, resource, name, verb, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = matching_events(audit_dir, resource, name, verb)
        if found:
            return found
        time.sleep(0.2)
    return matching_events(audit_dir, resource, name, verb)


def summarize(events, *, include_ids=False):
    return [{
        **({"auditID": event.get("auditID")} if include_ids else {}),
        "stage": event.get("stage"),
        "level": event.get("level"),
        "verb": event.get("verb"),
        "resource": (event.get("objectRef") or {}).get("resource"),
        "name": (event.get("objectRef") or {}).get("name"),
        "code": (event.get("responseStatus") or {}).get("code"),
        "requestObject": "present" if "requestObject" in event else "absent",
        "responseObject": "present" if "responseObject" in event else "absent",
    } for event in events]


def valid_single_request(events, client_ids, *, resource, name, level, request_body, response_body):
    ids = {event.get("auditID") for event in events}
    stages = {event.get("stage") for event in events}
    return (
        len(events) == 1 and len(ids) == 1 and ids.issubset(client_ids)
        and stages == {"ResponseComplete"}
        and all(event.get("level") == level for event in events)
        and all(event.get("responseStatus", {}).get("code") == 201 for event in events)
        and all((event.get("objectRef") or {}).get("resource") == resource for event in events)
        and all((event.get("objectRef") or {}).get("name") == name for event in events)
        and all(("requestObject" in event) == request_body for event in events)
        and all(("responseObject" in event) == response_body for event in events)
        and not any(event.get("stage") == "RequestReceived" for event in events)
    )


def baseline_state(lab):
    # Inspect only the runner-owned API server manifest and the exact backend path.
    script = (
        "set -eu; manifest=/etc/kubernetes/manifests/kube-apiserver.yaml; "
        "test -r $manifest; "
        "if grep -q -- '--audit-' $manifest; then flags=present; else flags=absent; fi; "
        f"if test -e {AUDIT_FILE}; then file=present; else file=absent; fi; "
        "printf 'audit_flags=%s audit_file=%s\\n' $flags $file"
    )
    result = lab.command("docker", "exec", f"{lab.cluster}-control-plane", "sh", "-c", script,
                         timeout=20)
    return result.stdout.strip()


@contextmanager
def audited_cluster(lab):
    cluster = lab.cluster + CLUSTER_SUFFIX
    with tempfile.TemporaryDirectory(prefix="saf-1001-010-") as temp:
        root = Path(temp).resolve()
        audit_dir = root / "audit"
        audit_dir.mkdir()
        kubeconfig = root / "kubeconfig"
        config = root / "kind.yaml"
        policy = CASE_DIR / "audit-policy.yaml"
        template = (CASE_DIR / "kind.yaml.in").read_text()
        config.write_text(template.replace("@POLICY_PATH@", json.dumps(str(policy)))
                          .replace("@AUDIT_DIR@", json.dumps(str(audit_dir))))
        existing = lab.command("kind", "get", "clusters").stdout.splitlines()
        if cluster in existing:
            lab.block(f"Case-owned comparison cluster name is already in use: {cluster}")
        try:
            lab.command("kind", "create", "cluster", "--name", cluster,
                        "--image", NODE_IMAGE, "--config", str(config),
                        "--kubeconfig", str(kubeconfig), "--wait", "90s", timeout=480)
            lab.command(*client_args(cluster, kubeconfig), "create", "namespace", NAMESPACE,
                        timeout=25)
            yield cluster, kubeconfig, audit_dir
        finally:
            lab.command("kind", "delete", "cluster", "--name", cluster,
                        "--kubeconfig", str(kubeconfig), timeout=90)


def start_watch(lab, cluster, kubeconfig, name, log):
    args = client_args(cluster, kubeconfig) + [
        "get", "configmap", name, "--watch-only", "-o", "json", "--v=8"
    ]
    try:
        return subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=log, env=lab.env)
    except OSError as error:
        lab.block(f"Could not start local kubectl watch request: {error}")


def wait_for_watch_event(audit_dir, name, process, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        events = matching_events(audit_dir, "configmaps", name, "watch")
        if any(event.get("stage") == "ResponseStarted" for event in events):
            return events
        if process.poll() is not None:
            break
        time.sleep(0.2)
    return matching_events(audit_dir, "configmaps", name, "watch")


def watch_assertion(events, name, client_ids):
    starts = [event for event in events if event.get("stage") == "ResponseStarted"]
    ids = {event.get("auditID") for event in events}
    return (
        len(starts) == 1 and len(ids) == 1 and ids.issubset(client_ids)
        and all(event.get("level") == "Metadata" for event in events)
        and not any(event.get("stage") == "RequestReceived" for event in events)
        and all("requestObject" not in event and "responseObject" not in event for event in events)
        and all((event.get("objectRef") or {}).get("name") == name for event in events)
    )


def run(lab):
    fixtures = load_fixtures()
    baseline_created = {key: created for key, (created, _) in
                        create_fixture_set(lab, lab.cluster, lab.kubeconfig, fixtures).items()}
    state = baseline_state(lab)
    inactive = "audit_flags=absent" in state and "audit_file=absent" in state
    lab.check("red", "Baseline API accepts the same inert fixture requests with its audit backend inactive",
              all(baseline_created.values()) and inactive,
              {"created": baseline_created, "backend": state})

    with audited_cluster(lab) as (cluster, kubeconfig, audit_dir):
        submissions = create_fixture_set(lab, cluster, kubeconfig, fixtures)
        created = {key: ok for key, (ok, _) in submissions.items()}
        lab.check("positive", "Matched training, serving, metadata and dummy Secret API requests succeed",
                  all(created.values()), {"created": created})

        expectations = {
            "training_job": ("jobs", "Request", True, False),
            "serving_deployment": ("deployments", "RequestResponse", True, True),
            "metadata_configmap": ("configmaps", "Metadata", False, False),
            "dummy_secret": ("secrets", "Metadata", False, False),
        }
        recorded = {}
        receipt = lab.evidence / "audit-observations.json"
        for key, (resource, level, request_body, response_body) in expectations.items():
            name = fixtures[key]["metadata"]["name"]
            events = wait_for_events(audit_dir, resource, name, "create")
            client_ids = submissions[key][1]
            recorded[key] = {"response_ids": sorted(client_ids), "events": summarize(events, include_ids=True)}
            receipt.write_text(json.dumps(recorded, indent=2) + "\n")
            exact = valid_single_request(events, client_ids, resource=resource, name=name, level=level,
                                         request_body=request_body, response_body=response_body)
            detail = {"expected": {"level": level, "requestObject": request_body,
                                   "responseObject": response_body,
                                   "stages": ["ResponseComplete"],
                                   "RequestReceived": "omitted"},
                      "observed": summarize(events), "matches_response_id": exact}
            phase = "green" if key != "dummy_secret" else "positive"
            lab.check(phase, f"Exact {resource}/{name} audit ID has the expected first-match level, body fields and stages",
                      exact, detail)

        # Two overlapping Job rules intentionally differ in level. Request (with no
        # response body) establishes that the earlier matching rule won.
        job_name = fixtures["training_job"]["metadata"]["name"]
        job_events = wait_for_events(audit_dir, "jobs", job_name, "create")
        first_match = valid_single_request(job_events, submissions["training_job"][1], resource="jobs", name=job_name,
                                           level="Request", request_body=True, response_body=False)
        lab.check("green", "Overlapping Job rules resolve to the first Request-level rule",
                  first_match, summarize(job_events))

        watch_name = fixtures["watch_configmap"]["metadata"]["name"]
        watch_created = created["watch_configmap"]
        lab.check("positive", "Watch target ConfigMap exists before opening the real watch",
                  watch_created, f"{NAMESPACE}/{watch_name} created")
        watch_log = kubeconfig.with_name("watch-response.log")
        with watch_log.open("w") as destination:
            process = start_watch(lab, cluster, kubeconfig, watch_name, destination)
            try:
                watch_events = wait_for_watch_event(audit_dir, watch_name, process)
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        client_ids = audit_ids(watch_log.read_text())
        recorded["watch"] = {"response_ids": sorted(client_ids),
                             "events": summarize(watch_events, include_ids=True)}
        receipt.write_text(json.dumps(recorded, indent=2) + "\n")
        lab.check("green", "A real watch records ResponseStarted with one audit ID and omits RequestReceived and bodies",
                  watch_assertion(watch_events, watch_name, client_ids), summarize(watch_events))
