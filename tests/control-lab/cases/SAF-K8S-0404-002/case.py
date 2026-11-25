"""Observe API-server trust validation for two distinct extension paths."""
import base64
import json
from pathlib import Path
import time

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
PYTHON = ("docker.io/library/python:3.13.2-alpine@sha256:"
          "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352")
GROUP = "extension-fixture.saf-k8s.example"
APISERVICE = "v1." + GROUP
NAME = "fixture-extension"
WRONG = "fixture-other-extension"
NS = "saf-test"
LABEL = "saf-k8s.example/extension-fixture"
POLICY_DENIAL = "Owned extension deliberately denies this public fixture"
MUTATOR = "saf-0404-002-mutator"
NO_ENDPOINT_SERVICE = "saf-0404-002-no-endpoints"
NO_ENDPOINT_SELECTOR = {"app": "saf-0404-002-no-endpoints"}
SCOPE = (
    "Separate native Kubernetes admission and API aggregation paths use the same case-owned "
    "HTTPS server. Actual API-server decisions distinguish trusted CA, service DNS identity, "
    "and an explicit admission denial. Workload-to-workload transports, extension-client "
    "authentication, CA reload and production trust policy need independent verification."
)


def root(lab, path, name):
    crt, key = path / f"{name}.crt", path / f"{name}.key"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", f"/CN={name}", "-addext", "basicConstraints=critical,CA:TRUE",
                "-keyout", str(key), "-out", str(crt))
    return crt, key


def certificate(lab, path, approved):
    csr, key, cert = (path / f"fixture-service.{suffix}" for suffix in ("csr", "key", "crt"))
    conf = path / "fixture-extension.ext"
    san = f"{NAME}.{NS}.svc"
    conf.write_text(f"subjectAltName=DNS:{san}\n"
                    "extendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n")
    lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={san}",
                "-keyout", str(key), "-out", str(csr))
    lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(approved[0]), "-CAkey",
                str(approved[1]), "-CAcreateserial", "-days", "1", "-extfile", str(conf), "-out", str(cert))
    lab.kubectl("create", "secret", "tls", "fixture-extension-tls", "--key=" + str(key),
                "--cert=" + str(cert), "-o", "name")


def endpoint(lab):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "fixture-extension-code"},
                "data": {"extension.py": (HERE / "extension.py").read_text()}})
    unit = container("app", image=PYTHON, command=["python3", "/code/extension.py"],
        volumeMounts=[{"name": "tls", "mountPath": "/tls", "readOnly": True},
                      {"name": "code", "mountPath": "/code", "readOnly": True}],
        readinessProbe={"tcpSocket": {"port": 8443}, "periodSeconds": 1})
    workload = pod(NAME, [unit], automountServiceAccountToken=False, securityContext={"fsGroup": 65534},
                   volumes=[{"name": "tls", "secret": {"secretName": "fixture-extension-tls", "defaultMode": 0o440}},
                            {"name": "code", "configMap": {"name": "fixture-extension-code"}}])
    workload["metadata"]["labels"] = {"app": NAME}
    lab.create(workload)
    for service in (NAME, WRONG):
        lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": service},
                    "spec": {"selector": {"app": NAME}, "ports": [{"port": 443, "targetPort": 8443}]}})
    ready(lab, NAME)


def webhook(service, trust):
    return {"name": "fixture-webhook.saf-k8s.example", "admissionReviewVersions": ["v1"],
            "failurePolicy": "Fail", "sideEffects": "None", "timeoutSeconds": 4,
            "clientConfig": {"caBundle": trust, "service": {
                "name": service, "namespace": NS, "path": "/admit", "port": 443}},
            "rules": [{"operations": ["CREATE"], "apiGroups": [""],
                       "apiVersions": ["v1"], "resources": ["configmaps"]}],
            "objectSelector": {"matchLabels": {LABEL: "checked"}}}


def aggregate(service, trust):
    return {"group": GROUP, "version": "v1", "groupPriorityMinimum": 90, "versionPriority": 20,
            "service": {"name": service, "namespace": NS, "port": 443},
            "insecureSkipTLSVerify": False, "caBundle": trust}


def mutator(trust):
    return {"apiVersion": "admissionregistration.k8s.io/v1",
            "kind": "MutatingWebhookConfiguration",
            "metadata": {"name": MUTATOR},
            "webhooks": [{
                "name": "fixture-mutator.saf-k8s.example",
                "admissionReviewVersions": ["v1"], "sideEffects": "None",
                "failurePolicy": "Fail", "matchPolicy": "Exact", "timeoutSeconds": 4,
                "clientConfig": {"caBundle": trust, "service": {
                    "name": NAME, "namespace": NS, "path": "/mutate", "port": 443}},
                "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": NS}},
                "objectSelector": {"matchLabels": {LABEL: "checked"}},
                "rules": [{"apiGroups": [""], "apiVersions": ["v1"],
                           "operations": ["CREATE"], "resources": ["configmaps"],
                           "scope": "Namespaced"}],
            }]}


def mutating_probe(lab, name):
    return lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
        "name": name, "namespace": NS, "labels": {LABEL: "checked"},
        "annotations": {"saf-k8s.example/original": "fixture"}},
        "data": {"fixture": "synthetic dry-run mutation probe"}},
        dry_run=True, allow_failure=True)


def check_mutating_trust(lab, approved_ca, unrelated_ca):
    approved = base64.b64encode(approved_ca.read_bytes()).decode()
    unrelated = base64.b64encode(unrelated_ca.read_bytes()).decode()
    lab.create(mutator(unrelated))
    try:
        denied_name = "fixture-mutator-wrong-ca"
        deadline = time.monotonic() + 45
        denied = None
        while time.monotonic() < deadline:
            denied = mutating_probe(lab, denied_name)
            if denied.returncode != 0 and "fixture-mutator.saf-k8s.example" in denied.stderr \
                    and "x509" in denied.stderr.lower() \
                    and "unknown authority" in denied.stderr.lower():
                break
            time.sleep(.5)
        rejected = (denied is not None and denied.returncode != 0
                    and "fixture-mutator.saf-k8s.example" in denied.stderr
                    and "x509" in denied.stderr.lower()
                    and "unknown authority" in denied.stderr.lower())
        lab.check("red", "The actual mutating webhook route rejects an unrelated CA on a matching dry-run create",
                  rejected, {"x509_unknown_authority": rejected, "same_owned_fixture_route": True})
        ordinary_read = lab.kubectl("get", "namespace", NS, allow_failure=True, timeout=12)
        continuity = ordinary_read.returncode == 0
        lab.check("positive", "Ordinary API reads continue while the mutating webhook trust is wrong",
                  continuity, {"namespace_read_succeeded": continuity})

        ca_patch = [{"op": "replace", "path": "/webhooks/0/clientConfig/caBundle", "value": approved}]
        lab.kubectl("patch", "mutatingwebhookconfiguration", MUTATOR, "--type=json", "-p",
                    json.dumps(ca_patch, separators=(",", ":")), timeout=15)
        allowed_name = "fixture-mutator-approved-ca"
        deadline = time.monotonic() + 45
        result = None
        mutated = False
        event_seen = False
        while time.monotonic() < deadline:
            result = mutating_probe(lab, allowed_name)
            if result.returncode == 0:
                body = json.loads(result.stdout)
                annotations = body.get("metadata", {}).get("annotations", {})
                mutated = (annotations.get("saf-k8s.example/mutated") == "yes"
                           and annotations.get("saf-k8s.example/original") == "fixture")
                logs = lab.kubectl("logs", NAME, "--tail=100", allow_failure=True, timeout=12)
                event_seen = any(
                    entry.get("probe") == allowed_name and entry.get("route") == "mutate"
                    and entry.get("tls") == "TLSv1.3"
                    for line in logs.stdout.splitlines() if line.startswith("fixture-mutating ")
                    for entry in [json.loads(line.removeprefix("fixture-mutating "))]
                )
                if mutated and event_seen:
                    break
            time.sleep(.5)
        success = result is not None and result.returncode == 0 and mutated and event_seen
        lab.check("positive", "Approved trust reaches the mutator and returns the exact fixture JSONPatch result",
                  success, {"dry_run_allowed": result is not None and result.returncode == 0,
                            "exact_annotation_mutation": mutated, "owned_backend_event": event_seen})
    finally:
        lab.kubectl("delete", "mutatingwebhookconfiguration", MUTATOR,
                    "--ignore-not-found=true", allow_failure=True, timeout=15)
    return {"unrelated_ca_refused": rejected, "ordinary_read_continued": continuity,
            "approved_ca_mutated": success}


def _no_ready_endpoints(lab):
    service = json.loads(lab.kubectl("get", "service", NO_ENDPOINT_SERVICE, "-o", "json").stdout)
    slices = json.loads(lab.kubectl(
        "get", "endpointslices", "-l",
        f"kubernetes.io/service-name={NO_ENDPOINT_SERVICE}", "-o", "json").stdout)["items"]
    legacy_result = lab.kubectl("get", "endpoints", NO_ENDPOINT_SERVICE, "-o", "json",
                                allow_failure=True)
    if legacy_result.returncode != 0:
        return False
    legacy = json.loads(legacy_result.stdout)
    slice_addresses = [address for item in slices
                       for endpoint in (item.get("endpoints") or [])
                       for address in (endpoint.get("addresses") or [])]
    legacy_addresses = [address for subset in (legacy.get("subsets") or [])
                        for field in ("addresses", "notReadyAddresses")
                        for address in (subset.get(field) or [])]
    return (service.get("spec", {}).get("selector") == NO_ENDPOINT_SELECTOR
            and not slice_addresses and not legacy_addresses)


def _wait_empty_service(lab):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if _no_ready_endpoints(lab):
            return True
        time.sleep(.5)
    return False


def _webhook_service(lab, kind, name):
    resource = json.loads(lab.kubectl("get", kind, name, "-o", "json").stdout)
    return resource["webhooks"][0]["clientConfig"]["service"]["name"]


def _set_webhook_service(lab, kind, name, service):
    patch = [{"op": "replace", "path": "/webhooks/0/clientConfig/service/name",
              "value": service}]
    lab.kubectl("patch", kind, name, "--type=json", "-p",
                json.dumps(patch, separators=(",", ":")), timeout=15)


def _event_seen(lab, marker, probe, route):
    logs = lab.kubectl("logs", NAME, "--tail=200", allow_failure=True, timeout=12)
    for line in logs.stdout.splitlines():
        if not line.startswith(marker + " "):
            continue
        try:
            entry = json.loads(line.removeprefix(marker + " "))
        except json.JSONDecodeError:
            continue
        if (entry.get("probe") == probe and entry.get("route") == route
                and entry.get("tls") == "TLSv1.3"):
            return True
    return False


def _mutating_recovery_probe(lab, name, *, require_validating):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        result = mutating_probe(lab, name)
        if result.returncode == 0:
            body = json.loads(result.stdout)
            annotations = body.get("metadata", {}).get("annotations", {})
            exact_patch = (annotations.get("saf-k8s.example/original") == "fixture"
                           and annotations.get("saf-k8s.example/mutated") == "yes")
            mutation_event = _event_seen(lab, "fixture-mutating", name, "mutate")
            validation_event = (not require_validating
                                or _event_seen(lab, "fixture-validating", name, "validate"))
            if exact_patch and mutation_event and validation_event:
                return True, exact_patch, mutation_event, validation_event
        time.sleep(.5)
    return False, False, False, False


def _unavailable_webhook_probe(lab, name, webhook_name):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        result = mutating_probe(lab, name)
        error = result.stderr.lower()
        if (result.returncode != 0 and webhook_name.lower() in error
                and NO_ENDPOINT_SERVICE in error
                and any(reason in error for reason in ("no endpoints", "connection refused", "i/o timeout"))
                and "x509" not in error and POLICY_DENIAL.lower() not in error):
            return True
        time.sleep(.5)
    return False


def apply_trust(lab, service, trust, initial=False):
    resources = (
        ("admissionregistration.k8s.io/v1", "ValidatingWebhookConfiguration", NAME, {"webhooks": [webhook(service, trust)]}),
        ("apiregistration.k8s.io/v1", "APIService", APISERVICE, {"spec": aggregate(service, trust)}),
    )
    for api, kind, name, fields in resources:
        if initial:
            lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})
        else:
            lab.kubectl("patch", kind, name, "--type=merge", "-p", json.dumps(fields), "-o", "name")


def admission(lab, deny=False):
    data = {"deny": "deliberate-public-marker"} if deny else {"allow": "deliberate-public-marker"}
    return lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
        "name": "fixture-admission-probe", "labels": {LABEL: "checked"}}, "data": data},
        dry_run=True, allow_failure=True)


def aggregation(lab):
    out = lab.kubectl("get", "apiservice", APISERVICE, "-o", "json").stdout
    conditions = json.loads(out).get("status", {}).get("conditions") or []
    return next((condition for condition in conditions if condition["type"] == "Available"), {})


def wait_for(lab, signal, expected):
    until = time.monotonic() + 45
    while time.monotonic() < until:
        denial = admission(lab)
        api = aggregation(lab)
        if expected == "allow":
            if denial.returncode == 0 and api.get("status") == "True":
                return {"admission": True, "aggregation": True}
        elif expected == "deny":
            admit_denied = denial.returncode != 0 and signal in denial.stderr and POLICY_DENIAL not in denial.stderr
            api_denied = api.get("status") == "False" and signal in api.get("message", "")
            if admit_denied and api_denied:
                return {"admission": True, "aggregation": True}
        time.sleep(.65)
    return {"admission": False, "aggregation": False}


def check_extension_unavailability(lab, approved_ca):
    """Fail and recover three exact API extension routes through a no-endpoint Service."""
    approved = base64.b64encode(approved_ca.read_bytes()).decode()
    marker_path = f"/apis/{GROUP}/v1/fixturemarkers"
    evidence = {}
    try:
        lab.create({"apiVersion": "v1", "kind": "Service",
                    "metadata": {"name": NO_ENDPOINT_SERVICE, "namespace": NS},
                    "spec": {"selector": dict(NO_ENDPOINT_SELECTOR),
                             "ports": [{"name": "https", "port": 443, "targetPort": 8443}]}})
        lab.create(mutator(approved))
        no_endpoints = _wait_empty_service(lab)
        lab.check("positive", "The distinct case-owned Service has no selected backend endpoints",
                  no_endpoints, {"exact_no_endpoint_selector": no_endpoints,
                                 "healthy_extension_service_untouched": True})

        _set_webhook_service(lab, "mutatingwebhookconfiguration", MUTATOR, NO_ENDPOINT_SERVICE)
        mutator_targeted = (_webhook_service(lab, "mutatingwebhookconfiguration", MUTATOR)
                            == NO_ENDPOINT_SERVICE)
        mutator_failed = _unavailable_webhook_probe(
            lab, "fixture-mutator-unavailable", "fixture-mutator.saf-k8s.example")
        mutator_unavailable = no_endpoints and mutator_targeted and mutator_failed
        lab.check("red", "The exact mutating webhook dry-run fails because its selected Service has no endpoints",
                  mutator_unavailable, {"mutator_points_to_empty_service": mutator_targeted,
                                        "route_specific_no_endpoint_failure": mutator_failed})
        mutator_read = lab.kubectl("get", "namespace", NS, allow_failure=True, timeout=12)
        mutator_continuity = mutator_read.returncode == 0
        lab.check("positive", "Ordinary API reads continue during mutating-webhook unavailability",
                  mutator_continuity, {"namespace_read_succeeded": mutator_continuity})

        _set_webhook_service(lab, "mutatingwebhookconfiguration", MUTATOR, NAME)
        mutator_recovered, exact_mutation, mutate_event, _ = _mutating_recovery_probe(
            lab, "fixture-mutator-restored", require_validating=False)
        mutator_recovery = (_webhook_service(lab, "mutatingwebhookconfiguration", MUTATOR) == NAME
                            and mutator_recovered and exact_mutation and mutate_event)
        lab.check("green", "Restoring the mutating webhook Service restores the exact JSONPatch response",
                  mutator_recovery, {"exact_mutation_returned": exact_mutation,
                                    "healthy_mutator_event": mutate_event})
        evidence["mutating_webhook"] = {"unavailable": mutator_unavailable,
                                        "ordinary_api_read": mutator_continuity,
                                        "restored_mutation": mutator_recovery}

        _set_webhook_service(lab, "validatingwebhookconfiguration", NAME, NO_ENDPOINT_SERVICE)
        validator_targeted = (_webhook_service(lab, "validatingwebhookconfiguration", NAME)
                              == NO_ENDPOINT_SERVICE)
        validator_name = "fixture-mutator-validator-unavailable"
        validator_failed = _unavailable_webhook_probe(
            lab, validator_name, "fixture-webhook.saf-k8s.example")
        mutation_arrived = _event_seen(lab, "fixture-mutating", validator_name, "mutate")
        validator_unavailable = (no_endpoints and validator_targeted
                                 and validator_failed and mutation_arrived)
        lab.check("red", "The validating webhook dry-run fails at its empty Service after the mutator is reached",
                  validator_unavailable, {"validator_points_to_empty_service": validator_targeted,
                                          "route_specific_no_endpoint_failure": validator_failed,
                                          "healthy_mutator_served_same_probe": mutation_arrived})
        validator_read = lab.kubectl("get", "namespace", NS, allow_failure=True, timeout=12)
        validator_continuity = validator_read.returncode == 0
        lab.check("positive", "Ordinary API reads continue during validating-webhook unavailability",
                  validator_continuity, {"namespace_read_succeeded": validator_continuity})

        _set_webhook_service(lab, "validatingwebhookconfiguration", NAME, NAME)
        validator_recovered, exact_mutation, mutate_event, validate_event = _mutating_recovery_probe(
            lab, "fixture-mutator-validator-restored", require_validating=True)
        validator_recovery = (_webhook_service(lab, "validatingwebhookconfiguration", NAME) == NAME
                              and validator_recovered and exact_mutation
                              and mutate_event and validate_event)
        lab.check("green", "Restoring validation accepts the route and returns the exact mutation",
                  validator_recovery, {"exact_mutation_returned": exact_mutation,
                                       "healthy_mutator_event": mutate_event,
                                       "healthy_validator_event": validate_event})
        evidence["validating_webhook"] = {"unavailable_after_mutator": validator_unavailable,
                                          "ordinary_api_read": validator_continuity,
                                          "restored_mutation_and_validation": validator_recovery}

        api_down = aggregate(NO_ENDPOINT_SERVICE, approved)
        lab.kubectl("patch", "apiservice", APISERVICE, "--type=merge", "-p",
                    json.dumps({"spec": api_down}, separators=(",", ":")), timeout=15)
        deadline = time.monotonic() + 45
        aggregate_failed = False
        api_condition = {}
        raw = None
        while time.monotonic() < deadline:
            api_condition = aggregation(lab)
            raw = lab.kubectl("get", "--raw", marker_path,
                              allow_failure=True, timeout=12)
            message = api_condition.get("message", "").lower()
            exact_endpoint_reason = (
                NO_ENDPOINT_SERVICE in message and api_condition.get("reason") in
                {"MissingEndpoints", "EndpointsNotFound", "EndpointSlicesNotFound"}
            )
            aggregate_failed = (raw.returncode != 0 and "serviceunavailable" in raw.stderr.lower()
                                and api_condition.get("status") == "False" and exact_endpoint_reason)
            if aggregate_failed:
                break
            time.sleep(.5)
        lab.check("red", "The exact aggregation marker read reports APIService unavailable for its empty Service",
                  no_endpoints and aggregate_failed,
                  {"api_service_unavailable": api_condition.get("status") == "False",
                   "service_no_endpoint_reason": exact_endpoint_reason,
                   "marker_read_service_unavailable": raw is not None
                   and "serviceunavailable" in raw.stderr.lower()})
        aggregation_read = lab.kubectl("get", "namespace", NS, allow_failure=True, timeout=12)
        aggregation_continuity = aggregation_read.returncode == 0
        lab.check("positive", "Ordinary API reads continue during aggregation endpoint unavailability",
                  aggregation_continuity, {"namespace_read_succeeded": aggregation_continuity})

        lab.kubectl("patch", "apiservice", APISERVICE, "--type=merge", "-p",
                    json.dumps({"spec": aggregate(NAME, approved)}, separators=(",", ":")), timeout=15)
        deadline = time.monotonic() + 45
        aggregate_recovered = False
        last_items = []
        aggregate_event = False
        while time.monotonic() < deadline:
            api_condition = aggregation(lab)
            raw = lab.kubectl("get", "--raw",
                              marker_path + "?probe=fixture-availability-aggregate-restored",
                              allow_failure=True, timeout=12)
            if raw.returncode == 0:
                last_items = json.loads(raw.stdout).get("items", [])
            items_ok = [row.get("metadata", {}).get("name") for row in last_items] == [
                "owned-aggregation-marker"]
            aggregate_event = _event_seen(lab, "fixture-aggregating",
                                          "fixture-availability-aggregate-restored", "aggregate")
            if api_condition.get("status") == "True" and items_ok and aggregate_event:
                aggregate_recovered = True
                break
            time.sleep(.5)
        lab.check("green", "Restoring the APIService route restores readiness and the exact marker read",
                  aggregate_recovered,
                  {"api_service_available": api_condition.get("status") == "True",
                   "exact_marker_returned": [row.get("metadata", {}).get("name") for row in last_items]
                   == ["owned-aggregation-marker"],
                   "healthy_aggregation_event": aggregate_event})
        evidence["aggregation"] = {"unavailable": aggregate_failed,
                                   "ordinary_api_read": aggregation_continuity,
                                   "restored_marker_read": aggregate_recovered}
        return evidence
    finally:
        try:
            apply_trust(lab, NAME, approved)
        finally:
            lab.kubectl("delete", "mutatingwebhookconfiguration", MUTATOR,
                        "--ignore-not-found=true", allow_failure=True, timeout=15)
            lab.kubectl("delete", "service", NO_ENDPOINT_SERVICE,
                        "--ignore-not-found=true", allow_failure=True, timeout=15)


def run(lab):
    path = lab.kubeconfig.parent
    approved, unrelated = root(lab, path, "fixture-approved-ca"), root(lab, path, "fixture-unrelated-ca")
    certificate(lab, path, approved)
    endpoint(lab)
    pass_ca = base64.b64encode(approved[0].read_bytes()).decode()
    fail_ca = base64.b64encode(unrelated[0].read_bytes()).decode()

    apply_trust(lab, NAME, fail_ca, initial=True)
    first = wait_for(lab, "certificate signed by unknown authority", "deny")
    lab.check("red", "The API server rejects both extension paths when the trust bundle excludes the actual issuer",
              all(first.values()), first)
    apply_trust(lab, WRONG, pass_ca)
    wrong = wait_for(lab, "certificate is valid for", "deny")
    lab.check("green", "The same trusted chain is denied on both paths when the Service DNS name does not match",
              all(wrong.values()), wrong)

    apply_trust(lab, NAME, pass_ca)
    trusted = wait_for(lab, "", "allow")
    blocked = admission(lab, deny=True)
    observed = False
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        response = lab.kubectl("get", "--raw", f"/apis/{GROUP}/v1/fixturemarkers", allow_failure=True, timeout=12)
        if response.returncode == 0 and [
                row["metadata"]["name"] for row in json.loads(response.stdout)["items"]] == ["owned-aggregation-marker"]:
            observed = True
            break
        time.sleep(.5)
    received = lab.kubectl("logs", NAME).stdout
    protocols = {"admission": set(), "aggregation": set()}
    for line in received.splitlines():
        if line.startswith("fixture-protocol "):
            entry = json.loads(line.removeprefix("fixture-protocol "))
            protocols[entry["route"]].add(entry["tls"])
    protocols = {route: sorted(versions) for route, versions in protocols.items()}
    lab.check("positive", "Both actual extension routes negotiate the configured TLS 1.3 protocol",
              protocols == {"admission": ["TLSv1.3"], "aggregation": ["TLSv1.3"]}, protocols)
    positive = {"accepted_trusted_admission": trusted["admission"],
                "trusted_api_aggregation_marker_read": trusted["aggregation"] and observed,
                "explicit_valid_webhook_denial": blocked.returncode != 0 and POLICY_DENIAL in blocked.stderr
                and "x509" not in blocked.stderr}
    lab.check("positive", "Both trusted paths work and a valid webhook decision remains distinct from failed TLS",
              all(positive.values()), positive)
    mutating = check_mutating_trust(lab, approved[0], unrelated[0])
    availability = check_extension_unavailability(lab, approved[0])
    (lab.evidence / "extension-tls-observations.json").write_text(json.dumps({
        "wrong_authority": first, "wrong_endpoint_name": wrong, "correct_tls": positive, "negotiated_protocols": protocols,
        "mutating_webhook": mutating,
        "extension_unavailability_and_recovery": availability,
    }, indent=2) + "\n")

SCOPE += " The owned receivers require TLS 1.3 and record the negotiated version for each exact API-server operation. "
SCOPE += " A separate selector-isolated Service with no endpoints checks fail-closed API extension calls and same-route recovery without stopping workloads."
