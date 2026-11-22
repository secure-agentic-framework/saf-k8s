"""Exercise fail-closed webhook timeout behavior for harmless ConfigMaps."""
import base64
import json
from pathlib import Path
import tempfile
import time


HERE = Path(__file__).parent
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NAMESPACE = "saf-test"
SELECTOR = "saf-k8s.example/admission=enabled"
WEBHOOK = "saf-0605-fixture"
SERVICE = "saf-0605-webhook"
TIMEOUT_SECONDS = 2  # Deliberate operational budget, within Kubernetes' 1..30 bound.
SCOPE = (
    "One disposable Kubernetes v1.36.1 kind cluster and one case-owned HTTPS "
    "AdmissionReview service using a digest-pinned Python image. Validating and "
    "mutating admission configurations match CREATE requests for ConfigMaps only "
    "in the case namespace. The fixture permits healthy requests, delays marked "
    "requests by six seconds, and adds one inert label in mutating mode. The case "
    "compares Fail and Ignore on the same deliberate timeout, checks persisted "
    "ConfigMap state, and exercises an excluded namespace and GET path. Results "
    "cover this v1.36.1 kind setup, not production topology, complete admission "
    "chain latency, workload impact, or operational policy appropriateness."
)


def _owned_kubectl(lab, *args, payload=None, timeout=40, allow_failure=False,
                   action="Kubernetes API request"):
    """Use only the runner's private kubeconfig and exact cluster context."""
    command = [
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
        f"kind-{lab.cluster}", f"--request-timeout={max(5, timeout - 5)}s", *args,
    ]
    try:
        return lab.command(*command, payload=payload, timeout=timeout,
                           allow_failure=allow_failure)
    except Exception as error:
        if allow_failure:
            raise
        lab.block(f"{action} could not complete ({type(error).__name__})")


def _certificates(lab, temp):
    ca_key = temp / "fixture-ca.key"
    ca_cert = temp / "fixture-ca.crt"
    leaf_key = temp / "fixture-tls.key"
    leaf_csr = temp / "fixture-tls.csr"
    leaf_cert = temp / "fixture-tls.crt"
    ext = temp / "fixture-ext.cnf"
    ext.write_text(
        "subjectAltName=DNS:saf-0605-webhook.saf-test.svc\n"
        "extendedKeyUsage=serverAuth\n"
        "basicConstraints=CA:FALSE\n",
        encoding="ascii",
    )
    # Keys remain in the runner's private temporary directory. The command
    # transcript records paths and statuses, never key contents.
    for command in (
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(ca_key), "-out", str(ca_cert), "-days", "1",
         "-subj", "/CN=SAF-K8S-0605-007 fixture CA", "-addext", "basicConstraints=critical,CA:TRUE"],
        ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(leaf_key), "-out", str(leaf_csr), "-subj",
         "/CN=saf-0605-webhook.saf-test.svc"],
        ["openssl", "x509", "-req", "-in", str(leaf_csr), "-CA", str(ca_cert),
         "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(leaf_cert),
         "-days", "1", "-extfile", str(ext)],
    ):
        try:
            lab.command(*command, timeout=30)
        except Exception as error:
            lab.block(f"case-owned TLS material could not be generated ({type(error).__name__})")
    return ca_cert, leaf_cert, leaf_key


def _create_fixture(lab, temp):
    ca_cert, leaf_cert, leaf_key = _certificates(lab, temp)
    _owned_kubectl(lab, "label", "namespace", NAMESPACE, SELECTOR, "--overwrite")
    _owned_kubectl(
        lab, "-n", NAMESPACE, "create", "secret", "tls", "saf-0605-fixture-tls",
        "--cert", str(leaf_cert), "--key", str(leaf_key),
    )
    server_config = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "saf-0605-fixture-code", "namespace": NAMESPACE},
        "data": {"fixture.py": (HERE / "fixture.py").read_text(encoding="utf-8")},
    }
    _owned_kubectl(lab, "apply", "-f", "-", payload=json.dumps(server_config))
    deployment = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": SERVICE, "namespace": NAMESPACE},
        "spec": {"replicas": 1,
                 "selector": {"matchLabels": {"app": SERVICE}},
                 "template": {
                     "metadata": {"labels": {"app": SERVICE}},
                     "spec": {
                         "automountServiceAccountToken": False,
                         "containers": [{
                             "name": "fixture", "image": IMAGE,
                             "imagePullPolicy": "IfNotPresent",
                             "command": ["python", "/fixture/fixture.py"],
                             "ports": [{"name": "https", "containerPort": 8443}],
                             "readinessProbe": {"tcpSocket": {"port": 8443},
                                                "initialDelaySeconds": 1,
                                                "periodSeconds": 1},
                             "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                           "limits": {"cpu": "100m", "memory": "96Mi"}},
                             "securityContext": {
                                 "allowPrivilegeEscalation": False,
                                 "readOnlyRootFilesystem": True,
                                 "runAsNonRoot": True,
                                 "runAsUser": 10001,
                                 "capabilities": {"drop": ["ALL"]},
                             },
                             "volumeMounts": [
                                 {"name": "code", "mountPath": "/fixture", "readOnly": True},
                                 {"name": "tls", "mountPath": "/tls", "readOnly": True},
                             ],
                         }],
                         "volumes": [
                             {"name": "code", "configMap": {"name": "saf-0605-fixture-code"}},
                             {"name": "tls", "secret": {"secretName": "saf-0605-fixture-tls"}},
                         ],
                     },
                 }},
    }
    service = {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": SERVICE, "namespace": NAMESPACE},
        "spec": {"selector": {"app": SERVICE},
                 "ports": [{"name": "https", "port": 443, "targetPort": 8443}]},
    }
    _owned_kubectl(lab, "apply", "-f", "-", payload=json.dumps({"apiVersion": "v1", "kind": "List",
                                                                      "items": [deployment, service]}))
    _owned_kubectl(lab, "-n", NAMESPACE, "rollout", "status", f"deployment/{SERVICE}",
                   "--timeout=90s", timeout=100)
    return base64.b64encode(ca_cert.read_bytes()).decode("ascii")


def _webhook(kind, ca_bundle, failure_policy):
    is_mutating = kind == "mutating"
    resource = "MutatingWebhookConfiguration" if is_mutating else "ValidatingWebhookConfiguration"
    endpoint = "/mutate" if is_mutating else "/validate"
    webhook = {
        "name": f"{WEBHOOK}.saf-k8s.example",
        "admissionReviewVersions": ["v1"],
        "sideEffects": "None",
        "failurePolicy": failure_policy,
        "matchPolicy": "Equivalent",
        "timeoutSeconds": TIMEOUT_SECONDS,
        "clientConfig": {
            "service": {"namespace": NAMESPACE, "name": SERVICE, "path": endpoint, "port": 443},
            "caBundle": ca_bundle,
        },
        "namespaceSelector": {"matchLabels": {"saf-k8s.example/admission": "enabled"}},
        "rules": [{"apiGroups": [""], "apiVersions": ["v1"],
                   "operations": ["CREATE"], "resources": ["configmaps"],
                   "scope": "Namespaced"}],
    }
    return {"apiVersion": "admissionregistration.k8s.io/v1", "kind": resource,
            "metadata": {"name": WEBHOOK}, "webhooks": [webhook]}


def _activate(lab, kind, ca_bundle, failure_policy):
    resource = "mutatingwebhookconfiguration" if kind == "mutating" else "validatingwebhookconfiguration"
    _owned_kubectl(lab, "delete", "mutatingwebhookconfiguration", WEBHOOK,
                   allow_failure=True, action="remove prior mutating configuration")
    _owned_kubectl(lab, "delete", "validatingwebhookconfiguration", WEBHOOK,
                   allow_failure=True, action="remove prior validating configuration")
    _owned_kubectl(lab, "apply", "-f", "-",
                   payload=json.dumps(_webhook(kind, ca_bundle, failure_policy)))
    _owned_kubectl(lab, "get", resource, WEBHOOK, "-o", "name")


def _candidate(name, *, slow=False, deny=False):
    return {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": NAMESPACE,
                     "labels": {"saf-k8s.example/mode": "deny" if deny else ("slow" if slow else "healthy"),
                                "saf-k8s.example/case": "0605-007"}},
        "data": {"marker": "harmless synthetic fixture"},
    }


def _create(lab, resource, *, expected_failure=False, dry_run=False):
    options = ["--dry-run=server"] if dry_run else []
    result = _owned_kubectl(lab, "create", "-f", "-", "-o", "json", *options,
                            payload=json.dumps(resource), timeout=25,
                            allow_failure=expected_failure,
                            action="synthetic ConfigMap create")
    return result


def _exists(lab, name, namespace=NAMESPACE):
    result = _owned_kubectl(lab, "-n", namespace, "get", "configmap", name, "-o", "json",
                            allow_failure=True, action="read synthetic ConfigMap")
    if result.returncode:
        if "(NotFound)" in result.stderr:
            return False, None
        lab.block("ConfigMap state could not be distinguished from an API read failure")
    try:
        return True, json.loads(result.stdout)
    except json.JSONDecodeError:
        lab.block("ConfigMap response was not valid JSON")


def _timeout_rejected(result):
    text = (result.stderr + result.stdout).lower()
    timeout_evidence = any(token in text for token in
                           ("context deadline exceeded", "client.timeout exceeded", "request timed out"))
    return result.returncode != 0 and "failed calling webhook" in text and timeout_evidence


def _wait_for_path(lab, kind):
    deadline = time.monotonic() + 25
    manifest = _candidate("saf-0605-readiness", deny=True)
    path = "/mutate" if kind == "mutating" else "/validate"
    while time.monotonic() < deadline:
        result = _create(lab, manifest, expected_failure=True, dry_run=True)
        if result.returncode and f"SAF-0605 fixture explicit denial via {path}" in result.stderr:
            return
        if result.returncode and "failed calling webhook" not in result.stderr:
            lab.block(f"Unexpected response checking {kind} webhook readiness")
        time.sleep(0.25)
    lab.block(f"The exact {kind} webhook did not answer a live server dry-run")


def _observe_slow_call(lab, kind, name):
    path = "/mutate" if kind == "mutating" else "/validate"
    response = _owned_kubectl(lab, "-n", NAMESPACE, "logs", f"deployment/{SERVICE}", "--tail=40")
    return f"slow:{path}:{name}" in response.stdout.splitlines()


def _slow_attempt(lab, manifest, *, dry_run=False):
    started = time.monotonic()
    result = _create(lab, manifest, expected_failure=True, dry_run=dry_run)
    return result, TIMEOUT_SECONDS - 0.25 <= time.monotonic() - started < 5.5


def _fail_then_ignore(lab, kind, ca_bundle):
    name = f"saf-0605-{kind}-slow"
    manifest = _candidate(name, slow=True)
    failed, bounded = _slow_attempt(lab, manifest)
    exists, _ = _exists(lab, name)
    observed = {
        "timeout_rejected": _timeout_rejected(failed),
        "within_fixture_budget": bounded,
        "request_seen_by_fixture": _observe_slow_call(lab, kind, name),
        "not_persisted": not exists,
    }
    lab.check("green", f"{kind} Fail rejects the observed timeout and persists no ConfigMap",
              all(observed.values()), observed)

    _activate(lab, kind, ca_bundle, "Ignore")
    _wait_for_path(lab, kind)
    canary_name = f"saf-0605-{kind}-ignore-canary"
    canary = _candidate(canary_name, slow=True)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        result, bounded = _slow_attempt(lab, canary, dry_run=True)
        if result.returncode == 0 and bounded:
            break
    else:
        lab.block(f"{kind} failed to observe successful Ignore timeout canary")

    admitted, bounded = _slow_attempt(lab, manifest)
    exists, obj = _exists(lab, name)
    patch_present = bool((obj or {}).get("metadata", {}).get("labels", {}).get(
        "saf-k8s.example/admission"))
    observed = {
        "admitted_after_timeout": admitted.returncode == 0 and bounded,
        "persisted": exists,
        "timed_out_mutation_not_applied": not patch_present,
        "request_seen_by_fixture": _observe_slow_call(lab, kind, canary_name),
    }
    lab.check("positive", f"{kind} Ignore admits the identical slow request within the fixture budget",
              all(observed.values()), observed)


def _check_bounds(lab, ca_bundle):
    for kind in ("validating", "mutating"):
        configuration = _webhook(kind, ca_bundle, "Fail")
        entry = configuration["webhooks"][0]
        del entry["timeoutSeconds"]
        del entry["failurePolicy"]
        response = _create(lab, configuration, dry_run=True)
        webhook = json.loads(response.stdout)["webhooks"][0]
        lab.check("positive", f"{kind} webhook defaults both timeoutSeconds and failurePolicy",
                  webhook["timeoutSeconds"] == 10 and webhook["failurePolicy"] == "Fail",
                  {"timeout_seconds": webhook["timeoutSeconds"], "failure_policy": webhook["failurePolicy"]})
        for seconds, accepted in ((0, False), (1, True), (30, True), (31, False)):
            entry["timeoutSeconds"] = seconds
            result = _create(lab, configuration, expected_failure=True, dry_run=True)
            rejected_by_field = result.returncode != 0 and "timeoutSeconds" in result.stderr
            matched = result.returncode == 0 if accepted else rejected_by_field
            lab.check("green" if not accepted else "positive",
                      f"{kind} API applies its timeoutSeconds bounds to {seconds}",
                      matched, {"requested_seconds": seconds, "accepted": result.returncode == 0,
                                "field_rejection": rejected_by_field})


def run(lab):
    with tempfile.TemporaryDirectory(prefix="saf-0605-007-") as raw_temp:
        baseline_name = "saf-0605-no-webhook-baseline"
        baseline = _create(lab, _candidate(baseline_name, slow=True))
        baseline_exists, _ = _exists(lab, baseline_name)
        lab.check("red", "Without the case webhook, a marked ConfigMap is admitted",
                  baseline.returncode == 0 and baseline_exists,
                  {"classification": "admitted_without_webhook" if baseline.returncode == 0
                   else "not_admitted", "persisted": baseline_exists})

        ca_bundle = _create_fixture(lab, Path(raw_temp))
        _check_bounds(lab, ca_bundle)

        # Validating healthy path, Fail timeout and Ignore counterfactual.
        _activate(lab, "validating", ca_bundle, "Fail")
        _wait_for_path(lab, "validating")
        healthy_name = "saf-0605-validating-healthy"
        healthy = _create(lab, _candidate(healthy_name))
        healthy_exists, _ = _exists(lab, healthy_name)
        lab.check("positive", "Validating webhook permits a healthy synthetic ConfigMap",
                  healthy.returncode == 0 and healthy_exists,
                  {"classification": "permitted" if healthy.returncode == 0 else "rejected",
                   "persisted": healthy_exists})
        _fail_then_ignore(lab, "validating", ca_bundle)

        # Mutating webhook healthy permit applies one inert label; timeout semantics match validation.
        _activate(lab, "mutating", ca_bundle, "Fail")
        _wait_for_path(lab, "mutating")
        mutate_name = "saf-0605-mutating-healthy"
        mutated = _create(lab, _candidate(mutate_name))
        mutated_exists, mutated_obj = _exists(lab, mutate_name)
        label_value = ((mutated_obj or {}).get("metadata", {}).get("labels", {})
                       .get("saf-k8s.example/admission"))
        lab.check("positive", "Mutating webhook permits and adds only its inert label",
                  mutated.returncode == 0 and mutated_exists and label_value == "fixture",
                  {"classification": "permitted_and_patched" if label_value == "fixture" else "not_patched",
                   "persisted": mutated_exists, "inert_label": label_value == "fixture"})
        _fail_then_ignore(lab, "mutating", ca_bundle)

        # Prove namespace and operation scoping while a Fail webhook has no
        # backend. A selected CREATE must fail; GET and excluded-namespace
        # CREATE must still work without relying on a healthy permit response.
        _activate(lab, "validating", ca_bundle, "Fail")
        _wait_for_path(lab, "validating")
        _owned_kubectl(lab, "-n", NAMESPACE, "patch", "service", SERVICE, "--type=merge",
                       "-p", '{"spec":{"selector":{"app":"fixture-offline"}}}')
        empty_endpoints = False
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            endpoint_result = _owned_kubectl(lab, "-n", NAMESPACE, "get", "endpoints", SERVICE, "-o", "json")
            endpoint_data = json.loads(endpoint_result.stdout)
            if not any(subset.get("addresses") for subset in endpoint_data.get("subsets", [])):
                empty_endpoints = True
                break
            time.sleep(0.25)
        if not empty_endpoints:
            lab.block("case-owned webhook Service did not reach the no-endpoint state")
        unavailable_name = "saf-0605-selected-backend-offline"
        unavailable = _create(lab, _candidate(unavailable_name), expected_failure=True)
        unavailable_exists, _ = _exists(lab, unavailable_name)
        get_result = _owned_kubectl(lab, "-n", NAMESPACE, "get", "configmap", healthy_name, "-o", "json",
                                    allow_failure=True, action="unmatched ConfigMap GET")
        _owned_kubectl(lab, "create", "namespace", "saf-0605-unaffected")
        outside = _candidate("saf-0605-unaffected-create")
        outside["metadata"]["namespace"] = "saf-0605-unaffected"
        outside_create = _owned_kubectl(lab, "create", "-f", "-", "-o", "json",
                                        payload=json.dumps(outside), allow_failure=True,
                                        action="excluded-namespace ConfigMap CREATE")
        outside_exists, _ = _exists(lab, outside["metadata"]["name"], "saf-0605-unaffected")
        selected_hook_failure = "failed calling webhook" in (unavailable.stderr + unavailable.stdout).lower()
        lab.check(
            "positive", "Unmatched GET and excluded-namespace CREATE work with the Fail webhook unavailable",
            empty_endpoints and selected_hook_failure and unavailable.returncode != 0 and not unavailable_exists
            and get_result.returncode == 0 and outside_create.returncode == 0 and outside_exists,
            {"classification": "scope_exemptions_work" if get_result.returncode == 0
             and outside_create.returncode == 0 and outside_exists else "scope_probe_failed",
             "selected_create_rejected": selected_hook_failure and unavailable.returncode != 0
             and not unavailable_exists,
             "unmatched_get_permitted": get_result.returncode == 0,
             "excluded_namespace_create_permitted": outside_create.returncode == 0 and outside_exists,
             "backend_state": "no_endpoints" if empty_endpoints else "unknown"},
        )
