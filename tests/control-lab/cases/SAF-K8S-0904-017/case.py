"""Real Kubernetes admission probes for a narrowly scoped WorkflowTemplate signature verifier."""
import base64
import hashlib
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
NAMESPACE = "saf-signing-admission"
WEBHOOK = "saf-workflow-signature"
SERVICE_DNS = f"{WEBHOOK}.{NAMESPACE}.svc.cluster.local"
IMAGE = "docker.io/library/golang:1.26.11-alpine3.24@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab"
CRD_SHA256 = "d7b69c80937843de3216185ed3400641a598cfdee4518b1e6fea11214b46633e"
LICENSE_SHA256 = "c996fc213c94f4a4a838407d355b081226caa7b103a4f239bb87fb8f1d8e3a60"
EXPECTED = {
    "unsigned": "signature is absent",
    "changed_trusted": "signature does not verify over canonical WorkflowTemplate identity and spec",
    "untrusted": "signature is valid but fixture identity is not trusted",
}
SCOPE = (
    "One disposable Kubernetes v1.36.1 cluster installs the official Argo Workflows v3.7.6 minimal "
    "namespaced WorkflowTemplate CRD and a fail-closed admissionregistration.k8s.io/v1 webhook. "
    "Only CREATE/UPDATE requests for WorkflowTemplates in saf-signing-admission are selected. "
    "A fixed benign template is tested unsigned, changed with a stale signature, signed by an "
    "untrusted ephemeral identity, and signed by a trusted ephemeral identity. No Argo controller "
    "is installed, so no WorkflowTemplate is instantiated or executed. Production trust and signer "
    "lifecycle remain outside this fixture."
)


def create(lab, obj, *, allow_failure=False, dry_run=False):
    flags = ["--dry-run=server"] if dry_run else []
    return lab.kubectl("create", "-f", "-", "-o", "json", "-n", NAMESPACE, *flags,
                       payload=json.dumps(obj, separators=(",", ":")), allow_failure=allow_failure)


def replace(lab, obj):
    return lab.kubectl("replace", "-f", "-", "-o", "json", "-n", NAMESPACE,
                       payload=json.dumps(obj, separators=(",", ":")), allow_failure=True)


def explicit_webhook_denial(result, expected):
    err = result.stderr.lower()
    return (result.returncode != 0 and "signature.saf.example.test" in err
            and expected.lower() in err and "denied the request" in err)


def webhook_configuration(ca_bundle):
    return {
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingWebhookConfiguration",
        "metadata": {"name": "saf-workflow-signatures"},
        "webhooks": [{
            "name": "signature.saf.example.test",
            "admissionReviewVersions": ["v1"],
            "sideEffects": "None",
            "failurePolicy": "Fail",
            "matchPolicy": "Equivalent",
            "timeoutSeconds": 5,
            "clientConfig": {"service": {"namespace": NAMESPACE, "name": WEBHOOK,
                "path": "/validate", "port": 443}, "caBundle": base64.b64encode(ca_bundle.encode()).decode("ascii")},
            "namespaceSelector": {"matchLabels": {"saf.example.test/signature-enforcement": "required"}},
            "matchConditions": [{"name": "exact-case-namespace",
                                 "expression": f'request.namespace == "{NAMESPACE}"'}],
            "rules": [{"operations": ["CREATE", "UPDATE"], "apiGroups": ["argoproj.io"],
                "apiVersions": ["v1alpha1"], "resources": ["workflowtemplates"],
                "scope": "Namespaced"}],
        }],
    }


def denied(lab, obj, expected, *, dry_run):
    result = create(lab, obj, allow_failure=True, dry_run=dry_run)
    return explicit_webhook_denial(result, expected)


def deployment(source_name):
    labels = {"app": WEBHOOK}
    return {
        "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": WEBHOOK, "namespace": NAMESPACE},
        "spec": {"replicas": 1, "selector": {"matchLabels": labels}, "template": {
            "metadata": {"labels": labels}, "spec": {
                "automountServiceAccountToken": False,
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                    "fsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
                "volumes": [
                    {"name": "source", "configMap": {"name": source_name}},
                    {"name": "cache", "emptyDir": {}},
                ],
                "containers": [{
                    "name": "webhook", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                    "command": ["/bin/sh", "-ec",
                        "mkdir -p /cache/go-build /cache/gopath /cache/tmp /cache/tls; "
                        "go build -trimpath -o /cache/verifier /src/webhook.go; "
                        "/cache/verifier material /cache/material /src/workflow-template.json; "
                        '/cache/verifier tls-material /cache/tls "$SERVICE_DNS"; '
                        "exec /cache/verifier"],
                    "env": [
                        {"name": "GOPROXY", "value": "off"}, {"name": "GOSUMDB", "value": "off"},
                        {"name": "GOTOOLCHAIN", "value": "local"}, {"name": "GO111MODULE", "value": "off"},
                        {"name": "GOCACHE", "value": "/cache/go-build"}, {"name": "GOPATH", "value": "/cache/gopath"},
                        {"name": "TMPDIR", "value": "/cache/tmp"}, {"name": "HOME", "value": "/cache/home"},
                        {"name": "SERVICE_DNS", "value": SERVICE_DNS},
                    ],
                    "ports": [{"name": "https", "containerPort": 8443}],
                    "readinessProbe": {"httpGet": {"scheme": "HTTPS", "path": "/healthz", "port": "https"},
                                       "periodSeconds": 2, "failureThreshold": 30},
                    "resources": {"requests": {"cpu": "100m", "memory": "256Mi"},
                                  "limits": {"cpu": "1", "memory": "768Mi"}},
                    "volumeMounts": [
                        {"name": "source", "mountPath": "/src", "readOnly": True},
                        {"name": "cache", "mountPath": "/cache"},
                    ],
                    "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                        "capabilities": {"drop": ["ALL"]}},
                }],
            }},
        },
    }


def run(lab):
    crd = FIXTURES / "argo-workflowtemplates.yaml"
    license_file = FIXTURES / "ARGO-LICENSE.txt"
    if hashlib.sha256(crd.read_bytes()).hexdigest() != CRD_SHA256:
        lab.block("Pinned upstream Argo Workflows v3.7.6 CRD hash mismatch")
    if hashlib.sha256(license_file.read_bytes()).hexdigest() != LICENSE_SHA256:
        lab.block("Pinned upstream Argo license hash mismatch")
    lab.apply(crd)
    lab.kubectl("wait", "--for=condition=Established", "crd/workflowtemplates.argoproj.io",
                "--timeout=45s", timeout=55)
    lab.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NAMESPACE,
        "labels": {"saf.example.test/signature-enforcement": "required"}}})

    source = WEBHOOK + "-source"
    create(lab, {"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": source, "namespace": NAMESPACE}, "immutable": True,
                "data": {"webhook.go": (HERE / "webhook.go").read_text(),
                         "workflow-template.json": (FIXTURES / "workflow-template.json").read_text()}})
    create(lab, {"apiVersion": "v1", "kind": "Service",
                "metadata": {"name": WEBHOOK, "namespace": NAMESPACE},
                "spec": {"selector": {"app": WEBHOOK},
                         "ports": [{"name": "https", "port": 443, "targetPort": "https"}]}})
    create(lab, deployment(source))
    lab.kubectl("rollout", "status", f"deployment/{WEBHOOK}", "-n", NAMESPACE,
                "--timeout=170s", timeout=180)
    logs = lab.kubectl("logs", f"deployment/{WEBHOOK}", "-n", NAMESPACE)
    if f"service_dns_observed={SERVICE_DNS}" not in logs.stdout:
        lab.block("Verifier Pod did not resolve its Service DNS")

    def read_public_file(path):
        result = lab.kubectl("exec", f"deployment/{WEBHOOK}", "-n", NAMESPACE, "--", "cat", path)
        return result.stdout

    objects = json.loads(read_public_file("/cache/material/objects.json"))
    order = ("unsigned", "changed_trusted", "untrusted", "trusted")
    if set(objects) != {*order, "trusted_update"}:
        lab.block("Signer did not emit the five fixed public WorkflowTemplate inputs")
    name = objects["trusted"]["metadata"]["name"]

    off = {case: create(lab, objects[case], allow_failure=True, dry_run=True).returncode == 0
           for case in order}
    read_before = lab.kubectl("get", "workflowtemplate", name, "-n", NAMESPACE, "-o", "name",
                             "--ignore-not-found")
    clean_off = not read_before.stdout.strip()
    lab.check("red", "Before webhook registration the API admits all four fixed server dry-run requests",
              all(off.values()) and clean_off, {"admitted": off, "dry_runs_did_not_persist": clean_off})

    lab.create(webhook_configuration(read_public_file("/cache/tls/ca.crt")))

    # Wait for the API server to observe the new configuration using its exact decision.
    deadline = time.monotonic() + 20
    while not denied(lab, objects["unsigned"], EXPECTED["unsigned"], dry_run=True):
        if time.monotonic() >= deadline:
            lab.block("The API server did not return the expected signature webhook denial")
        time.sleep(0.4)

    on = {case: denied(lab, objects[case], EXPECTED[case], dry_run=True) for case in EXPECTED}
    trusted_dry_run = create(lab, objects["trusted"], allow_failure=True, dry_run=True).returncode == 0
    lab.check("green", "The webhook rejects the same unsigned, modified and untrusted requests",
              all(on.values()), {"denied_for_expected_reason": on})
    accepted = json.loads(create(lab, objects["trusted"]).stdout)

    def read_template():
        result = lab.kubectl("get", "workflowtemplate", name, "-n", NAMESPACE, "-o", "json")
        return json.loads(result.stdout)

    readback = read_template()
    signed_spec = objects["trusted"]["spec"]
    exact_readback = (accepted["metadata"]["name"] == readback["metadata"]["name"] == name
                      and accepted["metadata"]["namespace"] == readback["metadata"]["namespace"] == NAMESPACE
                      and accepted["spec"] == readback["spec"] == signed_spec)
    lab.check("positive", "The trusted WorkflowTemplate is admitted and its signed spec persists",
              trusted_dry_run and exact_readback,
              {"trusted_dry_run_admitted": trusted_dry_run, "readback_matches_signed_spec": exact_readback})

    rv = readback["metadata"]["resourceVersion"]

    def with_version(obj, version):
        return {**obj, "metadata": {**obj["metadata"], "resourceVersion": version}}

    changed = objects["changed_trusted"]
    outcome = replace(lab, with_version(changed, rv))
    update_denied = explicit_webhook_denial(outcome, EXPECTED["changed_trusted"])
    after_denial = read_template()
    unchanged = after_denial["metadata"]["resourceVersion"] == rv and after_denial["spec"] == signed_spec
    lab.check("green", "A stale signature rejects the changed template without modifying storage",
              update_denied and unchanged, {"stale_update_denied": update_denied, "stored_spec_unchanged": unchanged})

    trusted_update = objects["trusted_update"]
    update_result = replace(lab, with_version(trusted_update, rv))
    final = read_template()
    updated = (update_result.returncode == 0 and final["spec"] == changed["spec"] == trusted_update["spec"]
               and final["spec"] != signed_spec and final["metadata"]["resourceVersion"] != rv)
    lab.check("positive", "A fresh trusted signature permits the same spec change and the API stores it",
              updated, {"fresh_signature_admitted_spec_change": updated})
