"""Verify defensive isolation and automatic cleanup of two short-lived CI Jobs."""
from hashlib import sha256
from ipaddress import ip_address
import json
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PYTHON = ("docker.io/library/python:3.13-slim@sha256:"
          "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
NAME = "fixture-build-runner"
APPROVED = "runner-approved-input"
OTHER = "runner-other-input"
MARKER = "public fixture source bytes"
TTL = 1
SCOPE = (
    "Disposable Kind build Jobs with enforced Restricted Pod security, isolated scratch "
    "storage, narrow projected Kubernetes access and an owned network allowlist. "
    "The Jobs package a harmless input and retain only verdicts, then are removed by the "
    "TTL controller. External CI infrastructure, secret stores, host cleanup and signing "
    "boundaries require separate evidence."
)


def get(lab, *args):
    return json.loads(lab.kubectl("get", *args, "-o", "json").stdout)


def security():
    return {"seccompProfile": {"type": "RuntimeDefault"}, "runAsNonRoot": True,
            "runAsUser": 65532, "fsGroup": 65532}


def container(name, args):
    return {"name": name, "image": PYTHON, "command": args,
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}}}


def pod():
    worker = container("runner", ["python", "-B", "-c", "print('fixture')"])
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "runner-security-comparison"},
            "spec": {"restartPolicy": "Never", "securityContext": security(), "containers": [worker]}}


def expect_restricted(lab):
    comparison = pod()
    comparison["spec"]["containers"][0]["securityContext"] = {"privileged": True}
    before = lab.create(comparison, dry_run=True, allow_failure=True)
    lab.check("red", "The same privileged declaration is accepted by API dry-run before enforcement",
              before.returncode == 0, {"before_policy_accepted": before.returncode == 0})
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted",
                "pod-security.kubernetes.io/enforce-version=v1.36", "--overwrite")
    after = lab.create(comparison, dry_run=True, allow_failure=True)
    rejected = after.returncode != 0 and "violates PodSecurity" in after.stderr and "privileged" in after.stderr
    lab.check("green", "The live Restricted admission policy denies the privileged runner declaration",
              rejected, {"privileged_declaration_denied": rejected})


def feed(lab, kind):
    name = f"runner-feed-{kind}"
    script = ("from http.server import BaseHTTPRequestHandler, HTTPServer\n"
              "class Marker(BaseHTTPRequestHandler):\n"
              " def do_GET(self):\n"
              "  self.send_response(200); self.end_headers(); self.wfile.write(b'owned fixture feed')\n"
              "HTTPServer(('0.0.0.0', 8080), Marker).serve_forever()\n")
    http = container("marker", ["python", "-B", "-c", script])
    http["readinessProbe"] = {"tcpSocket": {"port": 8080}, "periodSeconds": 1}
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "labels": {"runner-fixture-feed": kind}},
                "spec": {"securityContext": security(), "automountServiceAccountToken": False,
                         "containers": [http]}})
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=50s", timeout=60)
    return "http://" + get(lab, "pod", name)["status"]["podIP"] + ":8080/marker"


def policy(lab, api):
    expected = {api}
    # The pre-NAT Service and the live post-NAT endpoints are both case-owned API paths.
    slices = get(lab, "-n", "default", "endpointslices", "-l", "kubernetes.io/service-name=kubernetes")["items"]
    expected.update(address for item in slices for endpoint in item["endpoints"] for address in endpoint["addresses"])
    allowed = [{"ipBlock": {"cidr": f"{address}/{ip_address(address).max_prefixlen}"}} for address in sorted(expected)]
    lab.create({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": NAME},
                "spec": {"podSelector": {"matchLabels": {"app": NAME}}, "policyTypes": ["Egress"], "egress": [
                    {"to": [{"podSelector": {"matchLabels": {"runner-fixture-feed": "approved"}}}],
                     "ports": [{"protocol": "TCP", "port": 8080}]},
                    {"to": allowed, "ports": [{"protocol": "TCP", "port": 443}, {"protocol": "TCP", "port": 6443}]},
                ]}})


def access(lab):
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": NAME},
                "automountServiceAccountToken": False})
    rbac = {"apiVersion": "rbac.authorization.k8s.io/v1", "metadata": {"name": NAME}}
    lab.create({**rbac, "kind": "Role", "rules": [
        {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [APPROVED], "verbs": ["get"]},
    ]})
    lab.create({**rbac, "kind": "RoleBinding",
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": NAME},
                "subjects": [{"kind": "ServiceAccount", "name": NAME, "namespace": "saf-test"}]})
    for name, value in ((APPROVED, MARKER), (OTHER, "other inert fixture value")):
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                    "immutable": True, "data": {"value": value}})


def job(lab, suffix):
    name = f"{NAME}-{suffix}"
    worker = container("runner", ["python", "-B", "/fixture/runner.py"])
    worker["resources"] = {"requests": {"cpu": "20m", "memory": "32Mi", "ephemeral-storage": "16Mi"},
                           "limits": {"cpu": "200m", "memory": "128Mi", "ephemeral-storage": "32Mi"}}
    worker["env"] = [{"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}}]
    worker["volumeMounts"] = [{"name": name, "mountPath": path, "readOnly": name != "work"}
                              for name, path in (("fixture", "/fixture"), ("identity", "/identity"), ("work", "/work"))]
    created = lab.create({
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 85,
                 "template": {"metadata": {"labels": {"app": NAME}}, "spec": {
                     "restartPolicy": "Never", "securityContext": security(), "serviceAccountName": NAME,
                     "automountServiceAccountToken": False, "containers": [worker],
                     "volumes": [{"name": "work", "emptyDir": {"sizeLimit": "8Mi"}},
                                 {"name": "fixture", "configMap": {"name": NAME}},
                                 {"name": "identity", "projected": {"sources": [
                                     {"serviceAccountToken": {"path": "token", "expirationSeconds": 600}},
                                     {"configMap": {"name": "kube-root-ca.crt",
                                                    "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
                                 ]}}],
                 }},
        },
    })
    deadline = time.monotonic() + 100
    while True:
        conditions = {item["type"] for item in get(lab, "job", name)["status"].get("conditions", [])
                      if item["status"] == "True"}
        if "Complete" in conditions:
            break
        if "Failed" in conditions or time.monotonic() >= deadline:
            lab.kubectl("logs", f"job/{name}", allow_failure=True)
            lab.kubectl("get", "events", "--sort-by=.metadata.creationTimestamp", allow_failure=True)
            lab.block(f"The owned Job {name} did not complete; inspect its retained log and events")
        time.sleep(0.4)
    receipt = json.loads(lab.kubectl("logs", f"job/{name}").stdout)
    runner, = get(lab, "pods", "-l", f"job-name={name}")["items"]
    same = receipt["own_pod_uid"] == runner["metadata"]["uid"]
    owned = created["metadata"]["uid"] in {ref["uid"] for ref in runner["metadata"]["ownerReferences"]}
    # Keep evidence available until the terminal result and ownership have been observed.
    lab.kubectl("patch", "job", name, "--type=merge",
                "--patch", json.dumps({"spec": {"ttlSecondsAfterFinished": TTL}}))
    lab.kubectl("wait", "--for=delete", f"job/{name}", f"pod/{runner['metadata']['name']}",
                "--timeout=40s", timeout=50)
    return {**receipt, "owned_runner_garbage_collected": same and owned}


def run(lab):
    expect_restricted(lab)
    access(lab)
    api = get(lab, "-n", "default", "service", "kubernetes")["spec"]["clusterIP"]
    feeds = {key: feed(lab, key) for key in ("approved", "other")}
    input_data = json.dumps({"api": api, "feeds": feeds, "approved_sha256": sha256(MARKER.encode()).hexdigest()})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME}, "immutable": True,
                "data": {"inputs.json": input_data, "runner.py": (HERE / "runner.py").read_text()}})
    baseline = job(lab, "baseline")
    both_feeds = baseline["feeds"] == {"approved": 200, "other": 200}
    lab.check("red", "Without the network policy the isolated comparison runner reaches both owned fixture feeds",
              both_feeds, {"before_network_policy_both_reachable": both_feeds})

    policy(lab, api)
    active = job(lab, "restricted")
    routed = active["feeds"] == {"approved": 200, "other": 0}
    authorized = active["scoped_approved_status"] == 200 and active["scoped_other_status"] == 403
    lab.check("green", "The restricted runner uses the approved feed and identity while other fixture access is denied",
              routed and authorized and active["usual_automatic_identity_mount_absent"],
              {"approved_feed_reached_and_other_denied": routed, "projected_identity_scoped": authorized,
               "default_identity_mount_absent": active["usual_automatic_identity_mount_absent"]})
    fresh = baseline["own_pod_uid"] != active["own_pod_uid"] and all(
        report["private_workspace_empty"] and report["owned_runner_garbage_collected"] for report in (baseline, active)
    )
    lab.check("positive", "A fresh runner packages the verified input after automatic removal of the previous runner",
              fresh and active["packaged_verified_input"], {"distinct_empty_workspace": fresh,
                                                             "verified_fixture_artifact_built": active["packaged_verified_input"]})
    (lab.evidence / "ephemeral-runner-observations.json").write_text(json.dumps({
        "before": baseline, "restricted": active, "ttl_seconds": TTL,
    }, indent=2, sort_keys=True) + "\n")
