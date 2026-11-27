"""Enforce the intended service-account selection for two isolated workload fixtures."""

import json
import tempfile
import time
from pathlib import Path

SCOPE = (
    "Disposable Kind v1.36.1 admission and verified Pod identity. Two in-cluster TLS "
    "services submit TokenReviews for their exact audience and require their exact "
    "fixture ServiceAccount subject before a scoped read of one inert ConfigMap. "
    "Provider trust, IAM, cloud auditing and node credential isolation are outside "
    "this local relying-service fixture."
)
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
POLICY = "fixture-workload-identities"
REASON = "Fixture workload must use its approved ServiceAccount"
WORKLOADS = {"fixture-workload-a": "fixture-identity-a", "fixture-workload-b": "fixture-identity-b"}
SAME_SUBJECT_PEER = "fixture-workload-a-peer"
AUDIENCE = "saf-fixture-external"
WRONG_AUDIENCE = "saf-fixture-unapproved"
TRUST = "fixture-identity-trust"
CLIENT_CODE = "fixture-identity-client"
SERVICE_CODE = "fixture-identity-relying"
TLS_SECRET = "fixture-identity-relying-tls"
REVIEWER = "fixture-identity-tokenreviewer"
RELIERS = {"workload-a": "fixture-identity-relying-a",
           "workload-b": "fixture-identity-relying-b"}
MARKERS = {"workload-a": "identity-marker-a", "workload-b": "identity-marker-b"}
EXPECTED_USERS = {"workload-a": f"system:serviceaccount:saf-test:{WORKLOADS['fixture-workload-a']}",
                  "workload-b": f"system:serviceaccount:saf-test:{WORKLOADS['fixture-workload-b']}"}
ROOT = Path(__file__).resolve().parent


def pod(name, subject):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name},
            "spec": {"restartPolicy": "Never", "serviceAccountName": subject, "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                     "volumes": [{"name": "fixture-projection", "projected": {"sources": [
                         {"serviceAccountToken": {"path": "token", "audience": AUDIENCE, "expirationSeconds": 600}},
                         {"serviceAccountToken": {"path": "wrong-audience-token", "audience": WRONG_AUDIENCE,
                                                   "expirationSeconds": 600}},
                         {"configMap": {"name": TRUST, "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
                         {"configMap": {"name": CLIENT_CODE, "items": [{"key": "client.py", "path": "client.py"}]}}
                     ]}}],
                     "containers": [{"name": "inert", "image": IMAGE, "command": ["python", "-c", "import time; time.sleep(180)"],
                                     "resources": {"requests": {"cpu": "5m", "memory": "12Mi"}, "limits": {"cpu": "100m", "memory": "40Mi"}},
                                     "volumeMounts": [{"name": "fixture-projection", "mountPath": "/identity", "readOnly": True}],
                                     "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                         "capabilities": {"drop": ["ALL"]}}}]}}


def install(lab):
    api = "admissionregistration.k8s.io/v1"
    choices = [f"(object.metadata.name == '{name}' && object.spec.serviceAccountName == '{subject}')"
               for name, subject in WORKLOADS.items()]
    choices.append(f"(object.metadata.name == '{SAME_SUBJECT_PEER}' && "
                   f"object.spec.serviceAccountName == '{WORKLOADS['fixture-workload-a']}')")
    choices.extend(f"(object.metadata.name == '{account}' && object.spec.serviceAccountName == '{account}')"
                   for account in RELIERS.values())
    predicate = " || ".join(choices)
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicy", "metadata": {"name": POLICY},
                "spec": {"failurePolicy": "Fail",
                         "matchConstraints": {"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                                "operations": ["CREATE"], "resources": ["pods"]}]},
                         "validations": [{"expression": predicate, "message": REASON}]}})
    lab.create({"apiVersion": api, "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": POLICY},
                "spec": {"policyName": POLICY, "validationActions": ["Deny"], "matchResources": {
                    "namespaceSelector": {"matchLabels": {"fixture.example/workload-identities": "true"}}}}})


def setup_relying(lab, temp):
    for marker in MARKERS.values():
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": marker},
                    "immutable": True, "data": {"marker": marker}})
    for account in RELIERS.values():
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": account}})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
                "metadata": {"name": REVIEWER},
                "rules": [{"apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"],
                           "verbs": ["create"]}]})
    lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
                "metadata": {"name": REVIEWER},
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": REVIEWER},
                "subjects": [{"kind": "ServiceAccount", "namespace": "saf-test", "name": account}
                             for account in RELIERS.values()]})
    for alias, account in RELIERS.items():
        marker = MARKERS[alias]
        role = account + "-marker-read"
        lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                    "metadata": {"name": role},
                    "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                               "resourceNames": [marker], "verbs": ["get"]}]})
        lab.create({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                    "metadata": {"name": role},
                    "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": role},
                    "subjects": [{"kind": "ServiceAccount", "namespace": "saf-test", "name": account}]})

    key, cert = temp / "relying.key", temp / "relying.crt"
    dns_names = ",".join(f"DNS:{name}.saf-test.svc" for name in RELIERS.values())
    lab.command("openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
                "-subj", "/CN=fixture-workload-relying", "-addext", "subjectAltName=" + dns_names,
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "subjectKeyIdentifier=hash",
                "-addext", "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
                "-keyout", str(key), "-out", str(cert))
    lab.kubectl("create", "secret", "tls", TLS_SECRET, "--key=" + str(key), "--cert=" + str(cert), "-o", "name")
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": TRUST},
                "immutable": True, "data": {"ca.crt": cert.read_text()}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CLIENT_CODE},
                "immutable": True, "data": {"client.py": (ROOT / "client.py").read_text()}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": SERVICE_CODE},
                "immutable": True, "data": {"relying.py": (ROOT / "relying.py").read_text()}})


def launch_reliers(lab, expected_pods):
    for alias, account in RELIERS.items():
        pod_name = account
        lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": pod_name, "labels": {"app": pod_name}},
                    "spec": {"restartPolicy": "Always", "serviceAccountName": account,
                             "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534,
                                                 "seccompProfile": {"type": "RuntimeDefault"}},
                             "containers": [{"name": "relying", "image": IMAGE, "command": [
                                 "python", "/fixture/relying.py", "serve",
                                 EXPECTED_USERS[alias],
                                 MARKERS[alias], alias,
                                 expected_pods[alias]["name"], expected_pods[alias]["uid"]],
                                 "ports": [{"containerPort": 8443}],
                                 "readinessProbe": {"tcpSocket": {"port": 8443}, "periodSeconds": 1},
                                 "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                                               "limits": {"cpu": "100m", "memory": "48Mi"}},
                                 "volumeMounts": [{"name": "code", "mountPath": "/fixture", "readOnly": True},
                                                  {"name": "tls", "mountPath": "/certificate", "readOnly": True}],
                                 "securityContext": {"allowPrivilegeEscalation": False,
                                                     "readOnlyRootFilesystem": True,
                                                     "capabilities": {"drop": ["ALL"]}}}],
                             "volumes": [{"name": "code", "configMap": {"name": SERVICE_CODE}},
                                         {"name": "tls", "secret": {"secretName": TLS_SECRET,
                                                                        "defaultMode": 0o440}}]}})
        lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": pod_name},
                    "spec": {"selector": {"app": pod_name}, "ports": [{"port": 8443, "targetPort": 8443}]}})
        lab.kubectl("wait", "--for=condition=Ready", f"pod/{pod_name}", "--timeout=50s", timeout=60)


def probe(lab, pod_name, host, token_path, marker):
    result = lab.kubectl("exec", pod_name, "--", "python", "/identity/client.py",
                         host, token_path, marker, timeout=20)
    return json.loads(result.stdout)


def live_pod_identity(lab, name):
    obj = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
    sources = obj["spec"]["volumes"][0]["projected"]["sources"]
    tokens = [source["serviceAccountToken"] for source in sources
              if "serviceAccountToken" in source]
    return {"name": obj["metadata"]["name"], "uid": obj["metadata"]["uid"],
            "service_account": obj["spec"]["serviceAccountName"],
            "audience": tokens[0]["audience"] if len(tokens) == 2 else None}


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted",
                "fixture.example/workload-identities=true")
    for subject in WORKLOADS.values():
        lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": subject},
                    "automountServiceAccountToken": False})
    with tempfile.TemporaryDirectory(prefix="saf-0704-019-relying-") as directory:
        setup_relying(lab, Path(directory))
    first, second = WORKLOADS
    incorrect = pod(first, WORKLOADS[second])
    admitted = lab.create(incorrect, dry_run=True)["spec"]["serviceAccountName"] == WORKLOADS[second]
    lab.check("red", "With no workload mapping rule, Kubernetes accepts the other fixture ServiceAccount",
              admitted, {"incorrect_subject_admitted": admitted})

    install(lab)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        denied = lab.create(incorrect, dry_run=True, allow_failure=True)
        if denied.returncode and REASON in denied.stderr:
            break
        time.sleep(0.45)
    else:
        lab.block("The fixture ServiceAccount mapping policy did not return the expected explicit denial")
    missing = lab.create(pod(second, "default"), dry_run=True, allow_failure=True)
    rejects_default = missing.returncode != 0 and REASON in missing.stderr
    lab.check("green", "Admission denies the other workload's ServiceAccount and a default-account declaration",
              rejects_default, {"incorrect_subject_denied": True, "default_subject_denied": rejects_default})

    approved = {}
    for name, subject in WORKLOADS.items():
        lab.create(pod(name, subject))
    for name, subject in WORKLOADS.items():
        lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=55s", timeout=65)
        spec = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)["spec"]
        approved[name] = (spec["serviceAccountName"] == subject
                          and spec["automountServiceAccountToken"] is False
                          and len(spec["volumes"]) == 1
                          and spec["volumes"][0]["projected"]["sources"][0]["serviceAccountToken"]["audience"] == AUDIENCE)
    lab.check("positive", "Both approved Pods run with different expected ServiceAccounts and the declared projection",
              all(approved.values()), {"approved_workload_specs": approved})
    lab.create(pod(SAME_SUBJECT_PEER, WORKLOADS["fixture-workload-a"]))
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{SAME_SUBJECT_PEER}",
                "--timeout=55s", timeout=65)
    expected_pods = {alias: live_pod_identity(lab, name)
                     for alias, name in (("workload-a", "fixture-workload-a"),
                                         ("workload-b", "fixture-workload-b"))}
    peer_identity = live_pod_identity(lab, SAME_SUBJECT_PEER)
    launch_reliers(lab, expected_pods)

    a = probe(lab, "fixture-workload-a", f"{RELIERS['workload-a']}.saf-test.svc",
              "token", MARKERS["workload-a"])
    b = probe(lab, "fixture-workload-b", f"{RELIERS['workload-b']}.saf-test.svc",
              "token", MARKERS["workload-b"])
    wrong_audience = probe(lab, "fixture-workload-a", f"{RELIERS['workload-a']}.saf-test.svc",
                           "wrong-audience-token", MARKERS["workload-a"])
    cross_subject = probe(lab, "fixture-workload-b", f"{RELIERS['workload-a']}.saf-test.svc",
                          "token", MARKERS["workload-a"])
    relying_ok = (a.get("http_status") == 200 and a.get("principal") == "workload-a"
                  and a.get("marker") == MARKERS["workload-a"]
                  and b.get("http_status") == 200 and b.get("principal") == "workload-b"
                  and b.get("marker") == MARKERS["workload-b"]
                  and wrong_audience.get("http_status") == 401
                  and wrong_audience.get("decision") == "unauthenticated"
                  and wrong_audience.get("marker") is None
                  and cross_subject.get("http_status") == 403
                  and cross_subject.get("decision") == "denied"
                  and cross_subject.get("marker") is None)
    lab.check("green", "Relying services verify projected subject and audience before scoped marker reads",
              relying_ok,
              {"workload_a_exact_subject_allowed": a.get("http_status") == 200 and a.get("marker") == MARKERS["workload-a"],
               "workload_b_exact_subject_allowed": b.get("http_status") == 200 and b.get("marker") == MARKERS["workload-b"],
               "wrong_audience_denied": wrong_audience.get("http_status") == 401,
               "cross_subject_denied_without_data": cross_subject.get("http_status") == 403
               and cross_subject.get("marker") is None})
    peer = probe(lab, SAME_SUBJECT_PEER, f"{RELIERS['workload-a']}.saf-test.svc",
                 "token", MARKERS["workload-a"])
    approved_token_origin = (
        a.get("pod_binding_matches") is True
        and a.get("token_pod_name") == expected_pods["workload-a"]["name"]
        and a.get("token_pod_uid") == expected_pods["workload-a"]["uid"]
        and b.get("pod_binding_matches") is True
        and b.get("token_pod_name") == expected_pods["workload-b"]["name"]
        and b.get("token_pod_uid") == expected_pods["workload-b"]["uid"])
    peer_same_subject_audience = (
        peer_identity["service_account"] == expected_pods["workload-a"]["service_account"]
        and peer_identity["audience"] == AUDIENCE
        and peer_identity["uid"] != expected_pods["workload-a"]["uid"])
    peer_token_origin = (peer.get("token_pod_name") == peer_identity["name"]
                         and peer.get("token_pod_uid") == peer_identity["uid"]
                         and peer.get("token_pod_uid") != expected_pods["workload-a"]["uid"])
    peer_denied_by_pod_binding = (
        peer.get("http_status") == 403 and peer.get("decision") == "denied"
        and peer.get("reason") == "pod-binding" and peer.get("authenticated") is True
        and peer.get("audience_valid") is True and peer.get("subject_valid") is True
        and peer.get("pod_binding_matches") is False and peer.get("marker") is None)
    lab.check("positive", "TokenReview Pod UID binds the approved caller; same-subject peer is refused",
              approved_token_origin and peer_same_subject_audience and peer_token_origin
              and peer_denied_by_pod_binding,
              {"approved_token_origin_matches_live_pods": approved_token_origin,
               "peer_has_same_service_account_and_audience": peer_same_subject_audience,
               "peer_tokenreview_matches_its_distinct_live_pod": peer_token_origin,
               "peer_refused_for_pod_binding_without_data": peer_denied_by_pod_binding})
    (lab.evidence / "identity-binding-observations.json").write_text(json.dumps(
        {"incorrect_subject_before_policy": admitted, "incorrect_subject_denied": True,
         "default_subject_denied": rejects_default, "approved_workload_specs": approved,
         "provider_federation_tested": False,
         "relying_service": {"workload_a": a, "workload_b": b,
                             "wrong_audience": wrong_audience, "cross_subject": cross_subject,
                             "same_subject_peer": peer},
         "pod_origin": {"expected_workloads": expected_pods,
                        "same_subject_peer": peer_identity,
                        "tokenreview_observations": {
                            "workload_a": {"pod_name": a.get("token_pod_name"),
                                           "pod_uid": a.get("token_pod_uid")},
                            "workload_b": {"pod_name": b.get("token_pod_name"),
                                           "pod_uid": b.get("token_pod_uid")},
                            "same_subject_peer": {"pod_name": peer.get("token_pod_name"),
                                                  "pod_uid": peer.get("token_pod_uid")}}}}, indent=2) + "\n")
