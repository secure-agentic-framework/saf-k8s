"""Exercise federated orchestration identity and exact placement authorization."""
import importlib.util
import json
import tempfile
import time
from pathlib import Path

from fixtures import container

HERE = Path(__file__).resolve().parent
NS = "saf-test"
APPROVED = "fixture-orchestrator-approved"
ALTERNATE = "fixture-orchestrator-alternate"
GATEWAY = "fixture-orchestration-service"
BASELINE_GATEWAY = "fixture-orchestration-baseline"
ENFORCED_GATEWAY = "fixture-orchestration-enforced"
CODE = "fixture-orchestration-code"
TLS = "fixture-orchestration-tls"
WORKLOAD = "fixture-crosscluster-placement"
ALTERNATE_WORKLOAD = "fixture-crosscluster-other-placement"
POLICY = "fixture-exact-orchestration-placement"
POLICY_BINDING = "fixture-exact-orchestration-placement"
RBAC = "rbac.authorization.k8s.io/v1"
ADMISSION_REASON = "SAF-K8S-0910-016: placement is outside the approved fixture target"
DNS = "fixture-orchestration.saf.test"
ALLOWED_URI = f"spiffe://saf.test/ns/{NS}/sa/{APPROVED}"
OTHER_URI = f"spiffe://saf.test/ns/{NS}/sa/{ALTERNATE}"
SCOPE = (
    "Two distinct owned Kind APIs. A source-cluster orchestrator calls one private peer-cluster mTLS "
    "gateway. The gateway measures the certificate URI and gates one exact deployment placement; "
    "its separate Kubernetes service account is limited to Deployment CREATE in the target namespace, "
    "and target admission independently constrains the resource name and fixture labels. Baseline "
    "accepts a same-CA alternate URI; enforced mode refuses that identity and an alternate placement, "
    "then allows the approved request to persist on the peer API."
)


def row(kind, name, api="v1", **fields):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields}


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def certs(lab, temp):
    ca_key, ca_cert = temp / "fixture-ca.key", temp / "fixture-ca.crt"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=saf-0910-016-fixture-root", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash",
            "-keyout", str(ca_key),
                "-out", str(ca_cert), timeout=30)
    for name, purpose, san in (("server", "serverAuth", f"DNS:{DNS}"),
                               (APPROVED, "clientAuth", f"URI:{ALLOWED_URI}"),
                               (ALTERNATE, "clientAuth", f"URI:{OTHER_URI}")):
        key, csr, cert = (temp / f"{name}.{ext}" for ext in ("key", "csr", "crt"))
        ext = temp / f"{name}.ext"
        ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                       f"extendedKeyUsage={purpose}\nsubjectAltName={san}\n"
                       "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
        lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj",
                    f"/CN={name}", "-keyout", str(key), "-out", str(csr), timeout=30)
        lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert),
                    "-CAkey", str(ca_key), "-CAcreateserial", "-days", "1", "-sha256",
                    "-extfile", str(ext), "-out", str(cert), timeout=30)
    return {"ca": ca_cert, "server_cert": temp / "server.crt", "server_key": temp / "server.key",
            "approved_cert": temp / f"{APPROVED}.crt", "approved_key": temp / f"{APPROVED}.key",
            "alternate_cert": temp / f"{ALTERNATE}.crt", "alternate_key": temp / f"{ALTERNATE}.key"}


def create(kube, obj):
    return kube("create", "-f", "-", payload=json.dumps(obj))


def namespace_and_policy(peer):
    peer("label", "namespace", NS, "saf-fixture=0910-016", "--overwrite")
    create(peer, row("ServiceAccount", GATEWAY, automountServiceAccountToken=True))
    create(peer, row("Role", GATEWAY, RBAC, rules=[{
        "apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["create"],
    }]))
    create(peer, row("RoleBinding", GATEWAY, RBAC,
                     roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": GATEWAY},
                     subjects=[{"kind": "ServiceAccount", "name": GATEWAY, "namespace": NS}]))
    policy = row("ValidatingAdmissionPolicy", POLICY, "admissionregistration.k8s.io/v1", spec={
        "failurePolicy": "Fail",
        "matchConstraints": {"matchPolicy": "Equivalent", "namespaceSelector": {
            "matchLabels": {"saf-fixture": "0910-016"}}, "resourceRules": [{
                "apiGroups": ["apps"], "apiVersions": ["v1"], "operations": ["CREATE"],
                "resources": ["deployments"], "scope": "Namespaced",
            }]},
        "validations": [{"expression": (
            f"object.metadata.name == '{WORKLOAD}' && "
            "object.metadata.labels['saf-fixture'] == '0910-016' && "
            "object.spec.template.metadata.labels['saf-fixture'] == '0910-016' && "
            "object.spec.template.spec.automountServiceAccountToken == false"),
            "message": ADMISSION_REASON}],
    })
    create(peer, policy)
    create(peer, row("ValidatingAdmissionPolicyBinding", POLICY_BINDING,
                     "admissionregistration.k8s.io/v1", spec={
                         "policyName": POLICY, "validationActions": ["Deny"],
                         "matchResources": {"namespaceSelector": {"matchLabels": {"saf-fixture": "0910-016"}}},
                     }))


def peer_workloads(lab, peer, image, code, credentials):
    create(peer, row("ConfigMap", CODE, immutable=True,
                     data={"orchestration_fixture.py": code.read_text()}))
    create(peer, row("Secret", TLS, type="Opaque", stringData={
        "ca.crt": credentials["ca"].read_text(), "tls.crt": credentials["server_cert"].read_text(),
        "tls.key": credentials["server_key"].read_text(),
    }))
    nodeports = {}
    for name, mode in ((BASELINE_GATEWAY, "baseline"), (ENFORCED_GATEWAY, "enforced")):
        pod = row("Pod", name, metadata={"name": name, "namespace": NS, "labels": {"app": name}},
                  spec={"restartPolicy": "Always", "serviceAccountName": GATEWAY,
                        "securityContext": {"fsGroup": 65534}, "containers": [container(
                            "gateway", image=image, imagePullPolicy="Never",
                            command=["python", "/fixture/orchestration_fixture.py", "serve", mode],
                            ports=[{"containerPort": 8443}],
                            readinessProbe={"tcpSocket": {"port": 8443}, "periodSeconds": 1},
                            env=[{"name": "SAF_FIXTURE_IMAGE", "value": image}],
                            volumeMounts=[{"name": "code", "mountPath": "/fixture", "readOnly": True},
                                          {"name": "tls", "mountPath": "/tls", "readOnly": True}])],
                        "volumes": [{"name": "code", "configMap": {"name": CODE}},
                                    {"name": "tls", "secret": {"secretName": TLS, "defaultMode": 0o440}}]})
        create(peer, pod)
        service = row("Service", name, spec={"type": "NodePort", "selector": {"app": name},
                      "ports": [{"name": "mtls", "port": 8443, "targetPort": 8443}]})
        result = peer("create", "-f", "-", "-o", "json", payload=json.dumps(service))
        nodeports[mode] = json.loads(result.stdout)["spec"]["ports"][0]["nodePort"]
    return nodeports


def source_clients(lab, image, code, credentials):
    create(lab.kubectl, row("ConfigMap", CODE, immutable=True,
                            data={"orchestration_fixture.py": code.read_text()}))
    for name, cert_key in ((APPROVED, "approved"), (ALTERNATE, "alternate")):
        create(lab.kubectl, row("Secret", f"{name}-tls", type="Opaque", stringData={
            "ca.crt": credentials["ca"].read_text(), "tls.crt": credentials[f"{cert_key}_cert"].read_text(),
            "tls.key": credentials[f"{cert_key}_key"].read_text(),
        }))
        create(lab.kubectl, row("Pod", name, metadata={"name": name, "namespace": NS}, spec={
            "restartPolicy": "Always", "automountServiceAccountToken": False,
            "securityContext": {"fsGroup": 65534}, "containers": [container(
                "orchestrator", image=image, imagePullPolicy="Never", command=["sleep", "3600"],
                volumeMounts=[{"name": "code", "mountPath": "/fixture", "readOnly": True},
                              {"name": "tls", "mountPath": "/tls", "readOnly": True}])],
            "volumes": [{"name": "code", "configMap": {"name": CODE}},
                        {"name": "tls", "secret": {"secretName": f"{name}-tls", "defaultMode": 0o440}}],
        }))
    for name in (APPROVED, ALTERNATE):
        lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=90s", timeout=100)


def placement_object(name, image):
    labels = {"saf-fixture": "0910-016", "app": name}
    return row("Deployment", name, "apps/v1", metadata={"name": name, "namespace": NS,
                "labels": {"saf-fixture": "0910-016"}}, spec={
        "replicas": 1, "selector": {"matchLabels": labels},
        "template": {"metadata": {"labels": labels}, "spec": {
            "automountServiceAccountToken": False, "containers": [{
                "name": "fixture", "image": image, "imagePullPolicy": "Never",
                "command": ["python", "-c", "import time; time.sleep(3600)"],
            }],
        }},
    })


def probe(lab, pod, host, port, server_name, name):
    result = lab.kubectl("exec", pod, "--", "python", "/fixture/orchestration_fixture.py", "probe",
                         host, str(port), server_name, name, NS, timeout=20)
    try:
        return json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError):
        lab.block("Orchestration fixture returned no normalized decision")


def placement(peer, name):
    result = peer("get", "deployment", name, "-o", "json", allow_failure=True)
    if result.returncode:
        if "NotFound" in result.stderr:
            return None
        return {"read_error": True}
    obj = json.loads(result.stdout)
    return {"name": obj["metadata"]["name"], "namespace": obj["metadata"]["namespace"],
            "cluster_fingerprint": "peer", "fixture_label": obj["metadata"]["labels"].get("saf-fixture"),
            "service_account_token_automount": obj["spec"]["template"]["spec"].get("automountServiceAccountToken")}


def run(lab):
    runtime = load(HERE.parent / "SAF-K8S-0908-001" / "case.py", "saf_0910_016_runtime")
    peer_helper = load(HERE.parent / "SAF-K8S-0910-020" / "owned_peer.py", "saf_0910_016_peer")
    image = runtime.load_runtime(lab)
    with peer_helper.owned_peer(lab, image) as (peer, peer_address):
        peer_uid = peer("get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}").stdout.strip()
        source_uid = lab.kubectl("get", "namespace", "kube-system", "-o",
                                 "jsonpath={.metadata.uid}").stdout.strip()
        if not source_uid or not peer_uid or source_uid == peer_uid:
            lab.block("Cross-cluster placement requires distinct actual API servers")
        namespace_and_policy(peer)
        with tempfile.TemporaryDirectory(prefix="saf-0910-016-pki-") as temporary:
            credentials = certs(lab, Path(temporary))
            code = HERE / "orchestration_fixture.py"
            ports = peer_workloads(lab, peer, image, code, credentials)
            source_clients(lab, image, code, credentials)
            for name in (BASELINE_GATEWAY, ENFORCED_GATEWAY):
                peer("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=90s", timeout=100)

            for gateway, port in ports.items():
                deadline = time.monotonic() + 35
                while probe(lab, APPROVED, peer_address, port, DNS, "fixture-readiness") != {"ready": True}:
                    if time.monotonic() >= deadline:
                        lab.block(f"The {gateway} gateway did not verify its owned Kubernetes API route")
                    time.sleep(0.5)

            # Red control: trusted-chain authentication alone accepts the alternate URI and
            # creates the exact benign placement on the actual target API.
            baseline = probe(lab, ALTERNATE, peer_address, ports["baseline"], DNS, WORKLOAD)
            baseline_persisted = placement(peer, WORKLOAD)
            if baseline.get("status") == 201:
                peer("rollout", "status", "deployment/" + WORKLOAD, "--timeout=90s", timeout=100)
            red = {"same_ca_alternate_identity_received_created": baseline.get("status") == 201
                   and baseline.get("decision") == "created" and baseline.get("principal") == OTHER_URI,
                   "baseline_workload_persisted_on_peer_api": baseline_persisted == {
                       "name": WORKLOAD, "namespace": NS, "cluster_fingerprint": "peer",
                       "fixture_label": "0910-016", "service_account_token_automount": False}}
            if not all(red.values()):
                peer("logs", "pod/" + BASELINE_GATEWAY, allow_failure=True)
                peer("get", "events", "--sort-by=.metadata.creationTimestamp", allow_failure=True)
            lab.check("red", "Trusted-chain baseline accepts a same-CA alternate orchestration identity",
                      all(red.values()), {**red, "decision": baseline})
            peer("delete", "deployment", WORKLOAD, "--wait=true", "--timeout=30s", timeout=40)
            deadline = time.monotonic() + 20
            while placement(peer, WORKLOAD) is not None:
                if time.monotonic() >= deadline:
                    lab.block("Baseline placement did not clear before the enforced run")
                time.sleep(0.2)

            # GREEN: the gateway's measured URI must match the exact principal and placement.
            alternate = probe(lab, ALTERNATE, peer_address, ports["enforced"], DNS, WORKLOAD)
            action = probe(lab, APPROVED, peer_address, ports["enforced"], DNS, ALTERNATE_WORKLOAD)
            alternate_target = placement(peer, WORKLOAD)
            alternate_action_target = placement(peer, ALTERNATE_WORKLOAD)
            green = {
                "alternate_identity_refused_for_approved_placement": alternate == {
                    "status": 403, "decision": "refused", "reason": "identity-not-approved",
                    "principal": OTHER_URI},
                "approved_identity_refused_for_alternate_placement": action == {
                    "status": 403, "decision": "refused", "reason": "placement-not-approved",
                    "principal": ALLOWED_URI},
                "refused_identity_never_persisted_target": alternate_target is None,
                "refused_action_never_persisted_target": alternate_action_target is None,
            }
            # Independently exercise target-native admission using the gateway's Kubernetes
            # principal. The alternate-name request is otherwise authorized by its Role.
            native_attempt = peer(f"--as=system:serviceaccount:{NS}:{GATEWAY}", "create", "-f", "-",
                                  "--dry-run=server", "-o", "json", payload=json.dumps(placement_object(ALTERNATE_WORKLOAD, image)),
                                  allow_failure=True)
            native_absent = placement(peer, ALTERNATE_WORKLOAD) is None
            native_denied = (native_attempt.returncode != 0 and ADMISSION_REASON in native_attempt.stderr
                             and native_absent)
            green["target_admission_independently_refuses_alternate_name"] = native_denied
            lab.check("green", "Federated identity and exact placement policy refuse scoped alternatives",
                      all(green.values()), green)

            approved = probe(lab, APPROVED, peer_address, ports["enforced"], DNS, WORKLOAD)
            if approved.get("status") == 201:
                peer("rollout", "status", "deployment/" + WORKLOAD, "--timeout=90s", timeout=100)
            persisted = placement(peer, WORKLOAD)
            events = [json.loads(line) for name in (BASELINE_GATEWAY, ENFORCED_GATEWAY)
                      for line in peer("logs", "pod/" + name).stdout.splitlines() if line.startswith("{")]
            expected_event = {"event": "orchestration", "mode": "enforced", "principal": ALLOWED_URI,
                              "decision": "created", "target_cluster": "peer", "namespace": NS,
                              "name": WORKLOAD, "api_status": 201}
            positive = {
                "approved_request_reached_target_api": approved == {"status": 201, "decision": "created",
                                                                      "principal": ALLOWED_URI},
                "exact_deployment_persisted_on_peer_api": persisted == {
                    "name": WORKLOAD, "namespace": NS, "cluster_fingerprint": "peer",
                    "fixture_label": "0910-016", "service_account_token_automount": False},
                "peer_gateway_event_binds_identity_to_exact_target": expected_event in events,
                "native_admission_policy_persisted_and_deny_bound": (
                    json.loads(peer("get", "validatingadmissionpolicy", POLICY, "-o", "json").stdout)
                    ["metadata"]["name"] == POLICY and json.loads(peer(
                        "get", "validatingadmissionpolicybinding", POLICY_BINDING, "-o", "json").stdout
                    )["spec"]["validationActions"] == ["Deny"]),
            }
            lab.check("positive", "Approved federation action persists at its exact peer placement",
                      all(positive.values()), positive)
            evidence = {"case": "SAF-K8S-0910-016", "scope": "one-private-peer-api-one-placement",
                        "api_servers_distinct": True, "baseline": red, "enforced_refusals": green,
                        "approved_path": positive, "target_cluster_fingerprint": "peer",
                        "target_namespace": NS, "target_deployment": WORKLOAD,
                        "peer_events": [event for event in events if event.get("event") == "orchestration"]}
            (lab.evidence / "orchestration-identity-normalized.json").write_text(
                json.dumps(evidence, sort_keys=True, indent=2) + "\n")
            evidence["api_uids"] = {"source": source_uid, "peer": peer_uid}
            evidence["placement_uid"] = json.loads(
                peer("get", "deployment", WORKLOAD, "-o", "json").stdout)["metadata"]["uid"]
            (lab.evidence / "cross-cluster-orchestration-identity.json").write_text(
                json.dumps(evidence, sort_keys=True, indent=2) + "\n")
