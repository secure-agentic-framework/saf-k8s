"""Exercise federated orchestration identity and exact placement authorization."""
import importlib.util
import hashlib
import json
import os
import ssl
import tempfile
import time
from pathlib import Path

from fixtures import container

HERE = Path(__file__).resolve().parent
NS = "saf-test"
APPROVED = "fixture-orchestrator-approved"
APPROVED_SUCCESSOR = "fixture-orchestrator-successor"
APPROVED_RETIRED = "fixture-orchestrator-retired-leaf"
ALTERNATE = "fixture-orchestrator-alternate"
GATEWAY = "fixture-orchestration-service"
BASELINE_GATEWAY = "fixture-orchestration-baseline"
ENFORCED_GATEWAY = "fixture-orchestration-enforced"
ROTATION_GATEWAY = "fixture-orchestration-rotation"
ROTATION_SERVICE = "fixture-orchestration-rotation"
ROTATION_TLS = "fixture-orchestration-rotation-tls"
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
    "then allows the approved request to persist on the peer API. A separate rotation stage uses "
    "fixture-only old-only, overlap, and successor-only client trust bundles."
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
                "-addext", "subjectAltName=URI:spiffe://saf.test/",
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
    successor_ca_key = temp / "fixture-successor-ca.key"
    successor_ca_cert = temp / "fixture-successor-ca.crt"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=saf-0910-016-fixture-successor-root",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash",
                "-addext", "subjectAltName=URI:spiffe://saf.test/",
                "-keyout", str(successor_ca_key), "-out", str(successor_ca_cert), timeout=30)
    successor_key = temp / f"{APPROVED_SUCCESSOR}.key"
    successor_csr = temp / f"{APPROVED_SUCCESSOR}.csr"
    successor_cert = temp / f"{APPROVED_SUCCESSOR}.crt"
    successor_ext = temp / f"{APPROVED_SUCCESSOR}.ext"
    successor_ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                             "extendedKeyUsage=clientAuth\n"
                             f"subjectAltName=URI:{ALLOWED_URI}\n"
                             "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
    lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj",
                f"/CN={APPROVED_SUCCESSOR}", "-keyout", str(successor_key),
                "-out", str(successor_csr), timeout=30)
    lab.command("openssl", "x509", "-req", "-in", str(successor_csr),
                "-CA", str(successor_ca_cert), "-CAkey", str(successor_ca_key),
                "-CAcreateserial", "-days", "1", "-sha256", "-extfile", str(successor_ext),
                "-out", str(successor_cert), timeout=30)
    return {"ca": ca_cert, "server_cert": temp / "server.crt", "server_key": temp / "server.key",
            "approved_cert": temp / f"{APPROVED}.crt", "approved_key": temp / f"{APPROVED}.key",
            "alternate_cert": temp / f"{ALTERNATE}.crt", "alternate_key": temp / f"{ALTERNATE}.key",
            "successor_ca": successor_ca_cert, "successor_cert": successor_cert,
            "successor_key": successor_key}


def create(kube, obj):
    return kube("create", "-f", "-", payload=json.dumps(obj))


def secret_file_command(kube, args, payload, directory):
    """Pass private Secret JSON by protected file path, never logged stdin."""
    descriptor, path = tempfile.mkstemp(prefix="saf-0910-016-secret-", suffix=".json",
                                        dir=directory)
    secret_path = Path(path)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(json.dumps(payload))
            stream.flush()
            os.fsync(stream.fileno())
        # The command logger sees only the path and metadata-only kubectl output.
        kube(*args, str(secret_path), "-o", "name")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        secret_path.unlink(missing_ok=True)


def create_secret_file(kube, obj, directory):
    """Create a fixture Secret without sending its private bytes to commands.log."""
    secret_file_command(kube, ["create", "-f"], obj, directory)


def patch_secret_file(kube, name, string_data, directory):
    patch = {"stringData": string_data}
    secret_file_command(kube, ["patch", "secret", name, "--type=merge", "--patch-file"],
                        patch, directory)


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


def peer_workloads(lab, peer, image, code, credentials, secret_directory):
    create(peer, row("ConfigMap", CODE, immutable=True,
                     data={"orchestration_fixture.py": code.read_text()}))
    create_secret_file(peer, row("Secret", TLS, type="Opaque", stringData={
        "ca.crt": credentials["ca"].read_text(), "client-ca.crt": credentials["ca"].read_text(),
        "tls.crt": credentials["server_cert"].read_text(),
        "tls.key": credentials["server_key"].read_text(),
    }), secret_directory)
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


def source_clients(lab, image, code, credentials, secret_directory):
    create(lab.kubectl, row("ConfigMap", CODE, immutable=True,
                            data={"orchestration_fixture.py": code.read_text()}))
    for name, cert_key in ((APPROVED, "approved"), (ALTERNATE, "alternate"),
                           (APPROVED_SUCCESSOR, "successor"), (APPROVED_RETIRED, "approved")):
        create_secret_file(lab.kubectl, row("Secret", f"{name}-tls", type="Opaque", stringData={
            "ca.crt": credentials["ca"].read_text(), "tls.crt": credentials[f"{cert_key}_cert"].read_text(),
            "tls.key": credentials[f"{cert_key}_key"].read_text(),
        }), secret_directory)
        create(lab.kubectl, client_pod(name, image))
    for name in (APPROVED, ALTERNATE, APPROVED_SUCCESSOR, APPROVED_RETIRED):
        lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=90s", timeout=100)


def client_pod(name, image):
    return row("Pod", name, metadata={"name": name, "namespace": NS}, spec={
        "restartPolicy": "Always", "automountServiceAccountToken": False,
        "securityContext": {"fsGroup": 65534}, "containers": [container(
            "orchestrator", image=image, imagePullPolicy="Never", command=["sleep", "3600"],
            volumeMounts=[{"name": "code", "mountPath": "/fixture", "readOnly": True},
                          {"name": "tls", "mountPath": "/tls", "readOnly": True}])],
        "volumes": [{"name": "code", "configMap": {"name": CODE}},
                    {"name": "tls", "secret": {"secretName": f"{name}-tls", "defaultMode": 0o440}}],
    })


def rotation_secret(credentials, bundle):
    return row("Secret", ROTATION_TLS, type="Opaque", stringData={
        # ca.crt validates the unchanged gateway server leaf from source clients.
        # client-ca.crt is the member's staged trust bundle for requesters.
        "ca.crt": credentials["ca"].read_text(),
        "client-ca.crt": bundle,
        "tls.crt": credentials["server_cert"].read_text(),
        "tls.key": credentials["server_key"].read_text(),
    })


def rotation_gateway_pod(image):
    return row("Pod", ROTATION_GATEWAY, metadata={"name": ROTATION_GATEWAY, "namespace": NS,
               "labels": {"app": ROTATION_GATEWAY}},
               spec={"restartPolicy": "Always", "terminationGracePeriodSeconds": 5,
                     "serviceAccountName": GATEWAY,
                     "securityContext": {"fsGroup": 65534}, "containers": [container(
                         "gateway", image=image, imagePullPolicy="Never",
                         command=["python", "/fixture/orchestration_fixture.py", "serve", "rotation"],
                         ports=[{"containerPort": 8443}],
                         readinessProbe={"tcpSocket": {"port": 8443}, "periodSeconds": 1},
                         env=[{"name": "SAF_FIXTURE_IMAGE", "value": image}],
                         volumeMounts=[{"name": "code", "mountPath": "/fixture", "readOnly": True},
                                       {"name": "tls", "mountPath": "/tls", "readOnly": True}])],
                     "volumes": [{"name": "code", "configMap": {"name": CODE}},
                                 {"name": "tls", "secret": {"secretName": ROTATION_TLS,
                                                                "defaultMode": 0o440}}]})


def start_rotation_gateway(peer, image, credentials, secret_directory):
    create_secret_file(peer, rotation_secret(credentials, credentials["ca"].read_text()),
                       secret_directory)
    create(peer, rotation_gateway_pod(image))
    service = row("Service", ROTATION_SERVICE,
                  spec={"type": "NodePort", "selector": {"app": ROTATION_GATEWAY},
                        "ports": [{"name": "mtls", "port": 8443, "targetPort": 8443}]})
    result = peer("create", "-f", "-", "-o", "json", payload=json.dumps(service))
    peer("wait", "--for=condition=Ready", f"pod/{ROTATION_GATEWAY}", "--timeout=90s", timeout=100)
    return json.loads(result.stdout)["spec"]["ports"][0]["nodePort"]


def replace_rotation_bundle(peer, image, credentials, secret_directory, bundle):
    patch_secret_file(peer, ROTATION_TLS, {"client-ca.crt": bundle}, secret_directory)
    peer("delete", "pod", ROTATION_GATEWAY, "--wait=true", "--timeout=60s", timeout=70)
    create(peer, rotation_gateway_pod(image))
    peer("wait", "--for=condition=Ready", f"pod/{ROTATION_GATEWAY}", "--timeout=90s", timeout=100)


def rotate_approved_requester(lab, image, credentials, secret_directory):
    before_uid = lab.kubectl("get", "pod", APPROVED, "-o", "jsonpath={.metadata.uid}").stdout.strip()
    patch_secret_file(lab.kubectl, f"{APPROVED}-tls", {
        "tls.crt": credentials["successor_cert"].read_text(),
        "tls.key": credentials["successor_key"].read_text(),
    }, secret_directory)
    lab.kubectl("delete", "pod", APPROVED, "--wait=true", "--timeout=60s", timeout=70)
    create(lab.kubectl, client_pod(APPROVED, image))
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{APPROVED}", "--timeout=90s", timeout=100)
    after_uid = lab.kubectl("get", "pod", APPROVED, "-o", "jsonpath={.metadata.uid}").stdout.strip()
    return bool(before_uid and after_uid and before_uid != after_uid)


def route_ready(lab, identity_pod, peer_address, port):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if probe(lab, identity_pod, peer_address, port, DNS, "fixture-readiness") == {"ready": True}:
            return True
        time.sleep(0.5)
    return False


def rotation_request(peer, lab, identity_pod, peer_address, port):
    response = probe(lab, identity_pod, peer_address, port, DNS, WORKLOAD)
    current = placement(peer, WORKLOAD)
    accepted = response == {"status": 201, "decision": "created", "principal": ALLOWED_URI} and current == {
        "name": WORKLOAD, "namespace": NS, "cluster_fingerprint": "peer",
        "fixture_label": "0910-016", "service_account_token_automount": False}
    if accepted:
        peer("rollout", "status", "deployment/" + WORKLOAD, "--timeout=90s", timeout=100)
        peer("delete", "deployment", WORKLOAD, "--wait=true", "--timeout=30s", timeout=40)
        deadline = time.monotonic() + 20
        while placement(peer, WORKLOAD) is not None and time.monotonic() < deadline:
            time.sleep(0.2)
        accepted = placement(peer, WORKLOAD) is None
    return accepted, response


def current_rotation_events(peer):
    records = [json.loads(line) for line in peer(
        "logs", "pod/" + ROTATION_GATEWAY).stdout.splitlines() if line.startswith("{")]
    return [event for event in records if event.get("event") == "orchestration"]


def rotation_stage(lab, peer, image, peer_address, credentials, secret_directory):
    port = start_rotation_gateway(peer, image, credentials, secret_directory)
    old_pem = credentials["ca"].read_text()
    successor_pem = credentials["successor_ca"].read_text()

    old_route_ready = route_ready(lab, APPROVED, peer_address, port)
    old_current_ok, old_response = rotation_request(peer, lab, APPROVED, peer_address, port)
    successor_old_denied = probe(lab, APPROVED_SUCCESSOR, peer_address, port, DNS, WORKLOAD)
    successor_old_absent = placement(peer, WORKLOAD) is None
    old_events = current_rotation_events(peer)

    replace_rotation_bundle(peer, image, credentials, secret_directory, old_pem + successor_pem)
    overlap_old_ready = route_ready(lab, APPROVED, peer_address, port)
    overlap_successor_ready = route_ready(lab, APPROVED_SUCCESSOR, peer_address, port)
    overlap_old_ok, overlap_old_response = rotation_request(peer, lab, APPROVED, peer_address, port)
    overlap_successor_ok, overlap_successor_response = rotation_request(
        peer, lab, APPROVED_SUCCESSOR, peer_address, port)

    overlap_events = current_rotation_events(peer)
    replace_rotation_bundle(peer, image, credentials, secret_directory, successor_pem)
    requester_recreated = rotate_approved_requester(lab, image, credentials, secret_directory)
    successor_route_ready = route_ready(lab, APPROVED_SUCCESSOR, peer_address, port)
    old_new_denied = probe(lab, APPROVED_RETIRED, peer_address, port, DNS, WORKLOAD)
    old_new_absent = placement(peer, WORKLOAD) is None
    successor_new_ok, successor_new_response = rotation_request(peer, lab, APPROVED, peer_address, port)
    current_leaf_der = ssl.PEM_cert_to_DER_cert(credentials["approved_cert"].read_text())
    successor_leaf_der = ssl.PEM_cert_to_DER_cert(credentials["successor_cert"].read_text())
    successor_events = current_rotation_events(peer)
    event_groups = (old_events, overlap_events, successor_events)
    event_binding = ([len(events) for events in event_groups] == [1, 2, 1] and all(
        event == {"event": "orchestration", "mode": "rotation", "principal": ALLOWED_URI,
                  "decision": "created", "target_cluster": "peer", "namespace": NS,
                  "name": WORKLOAD, "api_status": 201,
                  "peer_certificate_authenticated": True, "tls_version_is_1_3": True}
        for events in event_groups for event in events))

    observed = {
        "old_only_bundle_allows_current_leaf": old_route_ready and old_current_ok
        and old_response.get("principal") == ALLOWED_URI,
        "old_only_bundle_refuses_successor_before_http": successor_old_denied == {
            "status": 0, "decision": "peer-untrusted-certificate"} and successor_old_absent,
        "overlap_bundle_allows_old_and_successor": overlap_old_ready and overlap_successor_ready
        and overlap_old_ok and overlap_successor_ok
        and overlap_old_response.get("principal") == ALLOWED_URI
        and overlap_successor_response.get("principal") == ALLOWED_URI,
        "successor_only_bundle_refuses_retired_leaf_before_http": successor_route_ready
        and old_new_denied == {"status": 0, "decision": "peer-untrusted-certificate"} and old_new_absent,
        "successor_only_bundle_allows_exact_approved_action": successor_new_ok
        and successor_new_response.get("principal") == ALLOWED_URI,
        "same_requester_pod_restarted_with_distinct_successor_leaf": hashlib.sha256(current_leaf_der).digest()
        != hashlib.sha256(successor_leaf_der).digest() and requester_recreated,
        "successor_retains_exact_approved_spiiffe_uri": successor_new_response.get("principal") == ALLOWED_URI,
        "accepted_rotation_events_bind_mtls_identity_and_exact_peer_action": event_binding,
    }
    lab.check("rotation", "Peer trust rollover accepts overlap then retires the old requester leaf",
              all(observed.values()), observed)
    peer("delete", "service", ROTATION_SERVICE, "--ignore-not-found=true", timeout=25)
    peer("delete", "pod", ROTATION_GATEWAY, "--ignore-not-found=true", "--wait=true", timeout=35)
    peer("delete", "secret", ROTATION_TLS, "--ignore-not-found=true", timeout=25)
    lab.kubectl("delete", "pod", APPROVED_SUCCESSOR, APPROVED_RETIRED,
                 "--ignore-not-found=true", "--wait=true", timeout=35)
    lab.kubectl("delete", "secret", f"{APPROVED_SUCCESSOR}-tls", f"{APPROVED_RETIRED}-tls",
                 "--ignore-not-found=true", timeout=25)
    return observed


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
    def case_path(case_id):
        for parent in (HERE, *HERE.parents):
            candidates = (parent / "saf-k8s-control-lab" / "cases" / case_id / "case.py",
                          parent / "cases" / case_id / "case.py",
                          parent / case_id / "case.py")
            for candidate in candidates:
                if candidate.is_file():
                    return candidate
        lab.block(f"Could not locate the pinned local helper case {case_id}")

    runtime = load(case_path("SAF-K8S-0908-001"), "saf_0910_016_runtime")
    peer_helper = load(HERE / "owned_peer.py", "saf_0910_016_peer")
    spire = load(HERE / "spire_integration.py", "saf_0910_016_spire")
    image = runtime.load_runtime(lab)
    with peer_helper.owned_peer(lab, image) as (peer, peer_address, peer_info):
        kubelet_csrs = spire.prepare_kubelets(lab, peer_info)
        peer_uid = peer("get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}").stdout.strip()
        source_uid = lab.kubectl("get", "namespace", "kube-system", "-o",
                                 "jsonpath={.metadata.uid}").stdout.strip()
        if not source_uid or not peer_uid or source_uid == peer_uid:
            lab.block("Cross-cluster placement requires distinct actual API servers")
        namespace_and_policy(peer)
        with tempfile.TemporaryDirectory(prefix="saf-0910-016-pki-") as temporary:
            credentials = certs(lab, Path(temporary))
            code = HERE / "orchestration_fixture.py"
            ports = peer_workloads(lab, peer, image, code, credentials, Path(temporary))
            source_clients(lab, image, code, credentials, Path(temporary))
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
                              "name": WORKLOAD, "api_status": 201,
                              "peer_certificate_authenticated": True,
                              "tls_version_is_1_3": True}
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
            positive_placement_uid = json.loads(
                peer("get", "deployment", WORKLOAD, "-o", "json").stdout)["metadata"]["uid"]
            peer("delete", "deployment", WORKLOAD, "--wait=true", "--timeout=30s", timeout=40)
            deadline = time.monotonic() + 20
            while placement(peer, WORKLOAD) is not None and time.monotonic() < deadline:
                time.sleep(0.2)
            if placement(peer, WORKLOAD) is not None:
                lab.block("Approved baseline placement did not clear before certificate rollover")
            rotation = rotation_stage(lab, peer, image, peer_address, credentials, Path(temporary))
            evidence = {"case": "SAF-K8S-0910-016", "scope": "one-private-peer-api-one-placement",
                        "api_servers_distinct": True, "baseline": red, "enforced_refusals": green,
                        "approved_path": positive, "identity_rotation": rotation,
                        "target_cluster_fingerprint": "peer",
                        "target_namespace": NS, "target_deployment": WORKLOAD,
                        "peer_events": [event for event in events if event.get("event") == "orchestration"]}
            (lab.evidence / "orchestration-identity-normalized.json").write_text(
                json.dumps(evidence, sort_keys=True, indent=2) + "\n")
            evidence["api_uids"] = {"source": source_uid, "peer": peer_uid}
            evidence["placement_uid"] = positive_placement_uid
            (lab.evidence / "cross-cluster-orchestration-identity.json").write_text(
                json.dumps(evidence, sort_keys=True, indent=2) + "\n")
            # Add the actual SPIRE issuer/federation path after preserving the
            # certificate-backed baseline and rollover receipts above.
            spire_observation = spire.run(lab, peer, peer_address, peer_info, image, image, kubelet_csrs)
            (lab.evidence / "spire-federated-orchestration-normalized.json").write_text(
                json.dumps(spire_observation, sort_keys=True, indent=2) + "\n")
