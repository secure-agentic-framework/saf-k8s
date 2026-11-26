"""Collect live Kubernetes audit events from two owned Kind sources."""
from datetime import datetime, timedelta
import base64
import ipaddress
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
import time
from urllib.parse import urlsplit
from uuid import UUID

from fixtures import BUSYBOX_IMAGE, container

HERE = Path(__file__).resolve().parent
SOURCE_POLICY = HERE.parent / "SAF-K8S-1001-004" / "case.py"
RUNTIME_CASE = HERE.parent / "SAF-K8S-0908-001" / "case.py"
NODE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
NS = "saf-test"
RBAC = "rbac.authorization.k8s.io/v1"
PLAN = "fixture-cross-cluster-placement"
WORKLOAD = "fixture-cross-cluster-workload"
WRITER = "fixture-orchestration-actor"
COLLECTOR = "fixture-audit-collector"
READER = "fixture-audit-reader"
OUTSIDER = "fixture-audit-unapproved"
RECORDS = "fixture-central-audit-records"
SOURCE_CODE = "fixture-audit-source-code"
DELIVERY_CODE = "fixture-audit-delivery-code"
TRUST = "fixture-audit-delivery-trust"
RECEIVER = "fixture-audit-delivery-receiver"
OBSERVER = "fixture-audit-delivery-observer"
SOURCE_ACTOR_POD = "fixture-audit-source-actor"
SOURCE_SENDER_POD = "fixture-audit-source-sender"
SERVER_NAME = "fixture-audit-collector.saf-test.svc"
SCOPE = (
    "One isolated collector cluster and two distinct, auditable disposable Kubernetes source clusters. "
    "Each source authenticates a harmless Deployment create and placement-marker patch with its scoped "
    "ServiceAccount, emits native Metadata audit records, and sends only the allowlisted records through "
    "case-local mTLS to an enrolled central receiver. The central immutable record is read under scoped "
    "RBAC after source removal. This does not establish production exporter, retry, clock, or retention behavior."
)
POLICY = """apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: [RequestReceived]
rules:
  - level: Metadata
    users: [system:serviceaccount:saf-test:fixture-orchestration-actor]
    verbs: [patch]
    namespaces: [saf-test]
    resources:
      - group: ""
        resources: [configmaps]
        resourceNames: [fixture-cross-cluster-placement]
  - level: Metadata
    users: [system:serviceaccount:saf-test:fixture-orchestration-actor]
    verbs: [create]
    namespaces: [saf-test]
    resources:
      - group: apps
        resources: [deployments]
  - level: None
"""


def configure(path, audit):
    spec = importlib.util.spec_from_file_location("saf_audit_kind_config", SOURCE_POLICY)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load the reviewed audit Kind configuration helper")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    policy = path / "policy.yaml"
    policy.write_text(POLICY)
    config = path / "kind.yaml"
    config.write_text(helper.kind_config(policy, audit))
    return config, audit / Path(helper.AUDIT_FILE).name


def principal(account):
    return f"system:serviceaccount:{NS}:{account}"


def identity(value):
    return str(UUID(value)) == value


def source_cli(lab, cluster, kubeconfig, *args, payload=None, timeout=17):
    return lab.command("kubectl", "--kubeconfig", str(kubeconfig), "--context", "kind-" + cluster,
                       "--namespace", NS, f"--request-timeout={timeout-5}s", *args,
                       payload=payload, timeout=timeout)


def body(kind, name, api="v1", **fields):
    return {"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields}


def account_rules(account, rules):
    return (
        body("ServiceAccount", account, automountServiceAccountToken=False),
        body("Role", account, RBAC, rules=rules),
        body("RoleBinding", account, RBAC,
             roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": account},
             subjects=[{"kind": "ServiceAccount", "name": account, "namespace": NS}]),
    )


def event_from_log(lab, location, uid, source):
    deadline = time.monotonic() + 12
    while True:
        if location.is_file():
            found = {}
            for line in location.read_text().splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ref = event.get("objectRef", {})
                user = event.get("user", {}).get("username")
                if (event.get("stage") != "ResponseComplete" or ref.get("namespace") != NS
                        or user != principal(WRITER)):
                    continue
                key = (event.get("verb"), ref.get("resource"), ref.get("name"))
                if key not in {
                    ("patch", "configmaps", PLAN),
                    ("create", "deployments", WORKLOAD),
                }:
                    continue
                found[key] = {
                    "source": source, "source_uid": uid, "audit_id": event["auditID"],
                    "timestamp": event["stageTimestamp"], "verb": event["verb"],
                    "resource": ref["resource"], "object": ref["name"],
                    "actor": user, "status": event["responseStatus"]["code"],
                }
            expected = {("patch", "configmaps", PLAN),
                        ("create", "deployments", WORKLOAD)}
            if set(found) == expected:
                return [found[key] for key in sorted(expected)]
        if time.monotonic() >= deadline:
            lab.block("The source audit backend did not emit both exact placement events")
        time.sleep(0.25)


def actor_pod(image, name):
    return body("Pod", name, spec={
        "restartPolicy": "Never", "serviceAccountName": WRITER,
        "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534},
        "containers": [container("actor", image=image, imagePullPolicy="Never",
                                  command=["sleep", "3600"],
                                  volumeMounts=[{"name": "code", "mountPath": "/fixture", "readOnly": True},
                                                {"name": "identity", "mountPath": "/identity", "readOnly": True}],
                                  securityContext={"allowPrivilegeEscalation": False,
                                                   "capabilities": {"drop": ["ALL"]},
                                                   "runAsNonRoot": True, "runAsUser": 65534,
                                                   "seccompProfile": {"type": "RuntimeDefault"}})],
        "volumes": [
            {"name": "code", "configMap": {"name": SOURCE_CODE, "defaultMode": 292}},
            {"name": "identity", "projected": {"defaultMode": 292, "sources": [
                {"serviceAccountToken": {"path": "token", "expirationSeconds": 600}},
                {"configMap": {"name": "kube-root-ca.crt",
                               "items": [{"key": "ca.crt", "path": "ca.crt"}]}}
            ]}},
        ],
    })


def event_sender_pod(name, image, events_name, credential_name):
    mounts = [
        {"name": "code", "mountPath": "/fixture", "readOnly": True},
        {"name": "trust", "mountPath": "/trust", "readOnly": True},
        {"name": "events", "mountPath": "/input", "readOnly": True},
        {"name": "credential", "mountPath": "/credential", "readOnly": True},
    ]
    return body("Pod", name, spec={
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534},
        "containers": [container("sender", image=image, imagePullPolicy="Never",
                                  command=["sleep", "3600"], volumeMounts=mounts,
                                  securityContext={"allowPrivilegeEscalation": False,
                                                   "capabilities": {"drop": ["ALL"]},
                                                   "runAsNonRoot": True, "runAsUser": 65534,
                                                   "seccompProfile": {"type": "RuntimeDefault"}})],
        "volumes": [
            {"name": "code", "configMap": {"name": DELIVERY_CODE, "defaultMode": 292}},
            {"name": "trust", "configMap": {"name": TRUST, "defaultMode": 292}},
            {"name": "events", "configMap": {"name": events_name, "defaultMode": 292}},
            {"name": "credential", "secret": {"secretName": credential_name,
                                                  "defaultMode": 288}},
        ],
    })


def collect(lab, stem, names, image):
    source = lab.cluster + "-src-" + stem
    root = lab.kubeconfig.parent / ("audit-source-" + stem)
    root.mkdir()
    audit = root / "audit"
    audit.mkdir()
    config, record_file = configure(root, audit)
    kubeconfig = root / "kubeconfig"
    names.append((source, kubeconfig))
    lab.command("kind", "create", "cluster", "--name", source, "--image", NODE, "--config", str(config),
                "--kubeconfig", str(kubeconfig), "--wait", "120s", timeout=200)
    lab.command("kind", "load", "docker-image", image, "--name", source, timeout=120)

    def call(*args, **kwargs):
        return source_cli(lab, source, kubeconfig, *args, **kwargs)

    endpoint = json.loads(call("config", "view", "--minify", "-o", "json").stdout)["clusters"][0]["cluster"]["server"]
    owned = lab.command("docker", "port", source + "-control-plane", "6443/tcp", timeout=15).stdout.strip()
    if not re.fullmatch(r"127\.0\.0\.1:\d+", owned) or urlsplit(endpoint).netloc != owned:
        lab.block("The nested Kubernetes context does not identify its expected owned loopback endpoint")
    uid = call("get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}").stdout.strip()
    if not identity(uid):
        lab.block("The source API did not provide an independently observed cluster UID")
    call("create", "namespace", NS)
    for resource in (body("ConfigMap", PLAN, data={"action": "pending"}),
                     *account_rules(WRITER, [{"apiGroups": [""], "resources": ["configmaps"],
                                              "verbs": ["get", "patch"], "resourceNames": [PLAN]},
                                            {"apiGroups": ["apps"], "resources": ["deployments"],
                                             "verbs": ["create"]},
                                            {"apiGroups": ["apps"], "resources": ["deployments"],
                                             "verbs": ["get"],
                                             "resourceNames": [WORKLOAD]}]),
                     body("ConfigMap", SOURCE_CODE, immutable=True,
                          data={"source_actor.py": (HERE / "source_actor.py").read_text()})):
        call("create", "-f", "-", payload=json.dumps(resource))
    actor_name = SOURCE_ACTOR_POD + "-" + stem
    call("create", "-f", "-", payload=json.dumps(actor_pod(image, actor_name)))
    call("wait", "--for=condition=Ready", f"pod/{actor_name}", "--timeout=45s", timeout=55)
    result = call("exec", actor_name, "--", "python", "/fixture/source_actor.py", stem, timeout=20)
    action = json.loads(result.stdout)
    if (action != {"source": stem, "marker_patch_status": 200, "placement_create_status": 201}):
        lab.block("The authenticated source actor did not complete the exact safe marker and Deployment operations")
    call("wait", "--for=condition=Available", f"deployment/{WORKLOAD}", "--timeout=65s", timeout=75)
    return {"source": stem, "cluster": source, "kubeconfig": str(kubeconfig), "cluster_uid": uid,
            "events": event_from_log(lab, record_file, uid, stem)}


def cleanup(lab, names):
    while names:
        cluster, kubeconfig = names[-1]
        lab.command("kind", "delete", "cluster", "--name", cluster, "--kubeconfig", str(kubeconfig),
                    timeout=75)
        names.pop()


def certificate_extensions(identity=None, dns=None, usage="clientAuth"):
    altname = f"subjectAltName=URI:{identity}" if identity else f"subjectAltName=DNS:{dns}"
    return ("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
            f"extendedKeyUsage={usage}\n{altname}\nsubjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid:always\n")


def create_pki(lab, root, sources, central_uid):
    ca_key, ca_cert = root / "ca.key", root / "ca.crt"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=saf-0910-017-audit-root",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash",
                "-keyout", str(ca_key), "-out", str(ca_cert), timeout=30)
    os.chmod(ca_key, 0o600)
    certs = {}
    identities = {"sources": {}, "observer_uri": f"spiffe://saf.test/cluster/{central_uid}/audit-observer"}
    identities_list = [("server", None, SERVER_NAME, "serverAuth")]
    for source in sources:
        uri = f"spiffe://saf.test/cluster/{source['cluster_uid']}/audit-exporter"
        identities["sources"][uri] = {"source": source["source"], "uid": source["cluster_uid"]}
        identities_list.append((f"source-{source['source']}", uri, None, "clientAuth"))
    identities_list.extend([
        ("unapproved", "spiffe://saf.test/cluster/unapproved/audit-exporter", None, "clientAuth"),
        ("observer", identities["observer_uri"], None, "clientAuth"),
    ])
    for name, uri, dns, usage in identities_list:
        key, csr, cert, ext = (root / f"{name}.{suffix}" for suffix in ("key", "csr", "crt", "ext"))
        ext.write_text(certificate_extensions(uri, dns, usage))
        os.chmod(ext, 0o600)
        subject = f"/CN=saf-0910-017-{name}"
        lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", subject,
                    "-keyout", str(key), "-out", str(csr), timeout=30)
        os.chmod(key, 0o600)
        lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey",
                    str(ca_key), "-CAcreateserial", "-days", "1", "-sha256", "-extfile", str(ext),
                    "-out", str(cert), timeout=30)
        os.chmod(cert, 0o600)
        certs[name] = {"cert": cert, "key": key}
    return ca_cert, certs, identities


def create_secret_file(root, name, files):
    manifest = {"apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": name, "namespace": NS}, "type": "Opaque",
                "data": {key: base64.b64encode(Path(path).read_bytes()).decode("ascii")
                         for key, path in files.items()}}
    path = root / f"{name}-secret.json"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(manifest, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
    os.chmod(path, 0o600)
    return path


def create_secret(lab, root, name, files, source=None, kubeconfig=None):
    manifest = create_secret_file(root, name, files)
    try:
        if source is None:
            lab.kubectl("create", "-f", str(manifest), "-o", "name")
        else:
            source_cli(lab, source, kubeconfig, "create", "-f", str(manifest), "-o", "name")
    finally:
        manifest.unlink(missing_ok=True)


def pod_security_container(name, image, command, mounts, ports=None, ready_port=None):
    value = container(name, image=image, imagePullPolicy="Never", command=command,
                      volumeMounts=mounts,
                      securityContext={"allowPrivilegeEscalation": False,
                                       "capabilities": {"drop": ["ALL"]},
                                       "runAsNonRoot": True, "runAsUser": 65534,
                                       "seccompProfile": {"type": "RuntimeDefault"}})
    if ports:
        value["ports"] = ports
    if ready_port:
        value["readinessProbe"] = {"tcpSocket": {"port": ready_port}, "periodSeconds": 1}
    return value


def receiver_pod(image):
    return body("Pod", RECEIVER, metadata={"name": RECEIVER, "labels": {"app": RECEIVER}}, spec={
        "restartPolicy": "Never", "serviceAccountName": COLLECTOR,
        "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534},
        "containers": [pod_security_container(
            "receiver", image, ["python", "/fixture/audit_delivery.py", "serve"],
            [{"name": "code", "mountPath": "/fixture", "readOnly": True},
             {"name": "trust", "mountPath": "/trust", "readOnly": True},
             {"name": "credential", "mountPath": "/credential", "readOnly": True},
             {"name": "hub-api", "mountPath": "/hub-api", "readOnly": True}],
            ports=[{"containerPort": 8443, "name": "mtls"}], ready_port=8443)],
        "volumes": [
            {"name": "code", "configMap": {"name": DELIVERY_CODE, "defaultMode": 292}},
            {"name": "trust", "configMap": {"name": TRUST, "defaultMode": 292}},
            {"name": "credential", "secret": {"secretName": RECEIVER, "defaultMode": 288}},
            {"name": "hub-api", "projected": {"defaultMode": 292, "sources": [
                {"serviceAccountToken": {"path": "token", "expirationSeconds": 600}},
                {"configMap": {"name": "kube-root-ca.crt",
                               "items": [{"key": "ca.crt", "path": "ca.crt"}]}}
            ]}},
        ],
    })


def observer_pod(image):
    return body("Pod", OBSERVER, spec={
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534},
        "containers": [pod_security_container(
            "observer", image, ["sleep", "3600"],
            [{"name": "code", "mountPath": "/fixture", "readOnly": True},
             {"name": "trust", "mountPath": "/trust", "readOnly": True},
             {"name": "credential", "mountPath": "/credential", "readOnly": True}])],
        "volumes": [
            {"name": "code", "configMap": {"name": DELIVERY_CODE, "defaultMode": 292}},
            {"name": "trust", "configMap": {"name": TRUST, "defaultMode": 292}},
            {"name": "credential", "secret": {"secretName": OBSERVER, "defaultMode": 288}},
        ],
    })


def node_bridge(lab, cluster):
    name = cluster + "-control-plane"
    output = lab.command("docker", "inspect", "--format",
                         '{{json (index .NetworkSettings.Networks "kind")}}', name, timeout=20).stdout
    network = json.loads(output)
    address = ipaddress.ip_address(network["IPAddress"])
    if not address.is_private or address.is_loopback or address.is_link_local:
        lab.block("A fixture Kubernetes node is not on the private owned Kind bridge")
    return network["NetworkID"], str(address)


def authenticated_delivery(lab, sources, image, central_uid, temp_root):
    ca_cert, certs, identities = create_pki(lab, temp_root, sources, central_uid)
    delivery_config = body("ConfigMap", DELIVERY_CODE, immutable=True, data={
        "audit_delivery.py": (HERE / "audit_delivery.py").read_text(),
        "identities.json": json.dumps(identities, sort_keys=True, separators=(",", ":")),
    })
    delivery_trust = body("ConfigMap", TRUST, immutable=True, data={"ca.crt": ca_cert.read_text()})
    for record in (delivery_config, delivery_trust):
        lab.create(record)
    create_secret(lab, temp_root, RECEIVER,
                  {"tls.crt": certs["server"]["cert"], "tls.key": certs["server"]["key"]})
    lab.create(receiver_pod(image))
    service = lab.create(body("Service", RECEIVER, spec={
        "type": "NodePort", "selector": {"app": RECEIVER},
        "ports": [{"name": "mtls", "port": 8443, "targetPort": 8443}],
    }))
    port = int(service["spec"]["ports"][0]["nodePort"])
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{RECEIVER}", "--timeout=65s", timeout=75)
    create_secret(lab, temp_root, OBSERVER,
                  {"tls.crt": certs["observer"]["cert"], "tls.key": certs["observer"]["key"]})
    lab.create(observer_pod(image))
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{OBSERVER}", "--timeout=45s", timeout=55)

    hub_network, hub_address = node_bridge(lab, lab.cluster)
    source_networks = [node_bridge(lab, source["cluster"]) for source in sources]
    if any(network != hub_network for network, _ in source_networks):
        lab.block("The case-owned hub and members do not share the private Kind network")
    if len({hub_address, *(address for _, address in source_networks)}) != 3:
        lab.block("The case-owned hub and members do not have distinct private node addresses")

    service_ip = service["spec"]["clusterIP"]
    service_port = int(service["spec"]["ports"][0]["port"])

    def observer_readback():
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            output = lab.kubectl("exec", OBSERVER, "--", "python", "/fixture/audit_delivery.py",
                                 "observe", service_ip, str(service_port), timeout=15, allow_failure=True)
            if output.returncode == 0:
                return json.loads(output.stdout)
            time.sleep(0.5)
        lab.block("The authorized audit observer could not reach the owned receiver Service")

    before_source_delivery = observer_readback()
    first_source_only = None
    send_results = []
    for source in sources:
        sender_name = SOURCE_SENDER_POD + "-" + source["source"]
        events_name = "fixture-audit-events-" + source["source"]
        source_call = lambda *args, _source=source, **kwargs: source_cli(
            lab, _source["cluster"], Path(_source["kubeconfig"]), *args, **kwargs)
        for record in (delivery_config, delivery_trust):
            source_call("create", "-f", "-", payload=json.dumps(record))
        source_call("create", "-f", "-", payload=json.dumps(body(
            "ConfigMap", events_name, immutable=True,
            data={"events.json": json.dumps(source["events"], sort_keys=True,
                                             separators=(",", ":"))})))
        name = f"spiffe://saf.test/cluster/{source['cluster_uid']}/audit-exporter"
        secret_files = {"tls.crt": certs[f"source-{source['source']}"]["cert"],
                        "tls.key": certs[f"source-{source['source']}"]["key"]}
        if source["source"] == "a":
            secret_files.update({"wrong.crt": certs["unapproved"]["cert"],
                                 "wrong.key": certs["unapproved"]["key"]})
        credential_name = "fixture-audit-client-" + source["source"]
        create_secret(lab, temp_root, credential_name, secret_files,
                      source=source["cluster"], kubeconfig=Path(source["kubeconfig"]))
        source_call("create", "-f", "-", payload=json.dumps(event_sender_pod(
            sender_name, image, events_name, credential_name)))
        source_call("wait", "--for=condition=Ready", f"pod/{sender_name}",
                    "--timeout=55s", timeout=65)
        result = source_call("exec", sender_name, "--", "python", "/fixture/audit_delivery.py",
                             "send", hub_address, str(port), timeout=15)
        send_results.append(json.loads(result.stdout))
        if source["source"] == "a":
            first_source_only = observer_readback()

    source_a = sources[0]
    rejected = source_cli(lab, source_a["cluster"], Path(source_a["kubeconfig"]),
                          "exec", SOURCE_SENDER_POD + "-a", "--", "python",
                          "/fixture/audit_delivery.py", "reject", hub_address, str(port), timeout=15)
    rejected_result = json.loads(rejected.stdout)
    observer_state = observer_readback()
    central_store_result = lab.kubectl("get", "configmap", RECORDS, "-o", "json", allow_failure=True)
    central_store = None
    if central_store_result.returncode == 0:
        central_store = json.loads(central_store_result.stdout)
    stored_events = (json.loads(central_store.get("data", {}).get("events.json", "null"))
                     if central_store else None)
    expected = []
    for source in sources:
        batch = json.dumps({"source_uid": source["cluster_uid"], "events": source["events"]},
                           sort_keys=True, separators=(",", ":")).encode()
        expected.append({"source": source["source"], "source_uid": source["cluster_uid"],
                         "event_count": len(source["events"]),
                         "audit_ids": sorted(event["audit_id"] for event in source["events"]),
                         "event_batch_sha256": __import__("hashlib").sha256(batch).hexdigest()})
    expected.sort(key=lambda row: row["source_uid"])
    state_match = observer_state.get("sources") == expected
    checks = {
        "two_distinct_member_identities_delivered_over_strict_mtls": (
            len(send_results) == 2 and all(result.get("status") == 202
                                           and result.get("accepted") is True
                                           and result.get("event_count") == 2
                                           for result in send_results)
            and [result.get("central_store_status") for result in send_results] == [None, 201]),
        "same_ca_unapproved_member_identity_refused": (
            rejected_result.get("status") == 403
            and rejected_result.get("decision") == "source-refused"),
        "observer_readback_matches_source_uid_event_ids_and_batch_digests": (
            observer_state.get("status") == 200 and state_match),
        "refused_delivery_created_no_extra_receiver_record": (
            len(observer_state.get("sources", [])) == 2),
        "hub_service_account_persisted_exact_immutable_central_batch": (
            central_store is not None and central_store.get("immutable") is True
            and stored_events == [event for source in sources for event in source["events"]]),
    }
    gap_checks = {
        "registered_but_undelivered_sources_reported": before_source_delivery == {
            "status": 200, "sources": [], "missing_sources": ["a", "b"]},
        "withheld_source_reported_after_first_delivery": first_source_only is not None
        and first_source_only.get("status") == 200 and first_source_only.get("missing_sources") == ["b"]
        and [entry["source"] for entry in first_source_only.get("sources", [])] == ["a"],
        "after_exact_delivery_missing_sources_clear": state_match and observer_state.get("missing_sources") == [],
    }
    return {"checks": checks, "gap_checks": gap_checks, "send_results": send_results,
            "unapproved_identity": rejected_result, "receiver_state": observer_state,
            "central_store": {"created": central_store is not None,
                              "immutable": central_store.get("immutable") is True if central_store else False,
                              "exact_events_match": stored_events == [
                                  event for source in sources for event in source["events"]]}}


def run(lab):
    names = []
    try:
        runtime_spec = importlib.util.spec_from_file_location("saf_audit_python_runtime", RUNTIME_CASE)
        if runtime_spec is None or runtime_spec.loader is None:
            lab.block("Could not load the reviewed pinned Python runtime helper")
        runtime = importlib.util.module_from_spec(runtime_spec)
        runtime_spec.loader.exec_module(runtime)
        image = runtime.load_runtime(lab)
        sources = [collect(lab, marker, names, image) for marker in ("a", "b")]
        events = [event for source in sources for event in source["events"]]
        central_uid = lab.kubectl("get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}").stdout.strip()
        locations = {source["cluster_uid"] for source in sources}
        exact_sources = len(locations) == 2 and identity(central_uid) and central_uid not in locations
        for resource in (*account_rules(COLLECTOR, [{"apiGroups": [""], "resources": ["configmaps"],
                                                    "verbs": ["create"]}]),
                         *account_rules(READER, [{"apiGroups": [""], "resources": ["configmaps"],
                                                 "resourceNames": [RECORDS], "verbs": ["get"]}]),
                         body("ServiceAccount", OUTSIDER, automountServiceAccountToken=False)):
            lab.create(resource)

        def retrieve(actor):
            return lab.kubectl("get", "configmap", RECORDS, "-o", "json",
                               f"--as={principal(actor)}", allow_failure=True)

        unforwarded = retrieve(READER)
        lab.check("red", "Both sources emit audit events while the central reader sees a collection gap",
                  exact_sources and unforwarded.returncode != 0 and "NotFound" in unforwarded.stderr,
                  {"source_events_observed": len(events), "distinct_sources_and_collector": exact_sources,
                   "central_record_not_found": "NotFound" in unforwarded.stderr})
        with tempfile.TemporaryDirectory(prefix="saf-0910-017-pki-", dir=lab.kubeconfig.parent) as temporary:
            temp_root = Path(temporary)
            os.chmod(temp_root, 0o700)
            delivery = authenticated_delivery(lab, sources, image, central_uid, temp_root)
            lab.check("delivery", "The hub accepts only enrolled source identities for actual placement audit events",
                      all(delivery["checks"].values()), delivery["checks"])
            lab.check("gap", "The scoped observer detects a withheld source and confirms complete delivery",
                      all(delivery["gap_checks"].values()), delivery["gap_checks"])

            result = retrieve(READER)
            receipt = json.loads(result.stdout)
            returned = json.loads(receipt["data"]["events.json"])
            unauthorized = retrieve(OUTSIDER)
            event_ids = {e["audit_id"] for e in returned}
            valid_utc = all(datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")).utcoffset()
                            == timedelta(0) for e in returned)
            expected_actions = {
                ("patch", "configmaps", PLAN, 200),
                ("create", "deployments", WORKLOAD, 201),
            }
            green = {
                "allowlisted_real_audit_records_roundtrip": returned == events and receipt["immutable"] is True,
                "unique_source_and_event_identity": exact_sources and len(event_ids) == 4
                and all(identity(v) for v in event_ids)
                and len({row["source_uid"] for row in returned}) == 2,
                "authenticated_actor_action_and_timestamp_verified": valid_utc and all(
                    row["actor"] == principal(WRITER) and
                    (row["verb"], row["resource"], row["object"], row["status"]) in expected_actions
                    for row in returned)
                    and {source["source"]: {(row["verb"], row["resource"], row["object"], row["status"])
                                         for row in returned if row["source"] == source["source"]}
                        for source in sources} == {source["source"]: expected_actions for source in sources},
                "unauthorized_identity_denied_central_read": unauthorized.returncode != 0
                and "Forbidden" in unauthorized.stderr,
            }
            lab.check("green", "The collector preserves authenticated workload-placement provenance and reader scope",
                      all(green.values()), green)
            cleanup(lab, names)
            after_sources = retrieve(READER)
            retained = json.loads(json.loads(after_sources.stdout)["data"]["events.json"])
            positive = {"both_source_clusters_removed": not names, "central_copy_matches": retained == events}
            lab.check("positive", "Independent central storage stays readable after both source clusters are removed",
                      all(positive.values()), positive)
            (lab.evidence / "cross-cluster-audit.json").write_text(json.dumps({
                "central_api_uid": central_uid, "retained_events": retained,
                "delivery": delivery, "checks": {**green, **positive},
            }, sort_keys=True, indent=2) + "\n")
    finally:
        cleanup(lab, names)
