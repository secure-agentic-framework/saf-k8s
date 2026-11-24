"""Live two-cluster registry replication channel test; run only via the SAF harness."""
import importlib.util
import json
from pathlib import Path
import time

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
NS = "saf-test"
CODE = "fixture-replication-code"
TRUST = "fixture-replication-trust"
DEST = "fixture-replication-destination"
APPROVED = "fixture-replication-approved"
OTHER = "fixture-replication-other"
ANONYMOUS = "fixture-replication-anonymous"
SOURCE_REGISTRY = "fixture-replication-source"
DNS = "registry-peer.saf.test"
SERVER_URI = "spiffe://saf.test/ns/saf-test/sa/fixture-replication-destination"
REGISTRY = ("docker.io/library/registry:3.0.0@sha256:"
            "6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e")
SCOPE = (
    "The source cluster sends one deterministic inert OCI fixture to one fixed mTLS ingress on an "
    "owned peer Kind cluster. The ingress accepts only a fixed POST operation, repository, tag, "
    "and bounded fixture byte set, then writes through loopback to the peer's pinned Distribution "
    "registry. A trusted-chain-only counterfactual accepts a separately scoped client URI; after "
    "registry reset, URI authorization refuses it. Missing client credentials and wrong peer DNS "
    "identity are separately refused. An independent peer-cluster readback verifies the manifest "
    "and blob digests in Distribution. Registry enrollment approval is outside this identity test."
)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Required adjacent SAF fixture helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def uri(account):
    return f"spiffe://saf.test/ns/saf-test/sa/{account}"


def issue_pki(lab):
    root = lab.kubeconfig.parent / "fixture-replication-pki"
    root.mkdir(mode=0o700)
    ca, ca_key = root / "ca.crt", root / "ca.key"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=fixture-replication-ca", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash",
        "-keyout", str(ca_key), "-out", str(ca))
    specs = ((DEST, "serverAuth", f"DNS:{DNS},URI:{SERVER_URI}"),
             (APPROVED, "clientAuth", f"URI:{uri(APPROVED)}"),
             (OTHER, "clientAuth", f"URI:{uri(OTHER)}"))
    for name, purpose, san in specs:
        key, csr, cert, ext = (root / f"{name}.{suffix}" for suffix in ("key", "csr", "crt", "ext"))
        ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                       f"extendedKeyUsage={purpose}\nsubjectAltName={san}\n"
                       "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
        lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                    "-subj", f"/CN={name}", "-keyout", str(key), "-out", str(csr))
        lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
                    "-CAcreateserial", "-days", "1", "-sha256", "-extfile", str(ext), "-out", str(cert))
    key_ids = {}
    for name, *_ in specs:
        certificate = lab.command("openssl", "x509", "-in", str(root / f"{name}.crt"),
                                  "-noout", "-text").stdout
        if "X509v3 Subject Key Identifier" not in certificate or "X509v3 Authority Key Identifier" not in certificate:
            lab.block(f"The fixture certificate for {name} lacks required key identifier extensions")
    return root, ca, key_ids


def registry_container():
    unit = container("registry", image=REGISTRY, imagePullPolicy="IfNotPresent",
                     ports=[{"containerPort": 5000}],
                     env=[{"name": "REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY", "value": "/tmp/registry"}])
    unit.pop("command", None)
    unit["readinessProbe"] = {"httpGet": {"port": 5000, "path": "/v2/"}, "periodSeconds": 1}
    return unit


def peer_pod(image, mode):
    gateway = container("replication-ingress", image=image, imagePullPolicy="Never",
        command=["python", "/code/replication_fixture.py", "serve", mode],
        ports=[{"containerPort": 8443}],
        volumeMounts=[{"name": "code", "mountPath": "/code", "readOnly": True},
                      {"name": "trust", "mountPath": "/trust", "readOnly": True},
                      {"name": "credential", "mountPath": "/credential", "readOnly": True}])
    gateway["readinessProbe"] = {"tcpSocket": {"port": 8443}, "periodSeconds": 1}
    observer = container("registry-observer", image=image, imagePullPolicy="Never", command=["sleep", "360"],
                         volumeMounts=[{"name": "code", "mountPath": "/code", "readOnly": True}])
    obj = pod(DEST, [registry_container(), gateway, observer], automountServiceAccountToken=False,
              terminationGracePeriodSeconds=2, securityContext={"fsGroup": 65534})
    obj["metadata"]["labels"] = {"app": DEST}
    obj["spec"]["volumes"] = [
        {"name": "code", "configMap": {"name": CODE}},
        {"name": "trust", "configMap": {"name": TRUST}},
        {"name": "credential", "secret": {"secretName": DEST, "defaultMode": 0o440}},
    ]
    return obj


def source_runner(lab, image, name, credential):
    mounts = [{"name": "code", "mountPath": "/code", "readOnly": True},
              {"name": "trust", "mountPath": "/trust", "readOnly": True}]
    volumes = [{"name": "code", "configMap": {"name": CODE}},
               {"name": "trust", "configMap": {"name": TRUST}}]
    if credential:
        mounts.append({"name": "credential", "mountPath": "/credential", "readOnly": True})
        volumes.append({"name": "credential", "secret": {"secretName": name, "defaultMode": 0o440}})
    unit = container("fixture", image=image, imagePullPolicy="Never", command=["sleep", "3600"],
                     volumeMounts=mounts)
    lab.create(pod(name, [unit], automountServiceAccountToken=False, volumes=volumes,
                   securityContext={"fsGroup": 65534}))
    ready(lab, name)


def source_registry(lab):
    unit = registry_container()
    obj = pod(SOURCE_REGISTRY, [unit], automountServiceAccountToken=False,
              terminationGracePeriodSeconds=2)
    obj["metadata"]["labels"] = {"app": SOURCE_REGISTRY}
    lab.create(obj)
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": SOURCE_REGISTRY},
                "spec": {"selector": {"app": SOURCE_REGISTRY},
                         "ports": [{"port": 5000, "targetPort": 5000}]}})
    ready(lab, SOURCE_REGISTRY)


def call(lab, actor, peer_ip, port, operation="replicate", hostname=DNS):
    cert = "none" if actor == ANONYMOUS else "cert"
    result = lab.kubectl("exec", actor, "--", "python", "/code/replication_fixture.py", "call",
                         peer_ip, str(port), operation, cert, hostname, timeout=20)
    return json.loads(result.stdout)


def await_route(lab, actor, peer_ip, port):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        response = call(lab, actor, peer_ip, port, operation="health")
        if response == {"status": 200, "body": {"decision": "ready"}}:
            return
        if response.get("status") != "transport-unavailable":
            lab.block(f"Peer TLS health returned an unrelated outcome: {response}")
        time.sleep(0.25)
    lab.block("The owned replication NodePort did not become reachable")


def observe_peer(peer):
    result = peer("exec", DEST, "-c", "registry-observer", "--", "python",
                  "/code/replication_fixture.py", "observe", timeout=15)
    return json.loads(result.stdout)


def run(lab):
    runtime = load(HERE.parent / "SAF-K8S-0908-001" / "case.py", "saf_replication_runtime")
    # Reuse the published disposable peer bridge; this case does not create or own a substitute.
    bridge = load(HERE.parent / "SAF-K8S-0910-020" / "owned_peer.py", "saf_replication_peer")
    fixture = (HERE / "replication_fixture.py").read_text()
    image = runtime.load_runtime(lab)
    root, ca, key_ids = issue_pki(lab)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CODE},
                "immutable": True, "data": {"replication_fixture.py": fixture}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": TRUST},
                "immutable": True, "data": {"ca.crt": ca.read_text()}})
    for name in (APPROVED, OTHER):
        lab.kubectl("create", "secret", "tls", name, "--cert=" + str(root / f"{name}.crt"),
                    "--key=" + str(root / f"{name}.key"), "-o", "name")
    for name in (APPROVED, OTHER, ANONYMOUS):
        source_runner(lab, image, name, name != ANONYMOUS)
    source_registry(lab)
    seeded = lab.kubectl("exec", APPROVED, "--", "python", "/code/replication_fixture.py", "seed",
                         timeout=20)
    seeded = json.loads(seeded.stdout)
    artifact = load(HERE / "replication_fixture.py", "saf_replication_artifact")
    digest = artifact.MANIFEST_DIGEST
    if seeded != {"digest": digest}:
        lab.block("Source Distribution did not confirm the deterministic fixture manifest digest")

    with bridge.owned_peer(lab, image) as (peer, peer_ip):
        peer("create", "-f", "-", payload=json.dumps({"apiVersion": "v1", "kind": "ConfigMap",
             "metadata": {"name": CODE}, "immutable": True,
             "data": {"replication_fixture.py": fixture}}))
        peer("create", "-f", "-", payload=json.dumps({"apiVersion": "v1", "kind": "ConfigMap",
             "metadata": {"name": TRUST}, "immutable": True, "data": {"ca.crt": ca.read_text()}}))
        peer("create", "secret", "tls", DEST, "--cert=" + str(root / f"{DEST}.crt"),
             "--key=" + str(root / f"{DEST}.key"), "-o", "name")
        service = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": DEST},
                   "spec": {"type": "NodePort", "selector": {"app": DEST},
                            "ports": [{"name": "mtls", "port": 8443, "targetPort": 8443}]}}
        peer("create", "-f", "-", payload=json.dumps(peer_pod(image, "baseline")))
        result = peer("create", "-f", "-", "-o", "json", payload=json.dumps(service))
        port = json.loads(result.stdout)["spec"]["ports"][0]["nodePort"]
        peer("wait", "--for=condition=Ready", f"pod/{DEST}", "--timeout=100s", timeout=110)
        await_route(lab, APPROVED, peer_ip, port)
        baseline = call(lab, OTHER, peer_ip, port)
        baseline_readback = observe_peer(peer)
        lab.check("red", "Trusted-chain-only counterfactual lets the alternate identity replicate",
                  baseline == {"status": 201, "body": {"decision": "replicated", "digest": digest,
                                "peer_uri": uri(OTHER)}} and baseline_readback == {"digest": digest, "status": 200},
                  {"attempt": baseline, "destination_readback": baseline_readback})

        # Delete and recreate both sidecars so the policy phase starts with no fixture content.
        peer("delete", "pod", DEST, "--wait=true", "--timeout=45s", timeout=55)
        peer("create", "-f", "-", payload=json.dumps(peer_pod(image, "restricted")))
        peer("wait", "--for=condition=Ready", f"pod/{DEST}", "--timeout=100s", timeout=110)
        await_route(lab, APPROVED, peer_ip, port)
        empty = observe_peer(peer)
        alternate = call(lab, OTHER, peer_ip, port)
        after_alternate = observe_peer(peer)
        no_client_cert = call(lab, ANONYMOUS, peer_ip, port)
        wrong_dns = call(lab, APPROVED, peer_ip, port, hostname="wrong-peer.saf.test")
        after_all_refusals = observe_peer(peer)
        approved = call(lab, APPROVED, peer_ip, port)
        approved_readback = observe_peer(peer)
        green_ok = (empty == {"digest": None, "status": 404}
                    and alternate == {"status": 403, "body": {"decision": "identity-refused",
                                                                  "peer_uri": uri(OTHER)}}
                    and after_alternate == {"digest": None, "status": 404}
                    and after_all_refusals == {"digest": None, "status": 404}
                    and no_client_cert == {"status": "client-certificate-refused"}
                    and wrong_dns == {"status": "server-identity-refused"})
        lab.check("green", "Restricted channel refuses alternate identity, missing certificate, and wrong server DNS",
                  green_ok, {"empty_before": empty, "alternate": alternate,
                             "readback_after_alternate": after_alternate,
                             "readback_after_all_refusals": after_all_refusals,
                             "missing_certificate": no_client_cert, "wrong_server_dns": wrong_dns})
        positive = (approved == {"status": 201, "body": {"decision": "replicated", "digest": digest,
                                                            "peer_uri": uri(APPROVED)}}
                    and approved_readback == {"digest": digest, "status": 200})
        lab.check("positive", "Approved URI identity transfers the pinned OCI digest to Distribution",
                  positive, {"attempt": approved, "destination_readback": approved_readback})

        receipt = {
            "case": "SAF-K8S-0910-030", "scope": SCOPE,
            "normalized_endpoints": {"source": "source-registry", "destination": "owned-peer-registry"},
            "registry": {"image": REGISTRY, "repository": "fixtures/saf-replication", "tag": "fixture-v1",
                         "manifest_digest": digest},
            "source_seed": seeded,
            "certificates": {"run_scoped": True, "server_dns": DNS, "server_uri": SERVER_URI,
                "approved_client_uri": uri(APPROVED), "alternate_client_uri": uri(OTHER),
                "extensions": ["subjectKeyIdentifier", "authorityKeyIdentifier"],
                "key_identifiers": key_ids},
            "counterfactual": {"identity": "alternate", "decision": baseline["body"]["decision"],
                               "destination_digest": baseline_readback["digest"]},
            "enforced": {"alternate_decision": alternate["body"]["decision"],
                "alternate_destination_digest": after_alternate["digest"],
                "missing_certificate": no_client_cert["status"], "wrong_server_dns": wrong_dns["status"]},
            "positive": {"decision": approved["body"]["decision"],
                         "destination_digest": approved_readback["digest"]},
        }
        (lab.evidence / "registry-replication-normalized.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n")
