"""Retain live destination and workload identity decisions across two clusters."""
import importlib.util
import json
from pathlib import Path
import time

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
NAME = "fixture-identity-endpoint"
CODE = "fixture-identity-code"
TRUST = "fixture-identity-trust"
APPROVED = "fixture-signed-caller"
OTHER = "fixture-other-caller"
ANONYMOUS = "fixture-no-certificate"
DNS = "fixture-identity.saf.test"
SCOPE = (
    "Separate source and peer Kind clusters. The same approved node path starts with certificate-chain "
    "validation alone. A later gateway listener binds authorization to the exact URI identity after "
    "mutual TLS. The lab independently observes destination-name refusal, a same-CA alternate "
    "identity rejection, and acceptance of a separate workload's exact approved identity. "
    "The certificates and trust root are ephemeral fixture credentials."
)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pki(lab):
    root = lab.kubeconfig.parent / "fixture-owned-pki"
    root.mkdir(mode=0o700)
    ca, key = root / "root.crt", root / "root.key"
    lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=fixture-identity-root", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash", "-keyout", str(key), "-out", str(ca))
    for label, purpose, subject in ((NAME, "serverAuth", f"DNS:{DNS}"),
                                    (APPROVED, "clientAuth", f"URI:{uri(APPROVED)}"),
                                    (OTHER, "clientAuth", f"URI:{uri(OTHER)}")):
        csr, cert, private = (root / f"{label}.{ext}" for ext in ("csr", "crt", "key"))
        conf = root / f"{label}.ext"
        conf.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                        f"extendedKeyUsage={purpose}\nsubjectAltName={subject}\n"
                        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
        lab.command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                    "-subj", f"/CN={label}", "-keyout", str(private), "-out", str(csr))
        lab.command("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(key),
                    "-CAcreateserial", "-days", "1", "-sha256", "-extfile", str(conf), "-out", str(cert))
    return root, ca


def uri(account):
    return f"spiffe://saf.test/ns/saf-test/sa/{account}"


def workload(name, image, credential=False, server=False):
    sources = {"code": ("configMap", {"name": CODE}),
               "trust": ("configMap", {"name": TRUST})}
    if credential:
        sources["credential"] = ("secret", {"secretName": name, "defaultMode": 0o440})
    unit = container("worker", image=image, imagePullPolicy="Never",
                     command=["python", "/code/identity_fixture.py", "serve"] if server else ["sleep", "3600"],
                     volumeMounts=[{"name": part, "mountPath": "/" + part, "readOnly": True}
                                   for part in sources])
    if server:
        unit["readinessProbe"] = {"tcpSocket": {"port": 8444}, "periodSeconds": 1}
    obj = pod(name, [unit], automountServiceAccountToken=False, securityContext={"fsGroup": 65534},
              volumes=[{"name": part, kind: detail} for part, (kind, detail) in sources.items()])
    obj["metadata"]["labels"] = {"app": name}
    if not server:
        obj["spec"]["serviceAccountName"] = name
    return obj


def run(lab):
    runtime = load(HERE.parent / "SAF-K8S-0908-001" / "case.py", "saf_identity_runtime")
    bridge = load(HERE.parent / "SAF-K8S-0910-020" / "owned_peer.py", "saf_identity_peer")
    image = runtime.load_runtime(lab)
    root, ca = pki(lab)
    maps = [
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CODE}, "immutable": True,
         "data": {"identity_fixture.py": (HERE / "identity_fixture.py").read_text()}},
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": TRUST}, "immutable": True,
         "data": {"ca.crt": ca.read_text()}},
    ]

    def secret(call, name):
        call("create", "secret", "tls", name, "--cert=" + str(root / (name + ".crt")),
             "--key=" + str(root / (name + ".key")), "-o", "name")

    with bridge.owned_peer(lab, image) as (peer, address):
        def create(contents):
            return peer("create", "-f", "-", "-o", "json", payload=json.dumps(contents))

        secret(peer, NAME)
        for resource in maps:
            create(resource)
            lab.create(resource)
        create(workload(NAME, image, credential=True, server=True))
        spec = {"type": "NodePort", "selector": {"app": NAME},
                "ports": [{"name": "mtls", "port": 8443, "targetPort": 8443}]}
        result = create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": NAME}, "spec": spec})
        port = json.loads(result.stdout)["spec"]["ports"][0]["nodePort"]
        for name in (APPROVED, OTHER, ANONYMOUS):
            lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": name},
                        "automountServiceAccountToken": False})
            if name != ANONYMOUS:
                secret(lab.kubectl, name)
            lab.create(workload(name, image, credential=name != ANONYMOUS))
        peer("wait", "--for=condition=Ready", "pod/" + NAME, "--timeout=80s", timeout=90)
        for name in (APPROVED, OTHER, ANONYMOUS):
            ready(lab, name)

        def probe(name, hostname=DNS):
            result = lab.kubectl("exec", name, "--", "python", "/code/identity_fixture.py",
                                 address, str(port), hostname, timeout=15)
            return json.loads(result.stdout)

        def await_decision(name, status):
            deadline = time.monotonic() + 16
            while True:
                result = probe(name)
                if result["status"] == status:
                    return result
                if time.monotonic() >= deadline:
                    lab.block(f"The expected identity decision {status} did not become observable: {result}")
                time.sleep(0.25)

        baseline = await_decision(OTHER, 200)
        expected_alt = {"caller": uri(OTHER), "decision": "allowed", "response": "synthetic-identity-ack"}
        lab.check("red", "The trusted-chain-only baseline accepts the separately signed alternate identity",
                  baseline["body"] == expected_alt, baseline)
        change = {"spec": {"ports": [{"name": "mtls", "port": 8443, "targetPort": 8444, "nodePort": port}]}}
        peer("patch", "service", NAME, "--type=merge", "-p", json.dumps(change))
        alternate = await_decision(OTHER, 403)
        wrong = probe(APPROVED, "fixture-unapproved.saf.test")
        anonymous = probe(ANONYMOUS)
        green = {
            "same_ca_alternate_refused_for_exact_workload_identity": alternate["body"] == {
                "caller": uri(OTHER), "decision": "refused", "response": None,
            },
            "the_source_rejects_an_unapproved_destination_dns_identity":
                wrong == {"status": "destination-identity-refused"},
            "server_requires_a_client_certificate": anonymous == {"status": "client-tls-refused"},
        }
        lab.check("green", "Destination and workload authentication reject independent test cases",
                  all(green.values()), green)
        authorized = probe(APPROVED)
        gateway_events = [json.loads(line) for line in peer("logs", "pod/" + NAME).stdout.splitlines()
                          if line.startswith("{")]
        expected = {"caller": uri(APPROVED), "decision": "allowed", "response": "synthetic-identity-ack"}
        positive = {"approved_source_gets_reply": authorized == {"status": 200, "body": expected},
                    "peer_independently_records_the_exact_approved_certificate_identity":
                    {"mode": "verified-identity", "status": 200, **expected} in gateway_events}
        lab.check("positive", "The real peer sees the approved source's certificate URI",
                  all(positive.values()), positive)
    (lab.evidence / "cross-cluster-identity.json").write_text(json.dumps({
        "baseline": baseline, "scoped_alternate": alternate, "wrong_destination": wrong,
        "no_client_certificate": anonymous, "approved": authorized,
        "matched_peer_events": [event for event in gateway_events if event["mode"] == "verified-identity"],
    }, sort_keys=True, indent=2) + "\n")
