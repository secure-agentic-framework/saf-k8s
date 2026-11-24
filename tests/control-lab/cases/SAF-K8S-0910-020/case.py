"""Route from a source Pod to a separately owned Kind peer and require TLS."""
import importlib.util
import json
from pathlib import Path
import time

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
TARGET = "fixture-transport"
CLIENT = "fixture-transport-caller"
CODE = "fixture-transport-code"
PEER_SECRET = "fixture-transport-cert"
TRUST = "fixture-transport-trust"
SCOPE = (
    "A source Pod reaches the same NodePort on a separate owned Kind cluster. The baseline "
    "returns a plaintext test response, then a verified Service switch requires TLS 1.3. "
    "Plaintext and a separate throwaway trust root fail while the intended client retrieves "
    "the approved marker through the verified TLS connection."
)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(lab):
    runtime = load(HERE.parent / "SAF-K8S-0908-001" / "case.py", "saf_tls_transport_runtime")
    bridge = load(HERE / "owned_peer.py", "saf_tls_owned_peer")
    image = runtime.load_runtime(lab)
    code = (HERE / "transport_fixture.py").read_text()
    key, cert, wrong_key, wrong_cert = (lab.kubeconfig.parent / filename for filename in
                                       ("tls.key", "tls.crt", "wrong.key", "wrong.crt"))
    for name, private, public in (("fixture-transport.saf.test", key, cert),
                                  ("unrelated-root.saf.test", wrong_key, wrong_cert)):
        lab.command("openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
                    "-subj", f"/CN={name}", "-addext", f"subjectAltName=DNS:{name}",
                    "-addext", "basicConstraints=critical,CA:TRUE",
                    "-addext", "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
                    "-keyout", str(private), "-out", str(public))
    template = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": CODE},
                "immutable": True, "data": {"transport_fixture.py": code}}
    with bridge.owned_peer(lab, image) as (peer, address):
        def create(contents):
            return peer("create", "-f", "-", "-o", "json", payload=json.dumps(contents))

        peer("create", "secret", "tls", PEER_SECRET, "--cert=" + str(cert), "--key=" + str(key), "-o", "name")
        create(template)
        server = container("endpoint", image=image, imagePullPolicy="Never",
                           command=["python", "/fixture/transport_fixture.py", "serve"],
                           readinessProbe={"tcpSocket": {"port": 8443}, "periodSeconds": 1},
                           volumeMounts=[{"name": "code", "mountPath": "/fixture", "readOnly": True},
                                         {"name": "pki", "mountPath": "/pki", "readOnly": True}])
        target = pod(TARGET, [server], automountServiceAccountToken=False,
                     securityContext={"fsGroup": 65534}, volumes=[
                         {"name": "code", "configMap": {"name": CODE}},
                         {"name": "pki", "secret": {"secretName": PEER_SECRET, "defaultMode": 0o440}},
                     ])
        target["metadata"]["labels"] = {"app": TARGET}
        create(target)
        service = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": TARGET},
                   "spec": {"type": "NodePort", "selector": {"app": TARGET},
                            "ports": [{"name": "transport", "port": 8443, "targetPort": 8080}]}}
        port = json.loads(create(service).stdout)["spec"]["ports"][0]["nodePort"]
        peer("wait", "--for=condition=Ready", "pod/" + TARGET, "--timeout=75s", timeout=85)
        lab.create(template)
        lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": TRUST},
                    "immutable": True, "data": {"ca.crt": cert.read_text(), "wrong.crt": wrong_cert.read_text()}})
        client = container("caller", image=image, imagePullPolicy="Never", command=["sleep", "3600"],
                           volumeMounts=[{"name": "code", "mountPath": "/fixture", "readOnly": True},
                                         {"name": "trust", "mountPath": "/trust", "readOnly": True}])
        lab.create(pod(CLIENT, [client], automountServiceAccountToken=False, volumes=[
            {"name": "code", "configMap": {"name": CODE}}, {"name": "trust", "configMap": {"name": TRUST}},
        ]))
        ready(lab, CLIENT)

        def probe(profile):
            result = lab.kubectl("exec", CLIENT, "--", "python", "/fixture/transport_fixture.py",
                                 address, str(port), profile, timeout=12)
            return json.loads(result.stdout)

        def await_read(profile):
            deadline = time.monotonic() + 14
            while True:
                result = probe(profile)
                if result.get("status") == 200 and result.get("marker"):
                    return result
                if time.monotonic() >= deadline:
                    lab.block("The expected cross-cluster fixture read did not reach its endpoint")
                time.sleep(0.25)

        baseline = await_read("plaintext")
        lab.check("red", "Before TLS is required the same peer route returns the plaintext marker",
                  baseline == {"status": 200, "marker": True}, baseline)
        changed = {"spec": {"ports": [{"name": "transport", "port": 8443, "targetPort": 8443, "nodePort": port}]}}
        service_live = json.loads(peer("patch", "service", TARGET, "--type=merge", "-p",
                                      json.dumps(changed), "-o", "json").stdout)
        secured = await_read("trusted")
        plaintext = probe("plaintext")
        wrong = probe("wrong")
        green = {
            "same_nodeport_now_routes_only_to_tls": service_live["spec"]["ports"][0]["nodePort"] == port
            and service_live["spec"]["ports"][0]["targetPort"] == 8443,
            "plaintext_refused": plaintext == {"status": "transport-refused"},
            "wrong_trust_refused": wrong == {"status": "certificate-refused"},
        }
        lab.check("green", "The peer route refuses plaintext and an unrelated trust root",
                  all(green.values()), green)
        positive = {"approved_response": secured.get("marker") is True and secured["status"] == 200,
                    "tls_1_3": secured["protocol"] == "TLSv1.3",
                    "approved_cipher": secured["cipher"] in {
                        "TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"
                    }}
        lab.check("positive", "A separately placed source retrieves the marker with verified TLS 1.3",
                  all(positive.values()), positive)
    (lab.evidence / "cross-cluster-tls.json").write_text(json.dumps({
        "baseline": baseline, "enforcement": green, "measured_tls": secured, "checks": positive,
    }, sort_keys=True, indent=2) + "\n")
