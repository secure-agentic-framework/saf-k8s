"""Bounded two-cluster federated-round enforcement witness for SAF-K8S-0910-004."""
import base64
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import time

from fixtures import container, pod

HERE = Path(__file__).resolve().parent
NS = "saf-test"
SERVER_DNS = "round-receiver.saf.test"
ROUND = "toy-round-2026-11-23-01"
STALE = "toy-round-2026-11-22-01"
PROTOCOL = "toy-vector-counts-v1"
PARTICIPANT_A = "spiffe://saf.test/ns/saf-test/sa/toy-participant-a"
PARTICIPANT_B = "spiffe://saf.test/ns/saf-test/sa/toy-participant-b"
ADMIN = "spiffe://saf.test/ns/saf-test/sa/toy-round-admin"
OBSERVER = "spiffe://saf.test/ns/saf-test/sa/toy-round-observer"
SERVICE = "toy-round-receiver"
CODE = "toy-round-code"
SERVER_SECRET = "toy-round-server-identity"
PARTICIPANT_A_SECRET = "toy-round-participant-a"
PARTICIPANT_B_SECRET = "toy-round-participant-b"
ADMIN_SECRET = "toy-round-admin"
OBSERVER_SECRET = "toy-round-observer"

SCOPE = (
    "Two distinct, disposable Kind clusters host one mTLS round receiver and one participant each. "
    "A pinned Python fixture accepts a stale synthetic vector in an explicitly unenforced baseline, "
    "then enforces exact round, protocol, membership, and duplicate checks. A separately identified "
    "observer reads the receiver's service state, and a valid harmless contribution submitted with "
    "that observer identity is refused without changing state. This covers one toy coordination "
    "path, not production FL, secure aggregation, differential privacy, Byzantine tolerance, or "
    "cluster-wide audit controls."
)


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _create(kubectl, resource):
    resource["metadata"].setdefault("namespace", NS)
    return kubectl("create", "-f", "-", "-o", "json", payload=json.dumps(resource), timeout=30)


def _configmap(kubectl, name, data):
    _create(kubectl, {"apiVersion": "v1", "kind": "ConfigMap",
                      "metadata": {"name": name}, "immutable": True, "data": data})


def _secret(kubectl, name, values):
    encoded = {key: base64.b64encode(value).decode("ascii") for key, value in values.items()}
    _create(kubectl, {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name},
                      "type": "Opaque", "data": encoded})


def _pki(lab, root):
    root.mkdir(mode=0o700, exist_ok=True)

    def openssl(*args):
        lab.command("openssl", *args, timeout=40)

    ca_key, ca_cert = root / "ca.key", root / "ca.crt"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-sha256",
            "-subj", "/CN=saf-k8s-0910-004-fixture-ca", "-addext",
            "basicConstraints=critical,CA:TRUE", "-addext",
            "keyUsage=critical,digitalSignature,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash",
            "-keyout", str(ca_key),
            "-out", str(ca_cert))

    identities = {
        "server": ("round-receiver", "DNS:" + SERVER_DNS, "serverAuth"),
        "participant-a": ("toy-participant-a", "URI:" + PARTICIPANT_A, "clientAuth"),
        "participant-b": ("toy-participant-b", "URI:" + PARTICIPANT_B, "clientAuth"),
        "admin": ("toy-round-admin", "URI:" + ADMIN, "clientAuth"),
        "observer": ("toy-round-observer", "URI:" + OBSERVER, "clientAuth"),
    }
    for label, (common_name, san, usage) in identities.items():
        key, csr, cert = (root / (label + suffix) for suffix in (".key", ".csr", ".crt"))
        ext = root / (label + ".ext")
        ext.write_text("basicConstraints=critical,CA:FALSE\n"
                       "keyUsage=critical,digitalSignature,keyEncipherment\n"
                       f"extendedKeyUsage={usage}\nsubjectAltName={san}\n"
                       "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj",
                "/CN=" + common_name, "-keyout", str(key), "-out", str(csr))
        openssl("x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
                "-CAcreateserial", "-days", "1", "-sha256", "-extfile", str(ext), "-out", str(cert))
    return root


def _cert_material(root, label, server=False):
    names = ("ca.crt", "server.crt", "server.key") if server else (
        "ca.crt", label + ".crt", label + ".key")
    return {("ca.crt" if name == "ca.crt" else ("server.crt" if name == "server.crt" else
             "server.key" if name == "server.key" else "client.crt" if name.endswith(".crt") else
             "client.key")): (root / name).read_bytes() for name in names}


def _runtime(lab):
    # The adjacent published runtime helper verifies architecture-specific image digests and
    # loads the same pinned image into the source cluster; owned_peer loads it into its cluster.
    module = _load(HERE.parent / "SAF-K8S-0908-001" / "case.py", "saf_0910_004_runtime")
    return module.load_runtime(lab)


def _client_pod(kubectl, image, name, secret_name):
    unit = container("fixture", image=image, imagePullPolicy="Never", command=["sleep", "3600"],
                     volumeMounts=[{"name": "code", "mountPath": "/fixture", "readOnly": True},
                                   {"name": "pki", "mountPath": "/pki", "readOnly": True}])
    _create(kubectl, pod(name, [unit], automountServiceAccountToken=False,
                         securityContext={"fsGroup": 65534}, volumes=[
                             {"name": "code", "configMap": {"name": CODE}},
                             {"name": "pki", "secret": {"secretName": secret_name,
                                                               "defaultMode": 0o440}},
                         ]))


def _client(kubectl, pod_name, endpoint, method, path, payload=None, *, wait=False):
    host, port = endpoint
    raw = "-" if payload is None else json.dumps(payload, sort_keys=True, separators=(",", ":"))
    deadline = time.monotonic() + 30
    while True:
        result = kubectl("exec", pod_name, "--", "python", "/fixture/round_service.py",
                         "client", host, str(port), SERVER_DNS, "/pki/client.crt", "/pki/client.key",
                         "/pki/ca.crt", method, path, raw, timeout=18, allow_failure=wait)
        if result.returncode == 0 or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])
    except (AttributeError, IndexError, json.JSONDecodeError):
        raise RuntimeError("bounded fixture client returned no valid JSON response")


def _state(kubectl, host):
    return _client(kubectl, "toy-round-observer", host, "GET", "/v1/state")


def run(lab):
    peer_module = _load(HERE.parent / "SAF-K8S-0910-020" / "owned_peer.py", "saf_0910_004_owned_peer")
    image = _runtime(lab)
    source = lab.kubectl

    with peer_module.owned_peer(lab, image) as (peer, peer_address):
        kube_apis = {name: kube("get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}").stdout
                     for name, kube in (("source", source), ("peer", peer))}
        if not all(kube_apis.values()) or len(set(kube_apis.values())) != 2:
            lab.block("Expected two different fixture API identities")
        for kubectl in (source, peer):
            _configmap(kubectl, CODE, {"round_service.py": (HERE / "round_service.py").read_text()})
        root = Path(tempfile.mkdtemp(prefix="saf-k8s-0910-004-pki-"))
        try:
            _pki(lab, root)
            _secret(peer, SERVER_SECRET, _cert_material(root, "server", server=True))
            _secret(source, PARTICIPANT_A_SECRET, _cert_material(root, "participant-a"))
            _secret(peer, PARTICIPANT_B_SECRET, _cert_material(root, "participant-b"))
            _secret(source, ADMIN_SECRET, _cert_material(root, "admin"))
            _secret(source, OBSERVER_SECRET, _cert_material(root, "observer"))
        finally:
            shutil.rmtree(root, ignore_errors=True)

        server = pod("toy-round-receiver", [container(
            "fixture", image=image, imagePullPolicy="Never",
            command=["python", "/fixture/round_service.py", "serve"],
            ports=[{"name": "mtls", "containerPort": 8443}],
            readinessProbe={"tcpSocket": {"port": 8443}, "periodSeconds": 1},
            volumeMounts=[{"name": "code", "mountPath": "/fixture", "readOnly": True},
                          {"name": "pki", "mountPath": "/pki", "readOnly": True}],
        )], automountServiceAccountToken=False,
            securityContext={"fsGroup": 65534}, volumes=[
                {"name": "code", "configMap": {"name": CODE}},
                {"name": "pki", "secret": {"secretName": SERVER_SECRET, "defaultMode": 0o440}},
            ])
        server["metadata"]["labels"] = {"app": "toy-round-receiver"}
        _create(peer, server)
        service = _create(peer, {"apiVersion": "v1", "kind": "Service", "metadata": {"name": SERVICE},
                       "spec": {"type": "NodePort", "selector": {"app": "toy-round-receiver"},
                                "ports": [{"name": "mtls", "port": 8443, "targetPort": 8443}]}})
        peer_address = (peer_address, json.loads(service.stdout)["spec"]["ports"][0]["nodePort"])

        _client_pod(source, image, "toy-participant-a", PARTICIPANT_A_SECRET)
        _client_pod(peer, image, "toy-participant-b", PARTICIPANT_B_SECRET)
        _client_pod(source, image, "toy-round-admin", ADMIN_SECRET)
        _client_pod(source, image, "toy-round-observer", OBSERVER_SECRET)
        for kubectl, name in ((peer, "toy-round-receiver"), (source, "toy-participant-a"),
                              (peer, "toy-participant-b"), (source, "toy-round-admin"),
                              (source, "toy-round-observer")):
            kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=95s", timeout=105)
        empty_state = _client(source, "toy-round-observer", peer_address, "GET", "/v1/state", wait=True)
        if empty_state != {"contributions": [], "aggregate": None}:
            lab.block("The owned receiver did not start with an empty fixture round")

        # Deliberately weak baseline: the receiver authenticates the same participant but accepts
        # a stale round and old protocol. This fixture vector contains only inert integer counts.
        stale = {"round": STALE, "protocol": "toy-vector-counts-v0", "cluster": "cluster-a",
                 "counts": [1, 0, 2]}
        baseline_reply = _client(source, "toy-participant-a", peer_address, "POST",
                                 "/v1/contributions", stale)
        baseline_state = _state(source, peer_address)
        expected_baseline_state = {"contributions": [stale], "aggregate": None}
        baseline_ok = (baseline_reply == {"status": 200, "decision": "contribution_recorded",
                                          "round": STALE, "cluster": "cluster-a"}
                       and baseline_state == expected_baseline_state)
        lab.check("red", "The unenforced baseline accepts a stale fixture round",
                  baseline_ok, {"response": baseline_reply, "receiver_state": baseline_state})

        policy = {"round": ROUND, "members": ["cluster-a", "cluster-b"], "protocol": PROTOCOL}
        wrong_admin = _client(source, "toy-participant-a", peer_address, "POST", "/v1/admin/enforce", policy)
        admin_reply = _client(source, "toy-round-admin", peer_address, "POST",
                              "/v1/admin/enforce", policy)
        before_refusal = _state(source, peer_address)
        stale_after_enforcement = {**stale, "counts": [2, 1, 0]}
        refusal = _client(source, "toy-participant-a", peer_address, "POST",
                          "/v1/contributions", stale_after_enforcement)
        after_refusal = _state(source, peer_address)
        expected_refusal = {"status": 409, "decision": "round_mismatch", "expected": ROUND,
                            "received": STALE}
        bad_protocol = {"round": ROUND, "protocol": "toy-vector-counts-v0", "cluster": "cluster-a",
                        "counts": [0, 1, 1]}
        protocol_refusal = _client(source, "toy-participant-a", peer_address, "POST",
                                   "/v1/contributions", bad_protocol)
        after_protocol_refusal = _state(source, peer_address)
        wrong_member = {"round": ROUND, "protocol": PROTOCOL, "cluster": "cluster-b",
                        "counts": [0, 1, 1]}
        member_refusal = _client(source, "toy-participant-a", peer_address, "POST",
                                 "/v1/contributions", wrong_member)
        after_member_refusal = _state(source, peer_address)
        expected_protocol_refusal = {"status": 409, "decision": "protocol_mismatch",
                                     "expected": PROTOCOL, "received": "toy-vector-counts-v0"}
        expected_member_refusal = {"status": 403, "decision": "round_member_refused",
                                   "cluster": "cluster-a"}
        green_ok = (wrong_admin == {"status": 403, "decision": "admin_identity_refused"}
                    and admin_reply == {"status": 200, "decision": "round_policy_enabled", "round": ROUND}
                    and before_refusal == expected_baseline_state
                    and refusal == expected_refusal and after_refusal == before_refusal
                    and protocol_refusal == expected_protocol_refusal
                    and after_protocol_refusal == before_refusal
                    and member_refusal == expected_member_refusal
                    and after_member_refusal == before_refusal)
        lab.check("green", "Round, protocol, and membership refusals leave receiver state unchanged",
                  green_ok, {"policy_enabled": admin_reply, "before": before_refusal,
                             "round_refusal": refusal, "after_round_refusal": after_refusal,
                             "protocol_refusal": protocol_refusal,
                             "after_protocol_refusal": after_protocol_refusal,
                             "membership_refusal": member_refusal,
                             "after_membership_refusal": after_member_refusal,
                             "state_unchanged": after_member_refusal == before_refusal})

        a = {"round": ROUND, "protocol": PROTOCOL, "cluster": "cluster-a", "counts": [2, 4, 6]}
        b = {"round": ROUND, "protocol": PROTOCOL, "cluster": "cluster-b", "counts": [4, 6, 8]}
        accepted_a = _client(source, "toy-participant-a", peer_address, "POST", "/v1/contributions", a)
        after_a = _state(source, peer_address)
        duplicate_a = _client(source, "toy-participant-a", peer_address, "POST",
                              "/v1/contributions", a)
        after_duplicate = _state(source, peer_address)
        accepted_b = _client(peer, "toy-participant-b", peer_address, "POST", "/v1/contributions", b)
        final_state = _state(source, peer_address)
        expected_final = {
            "contributions": [stale, a, b],
            "aggregate": {"round": ROUND, "protocol": PROTOCOL,
                          "members": ["cluster-a", "cluster-b"], "sum_counts": [6, 10, 14],
                          "mean_counts": [3, 5, 7]},
        }
        participant_read = _client(source, "toy-participant-a", peer_address, "GET", "/v1/state")
        expected_duplicate = {"status": 409, "decision": "duplicate_contribution_refused",
                              "round": ROUND, "cluster": "cluster-a"}
        positive_ok = (
            accepted_a == {"status": 200, "decision": "contribution_recorded", "round": ROUND,
                           "cluster": "cluster-a"}
            and after_a == {"contributions": [stale, a], "aggregate": None}
            and duplicate_a == expected_duplicate and after_duplicate == after_a
            and accepted_b == {"status": 200, "decision": "contribution_recorded", "round": ROUND,
                               "cluster": "cluster-b"}
            and final_state == expected_final
            and participant_read == {"status": 403, "decision": "observer_read_refused"}
        )
        lab.check("positive", "Both approved clusters contribute and the observer reads the exact deterministic aggregate",
                  positive_ok, {"participant_a": accepted_a, "participant_b": accepted_b,
                                "duplicate_refusal": duplicate_a,
                                "state_unchanged_after_duplicate": after_duplicate == after_a,
                                "observer_state": final_state, "participant_read_refused": participant_read})

        # Exercise principal authorization separately from a participant's false cluster claim.
        # The payload itself is a valid harmless current-round vector; the observer certificate
        # must be refused before the contribution can affect service state.
        before_observer_write = _state(source, peer_address)
        observer_vector = {"round": ROUND, "protocol": PROTOCOL, "cluster": "cluster-a",
                           "counts": [1, 1, 1]}
        observer_write_refusal = _client(source, "toy-round-observer", peer_address, "POST",
                                         "/v1/contributions", observer_vector)
        after_observer_write = _state(source, peer_address)
        observer_write_ok = (
            before_observer_write == final_state
            and observer_write_refusal == {"status": 403,
                                           "decision": "participant_identity_refused"}
            and after_observer_write == before_observer_write
        )
        lab.check("green", "Authenticated observer cannot submit a valid contribution and state stays unchanged",
                  observer_write_ok,
                  {"before": before_observer_write, "refusal": observer_write_refusal,
                   "after": after_observer_write,
                   "state_unchanged": after_observer_write == before_observer_write})

        receipt = {
            "case": "SAF-K8S-0910-004",
            "scope": "two-owned-kind-clusters/toy-vector-round/mTLS",
            "red": {"passed": baseline_ok, "baseline_response": baseline_reply,
                    "baseline_receiver_state": baseline_state},
            "green": {"passed": green_ok, "unapproved_policy_update": wrong_admin,
                      "expected_refusal": expected_refusal,
                      "protocol_refusal": expected_protocol_refusal,
                      "membership_refusal": expected_member_refusal,
                      "before": before_refusal, "after": after_member_refusal},
            "observer_write": {"passed": observer_write_ok,
                               "valid_fixed_vector": observer_vector,
                               "before": before_observer_write,
                               "refusal": observer_write_refusal,
                               "after": after_observer_write},
            "positive": {"passed": positive_ok,
                         "contributions": [accepted_a, accepted_b],
                         "duplicate_refusal": duplicate_a, "receiver_state": final_state,
                         "aggregate": expected_final["aggregate"]},
            "notes": ["Only inert toy integer counts are used.",
                      "Observer readback is an mTLS service GET using a distinct URI identity.",
                      "The aggregate includes only the exact enforced round; the baseline stale row remains visible but excluded."],
        }
        (lab.evidence / "federated-round-normalized.json").write_text(
            json.dumps(receipt, sort_keys=True, indent=2) + "\n")
        receipt["api_uids"] = kube_apis
        receipt["participant_pod_uids"] = [
            kube("get", "pod", name, "-o", "jsonpath={.metadata.uid}").stdout
            for kube, name in ((source, "toy-participant-a"), (peer, "toy-participant-b"))
        ]
        (lab.evidence / "federated-round-coordination.json").write_text(
            json.dumps(receipt, sort_keys=True, indent=2) + "\n")
