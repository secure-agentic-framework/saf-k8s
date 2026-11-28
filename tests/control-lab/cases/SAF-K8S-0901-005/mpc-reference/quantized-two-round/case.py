"""Additive finite two-round quantized MPC route for the existing SAF case."""

from base64 import b64encode
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent
PARTICIPANTS = tuple(f"saf-fl-q-party-{number}" for number in range(3))
FIXTURE_LABEL = "saf-k8s.example/fl-quantized-reference"
PORTS = (16000, 16100)
ENTRYPOINT = (HERE / "entrypoint.sh").read_text()


def parent_case():
    spec = importlib.util.spec_from_file_location("saf_0901_005_mpc_parent", PARENT / "case.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def helper(name):
    route = str(HERE)
    if route not in sys.path:
        sys.path.insert(0, route)
    spec = importlib.util.spec_from_file_location(f"saf_quantized_{name}", HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def create_peers(lab, base):
    addresses = []
    for namespace in PARTICIPANTS:
        lab.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {
            "name": namespace, "labels": {FIXTURE_LABEL: "owned",
                                          "pod-security.kubernetes.io/enforce": "restricted"}}})
        service = base.create_namespaced(lab, base.resource("Service", "mpc-peer", namespace, spec={
            "selector": {FIXTURE_LABEL: "peer"},
            "ports": [{"name": f"mpc-{port}", "port": port, "targetPort": port} for port in PORTS],
        }))
        addresses.append(service["spec"]["clusterIP"])
    return addresses


def install_peer_policies(lab, base):
    for namespace in PARTICIPANTS:
        authorized = {
            "namespaceSelector": {"matchLabels": {FIXTURE_LABEL: "owned"}},
            "podSelector": {"matchLabels": {FIXTURE_LABEL: "peer"}},
        }
        ports = [{"protocol": "TCP", "port": port} for port in PORTS]
        base.create_namespaced(lab, base.resource(
            "NetworkPolicy", "mpc-enrolled-peers", namespace, "networking.k8s.io/v1",
            spec={"podSelector": {"matchLabels": {FIXTURE_LABEL: "peer"}},
                  "policyTypes": ["Ingress", "Egress"],
                  "ingress": [{"from": [authorized], "ports": ports}],
                  "egress": [{"to": [authorized], "ports": ports}]}))


def enroll(lab, base, addresses, image, contract):
    public = {}
    with TemporaryDirectory(prefix="saf-fl-quantized-certs-") as directory:
        private = Path(directory)
        keys = []
        for number in range(len(PARTICIPANTS)):
            key, cert = private / f"P{number}.key", private / f"P{number}.pem"
            lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
                        "-subj", f"/CN=P{number}", "-keyout", str(key), "-out", str(cert), timeout=15)
            label = lab.command("openssl", "x509", "-in", str(cert), "-subject_hash", "-noout",
                                timeout=10).stdout.strip()
            public[cert.name] = public[f"{label}.0"] = cert.read_text()
            keys.append(key)
        for index, phase in enumerate(("calibration", "update")):
            public[f"{phase}-addresses"] = "".join(f"{address}:{PORTS[index]}\n" for address in addresses)
        for number, namespace in enumerate(PARTICIPANTS):
            text = contract.input_file_text(number)
            # Key material and synthetic private input enter via stdin, never argv or logs.
            secret = base.resource("Secret", "enrolled-party", namespace, immutable=True,
                                   data={"P%d.key" % number: b64encode(keys[number].read_bytes()).decode("ascii"),
                                         "input-bits": b64encode(text.encode()).decode("ascii")})
            result = subprocess.run(
                ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                 "--namespace", namespace, "create", "-f", "-", "-o", "name"],
                input=json.dumps(secret), env=lab.env, capture_output=True, text=True, timeout=15, check=False)
            if result.returncode != 0 or result.stdout.strip() != "secret/enrolled-party":
                lab.block(f"Could not install quantized fixture identity for party {number}")
    pods = []
    trust = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "mpc-trust"},
             "immutable": True, "data": public}
    for number, namespace in enumerate(PARTICIPANTS):
        namespaced_trust = {**trust, "metadata": {**trust["metadata"], "namespace": namespace}}
        base.create_namespaced(lab, namespaced_trust)
        pod = base.resource("Pod", "mpc-peer", namespace, spec={
            "automountServiceAccountToken": False, "restartPolicy": "Never", "activeDeadlineSeconds": 115,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534,
                                "fsGroup": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "participant", "image": image, "imagePullPolicy": "Never",
                            "command": ["/bin/sh", "-ec", ENTRYPOINT, "--", str(number)],
                            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                "capabilities": {"drop": ["ALL"]}},
                            "resources": {"requests": {"cpu": "25m", "memory": "24Mi"},
                                          "limits": {"cpu": "500m", "memory": "128Mi"}},
                            "volumeMounts": [{"name": name, "mountPath": "/" + name,
                                              "readOnly": name != "work"}
                                             for name in ("work", "trust", "identity")]}],
            "volumes": [{"name": "work", "emptyDir": {"sizeLimit": "12Mi"}},
                        {"name": "trust", "configMap": {"name": "mpc-trust"}},
                        {"name": "identity", "secret": {"secretName": "enrolled-party", "defaultMode": 0o440}}]})
        pod["metadata"]["labels"] = {FIXTURE_LABEL: "peer"}
        pods.append(base.create_namespaced(lab, pod)["metadata"]["uid"])
    return pods


def collect(lab):
    deadline = time.monotonic() + 100
    states = []
    phases = []
    while time.monotonic() < deadline:
        states = [json.loads(lab.kubectl("-n", namespace, "get", "pod", "mpc-peer", "-o", "json").stdout)
                  for namespace in PARTICIPANTS]
        phases = [state["status"].get("phase") for state in states]
        if "Failed" in phases or phases == ["Succeeded"] * len(PARTICIPANTS):
            break
        time.sleep(1)
    logs = []
    for namespace in PARTICIPANTS:
        # The vector is released to the participants and appears in Pod stdout.
        # Retrieve it only in memory so Lab.command does not copy it to commands.log.
        command = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                   "--namespace", namespace, "--request-timeout=30s", "logs", "pod/mpc-peer",
                   "--limit-bytes=262144"]
        try:
            result = subprocess.run(command, env=lab.env, capture_output=True, text=True,
                                    timeout=35, check=False)
        except (OSError, subprocess.TimeoutExpired):
            lab.block("Could not retrieve the bounded quantized participant transcript")
        if result.returncode != 0:
            lab.block("Could not retrieve the bounded quantized participant transcript")
        logs.append(result.stdout)
    if phases != ["Succeeded"] * len(PARTICIPANTS):
        lab.block(f"Quantized MPC attempt did not complete once: {phases}")
    return states, logs


def run(lab):
    """Run after the preserved one-bit suite, in separate namespaces and image."""
    base = parent_case()
    contract = helper("native_contract")
    verifier = helper("verify_witness")
    if verifier.verify_synthetic_fixture() != 18:
        lab.block("The fixed public quantizer no longer maps exactly 18 examples to the eight input bits")
    image = f"saf-k8s-local/mp-spdz-quantized-witness:{lab.cluster}"
    try:
        helper("build_runtime").build(lab, image)
        reservation = contract.reservation_manifest()
        admitted = lab.create(reservation)
        duplicate = lab.create(reservation, allow_failure=True)
        reservation_ok = contract.reservation_matches(admitted)
        duplicate_denied = contract.duplicate_rejected(duplicate)
        lab.check("red", "The quantized route reserves two fixed rounds and one vector transcript",
                  reservation_ok and duplicate_denied,
                  {"reservation_exact": reservation_ok, "duplicate_denied": duplicate_denied})

        addresses = create_peers(lab, base)
        install_peer_policies(lab, base)
        uids = enroll(lab, base, addresses, image, contract)
        states, logs = collect(lab)
        nonrestarted = (len(set(uids)) == 3 and all(uids) and
                        all(state["metadata"].get("uid") == uid for state, uid in zip(states, uids)) and
                        all(state["status"]["containerStatuses"][0]["restartCount"] == 0 for state in states))
        lab.check("green", "Three separately enrolled Pods complete one quantized two-round MPC transcript",
                  nonrestarted, {"distinct_pods": len(set(uids)), "all_completed": True,
                                 "no_restarts_or_retries": nonrestarted})
        try:
            oracle = verifier.parse_logs(logs)
            receipt = contract.stable_receipt(oracle)
            if verifier.verify_synthetic_fixture() != 18:
                raise ValueError("Fixed public gradient examples differ from the reviewed quantizer")
        except ValueError as error:
            lab.check("positive", "The quantized calibration, budget oracle and one-vector MPC logs match",
                      False, {"problem": str(error)})
        else:
            receipt.update({"mpc_release": "MP-SPDZ v0.4.4", "backend": "malicious-rep-bin-party.x",
                            "namespace_scoped_transport": True,
                            "random_vector_in_normalized_receipt": False})
            (lab.evidence / "bounded-quantized-private-aggregation.json").write_text(
                json.dumps(receipt, sort_keys=True, indent=2) + "\n")
            lab.check("positive", "The quantized calibration, budget oracle and one-vector MPC logs match",
                      True, {key: value for key, value in receipt.items()
                             if key not in {"random_vector_in_normalized_receipt"}})
    finally:
        lab.command("docker", "image", "rm", image, allow_failure=True, timeout=30)
