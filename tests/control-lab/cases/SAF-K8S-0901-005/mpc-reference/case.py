"""Scratch reference for a bounded private aggregation round on Kubernetes."""
from base64 import b64encode
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import time

HERE = Path(__file__).resolve().parent
FIXTURE_LABEL = "saf-k8s.example/fl-reference"
PARTICIPANTS = tuple(f"saf-fl-party-{number}" for number in range(3))
PORTS = (16000, 16100)
SCOPE = (
    "Three distinct enrolled participant Pods in a disposable Kind cluster run the official "
    "MP-SPDZ v0.4.4 malicious honest-majority binary MPC backend. The one-bit median fixture "
    "opens only a randomized-response output. An independently labeled public calibration "
    "uses no private inputs. This fixed equal-participant profile assumes at most one corrupted "
    "peer, a trusted cluster and enrollment authority, and no round retry."
)
ENTRYPOINT = r"""
set -eu
umask 077
cd /work
mkdir Player-Data
ln -s /opt/mp-spdz/Programs Programs
cp -L /trust/*.pem /trust/*.0 Player-Data/
cp -L /identity/P"$1".key Player-Data/
label=$(cat /identity/local-label)
case "$label" in
    0|1) ;;
    *) exit 2 ;;
esac
# At weight zero with a unit feature, twice the negative logistic gradient is 2y - 1.
sign_bit=0
if [ "$((2 * label - 1))" -gt 0 ]; then
    sign_bit=1
fi
printf '%s\n' "$sign_bit" > Player-Data/Input-P"$1"-0
run_protocol() {
    timeout --signal=TERM 45s /opt/mp-spdz/x86_64/ld-2.31.so \
      --library-path /opt/mp-spdz/x86_64 /opt/mp-spdz/malicious-rep-bin-party.x \
      -p "$1" -ip "$2" -OF . "$3"
}
run_protocol "$1" /trust/calibration-addresses saf_private_update_truth_table
exec timeout --signal=TERM 45s /opt/mp-spdz/x86_64/ld-2.31.so \
  --library-path /opt/mp-spdz/x86_64 /opt/mp-spdz/malicious-rep-bin-party.x \
  -p "$1" -ip /trust/update-addresses -OF . saf_private_update
"""


def resource(kind, name, namespace=None, api="v1", **fields):
    metadata = {"name": name}
    if namespace:
        metadata["namespace"] = namespace
    return {"apiVersion": api, "kind": kind, "metadata": metadata, **fields}


def create_namespaced(lab, resource):
    namespace = resource["metadata"]["namespace"]
    result = lab.kubectl("-n", namespace, "create", "-f", "-", "-o", "json", payload=json.dumps(resource))
    return json.loads(result.stdout)


def sealed_identity(lab, number, namespace, private_key, label):
    items = {f"P{number}.key": private_key, "local-label": f"{label}\n".encode()}
    payload = resource("Secret", "enrolled-party", namespace, immutable=True,
                       data={name: b64encode(value).decode("ascii") for name, value in items.items()})
    # Submit ephemeral private keys on stdin, outside the command transcript.
    result = subprocess.run(
        ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
         "--namespace", namespace, "create", "-f", "-", "-o", "name"], input=json.dumps(payload), env=lab.env,
        capture_output=True, text=True, timeout=15, check=False,
    )
    if result.returncode != 0 or result.stdout.strip() != "secret/enrolled-party":
        lab.block(f"Could not install the disposable identity for party {number}")


def create_peers(lab):
    addresses = []
    for namespace in PARTICIPANTS:
        lab.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {
            "name": namespace, "labels": {FIXTURE_LABEL: "owned",
                                          "pod-security.kubernetes.io/enforce": "restricted"}}})
        svc = create_namespaced(lab, resource("Service", "mpc-peer", namespace, spec={
            "selector": {FIXTURE_LABEL: "peer"},
            "ports": [{"name": f"mpc-{port}", "port": port, "targetPort": port} for port in PORTS],
        }))
        addresses.append(svc["spec"]["clusterIP"])
    return addresses


def install_peer_policy(lab, namespace):
    authorized = {
        "namespaceSelector": {"matchLabels": {FIXTURE_LABEL: "owned"}},
        "podSelector": {"matchLabels": {FIXTURE_LABEL: "peer"}},
    }
    ports = [{"protocol": "TCP", "port": port} for port in PORTS]
    create_namespaced(lab, resource("NetworkPolicy", "mpc-enrolled-peers", namespace, "networking.k8s.io/v1",
                        spec={"podSelector": {"matchLabels": {FIXTURE_LABEL: "peer"}},
                              "policyTypes": ["Ingress", "Egress"],
                              "ingress": [{"from": [authorized], "ports": ports}],
                              "egress": [{"to": [authorized], "ports": ports}]}))


def start_participant(lab, number, namespace, public, image):
    create_namespaced(lab, resource("ConfigMap", "mpc-trust", namespace, immutable=True, data=public))
    pod = resource("Pod", "mpc-peer", namespace, spec={
        "automountServiceAccountToken": False,
        "restartPolicy": "Never",
        "activeDeadlineSeconds": 115,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534,
                            "fsGroup": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{
            "name": "participant", "image": image, "imagePullPolicy": "Never",
            "command": ["/bin/sh", "-ec", ENTRYPOINT, "--", str(number)],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "25m", "memory": "24Mi"},
                          "limits": {"cpu": "500m", "memory": "128Mi"}},
            "volumeMounts": [{"name": name, "mountPath": "/" + name, "readOnly": name != "work"}
                             for name in ("work", "trust", "identity")],
        }],
        "volumes": [{"name": "work", "emptyDir": {"sizeLimit": "12Mi"}},
                    {"name": "trust", "configMap": {"name": "mpc-trust"}},
                    {"name": "identity", "secret": {"secretName": "enrolled-party", "defaultMode": 0o440}}],
    })
    pod["metadata"]["labels"] = {FIXTURE_LABEL: "peer"}
    return create_namespaced(lab, pod)["metadata"]["uid"]


def enroll(lab, addresses, image):
    with TemporaryDirectory(prefix="saf-fl-peer-certs-") as directory:
        private = Path(directory)
        public = {}
        for number in range(len(PARTICIPANTS)):
            key = private / f"P{number}.key"
            cert = private / f"P{number}.pem"
            lab.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
                        "-subj", f"/CN=P{number}", "-keyout", str(key), "-out", str(cert), timeout=15)
            label = lab.command("openssl", "x509", "-in", str(cert), "-subject_hash", "-noout",
                                timeout=10).stdout.strip()
            public[cert.name] = public[f"{label}.0"] = cert.read_text()
        for index, phase in enumerate(("calibration", "update")):
            public[f"{phase}-addresses"] = "".join(f"{address}:{PORTS[index]}\n" for address in addresses)
        # Each participant has one private synthetic local binary label. At zero weight,
        # the sign of the unit logistic-model update equals that label.
        labels = (1, 0, 1)
        for number, namespace in enumerate(PARTICIPANTS):
            sealed_identity(lab, number, namespace, (private / f"P{number}.key").read_bytes(), labels[number])
    return [start_participant(lab, number, namespace, public, image) for number, namespace in enumerate(PARTICIPANTS)]


def collect(lab):
    deadline = time.monotonic() + 100
    phases = []
    while time.monotonic() < deadline:
        states = [json.loads(lab.kubectl("-n", ns, "get", "pod", "mpc-peer", "-o", "json").stdout)
                  for ns in PARTICIPANTS]
        phases = [state["status"].get("phase") for state in states]
        if "Failed" in phases or phases == ["Succeeded"] * 3:
            break
        time.sleep(1)
    logs = [lab.kubectl("-n", ns, "logs", "pod/mpc-peer", allow_failure=True).stdout for ns in PARTICIPANTS]
    if phases != ["Succeeded"] * 3:
        lab.block(f"One bounded MPC attempt failed to complete: {phases}")
    return states, logs


def helper(name):
    spec = spec_from_file_location(f"saf_mpc_{name}", HERE / f"{name}.py")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(lab):
    image = f"saf-k8s-local/mp-spdz-witness:{lab.cluster}"
    try:
        helper("build_runtime").build(lab, image)
        exercise(lab, image)
    finally:
        lab.command("docker", "image", "rm", image, allow_failure=True, timeout=30)


def exercise(lab, image):
    lease = resource("ConfigMap", "mpc-round-reservation", "saf-test", immutable=True,
                     data={"round": "bounded-binary-reference", "maximum_releases": "1"})
    admitted = lab.create(lease)
    duplicate = lab.create(lease, allow_failure=True)
    locked = admitted.get("immutable") is True and admitted.get("data") == lease["data"]
    denied = duplicate.returncode != 0 and "AlreadyExists" in duplicate.stderr
    lab.check("red", "The immutable reservation rejects a second admission for the same fixture round",
              locked and denied, {"one_round_reservation": locked, "duplicate_denied": denied})

    addresses = create_peers(lab)
    for namespace in PARTICIPANTS:
        install_peer_policy(lab, namespace)
    uids = enroll(lab, addresses, image)
    states, logs = collect(lab)
    bound = (len(set(uids)) == 3 and all(uids) and all(state["metadata"]["uid"] == uid for state, uid in zip(states, uids))
             and all(state["status"]["containerStatuses"][0]["restartCount"] == 0 for state in states))
    lab.check("green", "Three distinct enrolled peer Pods complete a single non-restarted MPC reference round",
              bound, {"enrolled_peers": len(set(uids)), "all_completed": True, "no_restarts": bound})

    verifier = helper("verify_witness")
    try:
        summary = verifier.verify(logs)
    except ValueError as error:
        lab.check("positive", "The one-bit release and public calibration match the independent oracle", False,
                  {"problem": str(error)})
    else:
        scope = {
            **summary, "mpc_release": "MP-SPDZ v0.4.4", "adjacency": "one changed participant bit",
            "maximum_output_releases": 1, "robustness_condition": "two agreeing honest binary inputs",
            "abort_selection_excluded": True, "production_gradient_claimed": False,
            "participant_update": "one-bit unit-feature logistic update at weight zero",
        }
        (lab.evidence / "bounded-private-aggregation.json").write_text(
            json.dumps(scope, indent=2, sort_keys=True) + "\n")
        lab.check("positive", "The one-bit release and public calibration match the independent oracle",
                  True, summary)
