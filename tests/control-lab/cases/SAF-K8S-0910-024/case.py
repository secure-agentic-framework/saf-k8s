"""Test signed model provenance transfer between separately owned clusters."""
import base64
from hashlib import sha256
import importlib.util
import ipaddress
import json
from pathlib import Path
import tempfile
from datetime import datetime, timedelta, timezone

from fixtures import container, pod

HERE = Path(__file__).resolve().parent
NS = "saf-test"
SOURCE_REGISTRY = "fixture-source-registry"
DESTINATION_REGISTRY = "fixture-destination-registry"
SOURCE_CLIENT = "fixture-provenance-source-client"
TRANSFER_CLIENT = "fixture-provenance-transfer"
VALIDATOR_CLIENT = "fixture-provenance-validator"
SOURCE_CODE = "fixture-provenance-source-code"
PEER_CODE = "fixture-provenance-peer-code"
REPO = "fixtures/model"
NOW_VALUE = datetime.now(timezone.utc).replace(microsecond=0)
NOW = NOW_VALUE.isoformat().replace("+00:00", "Z")
REGISTRY = ("docker.io/library/registry:3.0.0@sha256:"
            "6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e")
SCOPE = (
    "An inert model-metadata blob and OCI manifest are seeded through the Distribution API in the "
    "harness-owned source cluster. The exact SAF-K8S-0910-020 owned_peer manager creates a separately "
    "owned peer cluster on the isolated Kind bridge. The same source blob is transferred in a control-off "
    "baseline that strips signed provenance and a control-on path that requires source-bound signed "
    "in-toto/SLSA lineage. A different peer pod independently reads the destination manifest and blob, "
    "compares exact source bytes and digests, and verifies the signature using only approved public-key "
    "bytes and the signature bytes returned by the registry."
)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(data):
    return "sha256:" + sha256(data).hexdigest()


def model_blob():
    return json.dumps({"executable": False, "name": "fixture-linear-model",
                       "version": "1.0.0", "weights": "synthetic-placeholder"},
                      sort_keys=True, separators=(",", ":")).encode()


def statement(created=NOW, subject=None):
    model_digest = subject or sha256(model_blob()).hexdigest()
    value = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": REPO, "digest": {"sha256": model_digest}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {"buildType": "https://example.invalid/saf/fixture-training/v1",
                                "externalParameters": {"model": "fixture-linear-model"},
                                "internalParameters": {}},
            "runDetails": {"builder": {"id": "fixture://training-workflow"},
                           "metadata": {"invocationId": "fixture-run-001",
                                        "startedOn": created, "finishedOn": created}},
            "saf_created_at": created,
            "saf_origin_cluster": "fixture-training-cluster",
            "saf_signing_identity": "fixture://model-release-signer",
            "saf_promotion_workflow": "fixture-model-approved",
        },
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sign(lab, key_path, directory, label, payload):
    payload_path = Path(directory) / (label + ".json")
    signature_path = Path(directory) / (label + ".sig")
    payload_path.write_bytes(payload)
    lab.command("openssl", "dgst", "-sha256", "-sign", str(key_path),
                "-out", str(signature_path), str(payload_path), timeout=20)
    return base64.b64encode(payload).decode(), base64.b64encode(signature_path.read_bytes()).decode()


def create(lab, obj):
    obj.setdefault("metadata", {})["namespace"] = NS
    if callable(lab):
        lab("apply", "-f", "-", payload=json.dumps(obj, sort_keys=True), timeout=20)
    else:
        lab.create(obj)


def registry(lab, name, node_port=False):
    unit = container("registry", image=REGISTRY,
                     ports=[{"containerPort": 5000}],
                     env=[{"name": "REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY",
                           "value": "/tmp/saf-registry"}])
    unit.pop("command", None)
    unit["readinessProbe"] = {"httpGet": {"port": 5000, "path": "/v2/"},
                              "periodSeconds": 1}
    workload = pod(name, [unit], automountServiceAccountToken=False)
    workload["metadata"]["labels"] = {"app": name}
    create(lab, workload)
    port = {"port": 5000, "targetPort": 5000}
    service = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name},
               "spec": {"type": "NodePort" if node_port else "ClusterIP",
                        "selector": {"app": name}, "ports": [port]}}
    if node_port:
        return lab.create(service)["spec"]["ports"][0]["nodePort"]
    create(lab, service)


def client(lab, name, image, command, mounts, volumes):
    unit = container("client", image=image, imagePullPolicy="Never",
                     command=command, volumeMounts=mounts)
    create(lab, pod(name, [unit], automountServiceAccountToken=False, volumes=volumes))


def code_map(lab, name, files):
    create(lab, {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                 "immutable": True, "data": files})


def wait(lab, name):
    if callable(lab):
        lab("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=95s", timeout=105)
    else:
        lab.kubectl("-n", NS, "wait", "--for=condition=Ready", f"pod/{name}",
                    "--timeout=95s", timeout=105)


def exec_json(kubectl, pod_name, script_name, operation, payload=None, tag=None):
    args = ["exec"]
    options = {"timeout": 35}
    if payload is not None:
        args.append("-i")
        options["payload"] = json.dumps(payload, sort_keys=True)
    args.extend([pod_name, "--", "python", "/fixture/" + script_name, operation])
    if tag is not None:
        args.append(tag)
    result = kubectl(*args, **options)
    return json.loads(result.stdout)


def source_host(lab):
    fmt = '{{json (index .NetworkSettings.Networks "kind")}}'
    raw = lab.command("docker", "inspect", "--format", fmt,
                      lab.cluster + "-control-plane", timeout=15).stdout
    address = ipaddress.ip_address(json.loads(raw)["IPAddress"])
    if address.version != 4 or address.is_global or address.is_loopback or address.is_link_local:
        lab.block("The source cluster does not have a private owned bridge address")
    return str(address)


def pod_code_config(lab, peer, public_pem, source_route):
    shared = {name: (HERE / name).read_text() for name in ("replication_fixture.py", "verify_signature.py")}
    code_map(lab, SOURCE_CODE, shared)
    code_map(peer, PEER_CODE, {
        **shared, "destination_validator.py": (HERE / "destination_validator.py").read_text(),
        "approved-public.pem": public_pem.decode("ascii"),
        "source-route.json": json.dumps(source_route),
    })


def create_clients(lab, peer, image):
    for name, code_name in ((SOURCE_CLIENT, SOURCE_CODE),
                            (TRANSFER_CLIENT, PEER_CODE),
                            (VALIDATOR_CLIENT, PEER_CODE)):
        client_kube = peer if name != SOURCE_CLIENT else source_kubectl(lab)
        mounts = [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}]
        volumes = [{"name": "fixture", "configMap": {"name": code_name}}]
        client(client_kube, name, image, ["sleep", "360"], mounts, volumes)
        wait(client_kube, name)


def source_kubectl(lab):
    def command(*args, **kwargs):
        return lab.kubectl("-n", NS, *args, **kwargs)
    return command


def run(lab):
    bridge = load(HERE.parent / "SAF-K8S-0910-020" / "owned_peer.py", "saf_lineage_peer")
    runtime = load(HERE.parent / "SAF-K8S-0908-001" / "case.py", "saf_lineage_runtime")
    image = runtime.load_runtime(lab)
    with tempfile.TemporaryDirectory(prefix="saf-0910-024-") as key_dir:
        key_path = Path(key_dir) / "ephemeral-signing-key.pem"
        public_path = Path(key_dir) / "approved-public.pem"
        lab.command("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                    "-out", str(key_path), timeout=30)
        lab.command("openssl", "pkey", "-in", str(key_path), "-pubout", "-out", str(public_path), timeout=20)
        public_pem = public_path.read_bytes()

        with bridge.owned_peer(lab, image) as (peer, _):
            source_port = registry(lab, SOURCE_REGISTRY, node_port=True)
            registry(peer, DESTINATION_REGISTRY)
            wait(lab, SOURCE_REGISTRY)
            peer("wait", "--for=condition=Ready", f"pod/{DESTINATION_REGISTRY}",
                 "--timeout=95s", timeout=105)
            source = SOURCE_REGISTRY + "." + NS + ".svc"
            node_address = source_host(lab)
            statement_b64, signature_b64 = sign(lab, key_path, key_dir, "source", statement())
            pod_code_config(lab, peer, public_pem, {"host": node_address, "port": source_port})
            create_clients(lab, peer, image)

            source_command = source_kubectl(lab)
            seed = exec_json(source_command, SOURCE_CLIENT, "replication_fixture.py", "seed", {
                "source_host": source,
                "statement_b64": statement_b64,
                "signature_b64": signature_b64,
                "public_pem_b64": base64.b64encode(public_pem).decode(),
            })
            source_readback = exec_json(source_command, SOURCE_CLIENT,
                                        "replication_fixture.py", "inspect", tag=source)
            if seed.get("source_digest") != source_readback.get("manifest_digest"):
                lab.block("Source registry seed did not match its independent API readback")

            if exec_json(peer, TRANSFER_CLIENT, "replication_fixture.py", "wait-source") != {"ready": True}:
                lab.block("The owned source Distribution NodePort did not become reachable")
            common = {"expected_source_digest": source_readback["manifest_digest"]}
            baseline_gate = exec_json(peer, TRANSFER_CLIENT, "replication_fixture.py", "transfer",
                                      {**common, "mode": "off", "tag": "baseline"})
            baseline_readback = exec_json(peer, VALIDATOR_CLIENT, "destination_validator.py", "inspect", {
                "mode": "off", "manifest_b64": source_readback["manifest_bytes_b64"],
                "blob_digest": source_readback["blob_digest"],
                "blob_bytes_b64": source_readback["blob_bytes_b64"],
            }, tag="baseline")
            baseline_checks = baseline_readback.get("checks", {})
            baseline = {
                "control_off_transfer_allowed": baseline_gate.get("written") is True
                and baseline_gate.get("decision") == "unchecked-baseline",
                "destination_manifest_present_and_self_consistent": baseline_checks.get("manifest_present") is True
                and baseline_checks.get("manifest_body_hash_matches_header") is True,
                "same_model_blob_preserved": baseline_checks.get("blob_readback_present") is True
                and baseline_checks.get("blob_bytes_match_descriptor") is True
                and baseline_checks.get("blob_bytes_equal_source") is True
                and baseline_checks.get("blob_digest_equal_source") is True
                and baseline_checks.get("blob_length_matches_descriptor") is True,
                "source_manifest_provenance_omitted": baseline_checks.get("required_lineage_omitted") is True
                and baseline_checks.get("manifest_bytes_equal_source") is False,
            }
            lab.check("red", "Control-off transfers the model blob while omitting signed provenance",
                      all(baseline.values()), baseline)

            positive = {**common, "mode": "on", "tag": "preserved",
                        "statement_b64": source_readback["statement_b64"],
                        "signature_b64": source_readback["signature_b64"]}
            gate = exec_json(peer, TRANSFER_CLIENT, "replication_fixture.py", "transfer", positive)
            readback = exec_json(peer, VALIDATOR_CLIENT, "destination_validator.py", "inspect", {
                "mode": "on", "manifest_b64": source_readback["manifest_bytes_b64"],
                "blob_digest": source_readback["blob_digest"],
                "blob_bytes_b64": source_readback["blob_bytes_b64"],
                "statement_b64": source_readback["statement_b64"],
                "signature_b64": source_readback["signature_b64"],
            }, tag="preserved")
            enforced_checks = readback.get("checks", {})
            enforced = {
                "control_on_transfer_allowed": gate.get("written") is True and gate.get("decision") == "allowed",
                "exact_source_manifest_bytes_preserved": enforced_checks.get("manifest_bytes_equal_source") is True,
                "manifest_body_hash_matches_distribution_header": enforced_checks.get("manifest_body_hash_matches_header") is True,
                "exact_source_blob_preserved": enforced_checks.get("blob_readback_present") is True
                and enforced_checks.get("blob_bytes_match_descriptor") is True
                and enforced_checks.get("blob_bytes_equal_source") is True
                and enforced_checks.get("blob_digest_equal_source") is True
                and enforced_checks.get("blob_length_matches_descriptor") is True
                and enforced_checks.get("blob_header_matches_bytes") is True,
                "source_lineage_bytes_preserved": enforced_checks.get("lineage_bytes_equal_source") is True,
                "readback_signature_cryptographically_valid": enforced_checks.get(
                    "lineage_signature_check_passed_from_readback_bytes") is True,
                "lineage_subject_and_policy_bound": enforced_checks.get("lineage_subject_binds_blob") is True
                and enforced_checks.get("lineage_policy_fields_match") is True,
            }
            lab.check("positive", "Control-on requires and preserves verifiable source lineage",
                      all(enforced.values()), enforced)

            stale_time = (NOW_VALUE - timedelta(days=3)).isoformat().replace("+00:00", "Z")
            stale_b64, stale_sig = sign(lab, key_path, key_dir, "stale", statement(stale_time))
            wrong_b64, wrong_sig = sign(lab, key_path, key_dir, "wrong-subject", statement(subject="0" * 64))
            invalid_sig = base64.b64encode(b"invalid-signature-fixture").decode()
            refusals = {
                "missing-lineage": ({"tag": "refuse-missing"}, "lineage-missing"),
                "stale-lineage": ({"tag": "refuse-stale", "statement_b64": stale_b64,
                                   "signature_b64": stale_sig}, "lineage-stale"),
                "wrong-subject": ({"tag": "refuse-subject", "statement_b64": wrong_b64,
                                   "signature_b64": wrong_sig}, "subject-mismatch"),
                "wrong-source-digest": ({"tag": "refuse-source-digest", "statement_b64": statement_b64,
                                          "signature_b64": signature_b64,
                                          "expected_source_digest": "sha256:" + "0" * 64},
                                         "source-manifest-digest-mismatch"),
                "invalid-signature": ({"tag": "refuse-signature", "statement_b64": statement_b64,
                                       "signature_b64": invalid_sig}, "signature-invalid"),
            }
            refusal_results = {}
            for name, (variant, expected) in refusals.items():
                proposal = {**common, **variant, "mode": "on"}
                result = exec_json(peer, TRANSFER_CLIENT, "replication_fixture.py", "transfer", proposal)
                absent = exec_json(peer, VALIDATOR_CLIENT, "destination_validator.py", "absent",
                                   tag=variant["tag"])
                refusal_results[name] = {
                    "expected_decision": expected,
                    "decision_matches": result.get("decision") == expected and result.get("written") is False,
                    "destination_tag_absent": absent.get("status") == 404 and
                    absent.get("checks", {}).get("destination_tag_absent") is True,
                }
            refusal_ok = all(row["decision_matches"] and row["destination_tag_absent"]
                             for row in refusal_results.values())
            lab.check("green", "Control-on refuses invalid lineage without destination writes",
                      refusal_ok, refusal_results)

            (lab.evidence / "cross-cluster-provenance.json").write_text(json.dumps({
                "fixture": "SAF-K8S-0910-024",
                "normalized": {
                    "baseline": baseline,
                    "control_on": enforced,
                    "refusals": {name: {"decision_matches": row["decision_matches"],
                                        "destination_tag_absent": row["destination_tag_absent"]}
                                 for name, row in refusal_results.items()},
                },
            }, indent=2, sort_keys=True) + "\n")
