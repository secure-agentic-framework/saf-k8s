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
WITHDRAWN_CLIENT = "fixture-provenance-withdrawn-client"
SOURCE_CODE = "fixture-provenance-source-code"
PEER_CODE = "fixture-provenance-peer-code"
PEER_TRUST = "fixture-provenance-peer-trust"
REPO = "fixtures/model"
APPROVED_SIGNER = "fixture://model-release-signer"
UNAPPROVED_SIGNER = "fixture://model-release-signer-unapproved"
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
    "compares exact source bytes and digests, and verifies the signature against a separately published "
    "peer trust policy. A grouped addition rejects a valid unapproved signer and a previously approved "
    "signer after the fixture trust policy records withdrawal."
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


def statement(created=NOW, subject=None, signer=APPROVED_SIGNER):
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
            "saf_signing_identity": signer,
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


def code_map(lab, name, files, immutable=True):
    create(lab, {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name},
                 "immutable": immutable, "data": files})


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
        "source-route.json": json.dumps(source_route),
    })
    trust_policy = {"version": 1, "signers": {APPROVED_SIGNER: {
        "state": "active", "public_key_file": "approved-public.pem",
        "public_key_sha256": sha256(public_pem).hexdigest(),
    }}}
    code_map(peer, PEER_TRUST, {
        "approved-public.pem": public_pem.decode("ascii"),
        "trusted-signers.json": json.dumps(trust_policy, sort_keys=True, separators=(",", ":")),
    }, immutable=False)


def create_clients(lab, peer, image):
    for name, code_name in ((SOURCE_CLIENT, SOURCE_CODE),
                            (TRANSFER_CLIENT, PEER_CODE),
                            (VALIDATOR_CLIENT, PEER_CODE)):
        client_kube = peer if name != SOURCE_CLIENT else source_kubectl(lab)
        mounts = [{"name": "fixture", "mountPath": "/fixture", "readOnly": True}]
        volumes = [{"name": "fixture", "configMap": {"name": code_name}}]
        if name != SOURCE_CLIENT:
            mounts.append({"name": "trust", "mountPath": "/trust", "readOnly": True})
            volumes.append({"name": "trust", "configMap": {"name": PEER_TRUST}})
        client(client_kube, name, image, ["sleep", "360"], mounts, volumes)
        wait(client_kube, name)


def create_peer_transfer_client(peer, name, image):
    mounts = [{"name": "fixture", "mountPath": "/fixture", "readOnly": True},
              {"name": "trust", "mountPath": "/trust", "readOnly": True}]
    volumes = [{"name": "fixture", "configMap": {"name": PEER_CODE}},
               {"name": "trust", "configMap": {"name": PEER_TRUST}}]
    client(peer, name, image, ["sleep", "360"], mounts, volumes)
    wait(peer, name)


def peer_trust_state(peer):
    value = json.loads(peer("get", "configmap", PEER_TRUST, "-o", "json").stdout)
    policy = json.loads(value.get("data", {}).get("trusted-signers.json", "{}"))
    signer = policy.get("signers", {}).get(APPROVED_SIGNER, {})
    return value.get("metadata", {}).get("resourceVersion"), policy, signer


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
            pod_code_config(lab, peer, public_pem, {"host": node_address, "port": source_port})
            published_rv, initial_policy, initial_signer = peer_trust_state(peer)
            approved_fingerprint = sha256(public_pem).hexdigest()
            trust_published_before_sign = (
                bool(published_rv) and initial_policy.get("version") == 1
                and initial_signer.get("state") == "active"
                and initial_signer.get("public_key_sha256") == approved_fingerprint)
            statement_b64, signature_b64 = sign(lab, key_path, key_dir, "source", statement())
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

            # A second, valid signer demonstrates that cryptographic validity alone is not trust.
            unapproved_private = Path(key_dir) / "unapproved-signing-key.pem"
            unapproved_public_path = Path(key_dir) / "unapproved-public.pem"
            lab.command("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                        "-out", str(unapproved_private), timeout=30)
            lab.command("openssl", "pkey", "-in", str(unapproved_private), "-pubout",
                        "-out", str(unapproved_public_path), timeout=20)
            unapproved_public = unapproved_public_path.read_bytes()
            unapproved_statement = statement(signer=UNAPPROVED_SIGNER)
            unapproved_statement_b64, unapproved_signature_b64 = sign(
                lab, unapproved_private, key_dir, "unapproved", unapproved_statement)
            unapproved_signature_path = Path(key_dir) / "unapproved.sig"
            unapproved_payload_path = Path(key_dir) / "unapproved.json"
            unapproved_verify = lab.command(
                "openssl", "dgst", "-sha256", "-verify", str(unapproved_public_path),
                "-signature", str(unapproved_signature_path), str(unapproved_payload_path), timeout=20)
            unapproved_signature_valid = "Verified OK" in unapproved_verify.stdout
            unapproved_seed = exec_json(source_command, SOURCE_CLIENT, "replication_fixture.py", "seed", {
                "source_host": source,
                "source_tag": "unapproved",
                "statement_b64": unapproved_statement_b64,
                "signature_b64": unapproved_signature_b64,
                "public_pem_b64": base64.b64encode(unapproved_public).decode(),
            })
            unapproved_transfer = exec_json(peer, TRANSFER_CLIENT, "replication_fixture.py", "transfer", {
                "mode": "on", "tag": "refuse-unapproved", "source_tag": "unapproved",
                "expected_source_digest": unapproved_seed.get("source_digest"),
                "statement_b64": unapproved_statement_b64,
                "signature_b64": unapproved_signature_b64,
            })
            unapproved_absent = exec_json(peer, VALIDATOR_CLIENT, "destination_validator.py", "absent",
                                          tag="refuse-unapproved")

            # Change only the peer trust status, observe the API resourceVersion/state transition,
            # and use a fresh verifier Pod that mounts the withdrawn policy for a later replay.
            current_rv, current_policy, current_signer = peer_trust_state(peer)
            withdrawn_policy = json.loads(json.dumps(current_policy))
            withdrawn_policy["signers"][APPROVED_SIGNER]["state"] = "withdrawn"
            peer("patch", "configmap", PEER_TRUST, "--type=merge", "-p",
                 json.dumps({"data": {"trusted-signers.json": json.dumps(
                     withdrawn_policy, sort_keys=True, separators=(",", ":"))}}), timeout=20)
            withdrawn_rv, observed_policy, observed_signer = peer_trust_state(peer)
            observed_withdrawal = (
                bool(current_rv) and withdrawn_rv != current_rv
                and current_signer.get("state") == "active"
                and observed_signer.get("state") == "withdrawn"
                and observed_signer.get("public_key_sha256") == approved_fingerprint)
            create_peer_transfer_client(peer, WITHDRAWN_CLIENT, image)
            withdrawn_transfer = exec_json(peer, WITHDRAWN_CLIENT, "replication_fixture.py", "transfer", {
                **common, "mode": "on", "tag": "refuse-withdrawn",
                "statement_b64": source_readback["statement_b64"],
                "signature_b64": source_readback["signature_b64"],
            })
            withdrawn_absent = exec_json(peer, VALIDATOR_CLIENT, "destination_validator.py", "absent",
                                         tag="refuse-withdrawn")
            trust_lifecycle = {
                "approved_peer_policy_preceded_source_signing_and_seed": trust_published_before_sign,
                "active_policy_fingerprint_matches_approved_public_key": initial_signer.get(
                    "public_key_sha256") == approved_fingerprint,
                "approved_transfer_was_accepted": enforced["control_on_transfer_allowed"],
                "unapproved_signature_is_cryptographically_valid": unapproved_signature_valid,
                "valid_unapproved_signer_refused_before_destination_write":
                    unapproved_transfer.get("decision") == "signer-unapproved"
                    and unapproved_transfer.get("written") is False
                    and unapproved_absent.get("status") == 404
                    and unapproved_absent.get("checks", {}).get("destination_tag_absent") is True,
                "withdrawal_transition_observed": observed_withdrawal,
                "withdrawn_signer_refused_on_later_transfer":
                    withdrawn_transfer.get("decision") == "signer-withdrawn"
                    and withdrawn_transfer.get("written") is False
                    and withdrawn_absent.get("status") == 404
                    and withdrawn_absent.get("checks", {}).get("destination_tag_absent") is True,
            }
            lab.check("trust", "Peer trust publication, unapproved signer refusal, and signer withdrawal fail closed",
                      all(trust_lifecycle.values()), trust_lifecycle)

            (lab.evidence / "cross-cluster-provenance.json").write_text(json.dumps({
                "fixture": "SAF-K8S-0910-024",
                "normalized": {
                    "baseline": baseline,
                    "control_on": enforced,
                    "refusals": {name: {"decision_matches": row["decision_matches"],
                                        "destination_tag_absent": row["destination_tag_absent"]}
                                 for name, row in refusal_results.items()},
                    "trust_lifecycle": trust_lifecycle,
                },
            }, indent=2, sort_keys=True) + "\n")
