"""Verify initial enrollment approval for one exact cross-cluster registry pair."""
import importlib.util
import json
from pathlib import Path
import tempfile
import time

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
NS = "saf-test"
CODE = "fixture-endpoint-enrollment-code"
REQUEST = "fixture-endpoint-enrollment-request"
APPROVAL = "fixture-endpoint-enrollment-approval"
ENROLLER = "fixture-endpoint-enroller"
APPROVER = "fixture-endpoint-approver"
COPIER = "fixture-endpoint-copier"
OBSERVER = "fixture-endpoint-observer"
SOURCE_OWNER = "fixture-source-endpoint-owner"
DESTINATION_CLAIM_WRITER = "fixture-destination-claim-writer"
PEER_REQUEST = "fixture-peer-service-request"
PEER_APPROVAL = "fixture-peer-service-approval"
PEER_POLICY = "fixture-peer-service-policy"
SOURCE_CLAIM = "fixture-source-owner-claim"
DESTINATION_CLAIM = "fixture-destination-owner-claim"
SOURCE = "fixture-enrollment-source"
APPROVED = "fixture-enrollment-approved"
UNAPPROVED = "fixture-enrollment-unapproved"
REPOSITORY = "fixtures/saf-endpoint-enrollment"
TAG = "inert-v1"
RBAC = "rbac.authorization.k8s.io/v1"
REGISTRY = ("docker.io/library/registry:3.0.0@sha256:"
            "6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e")
SCOPE = (
    "An owned source Kind API server and a second owned peer Kind API server host a source registry "
    "and two fixed candidate destination registries. The same source-to-approved-destination pair "
    "first transfers the inert artifact through an open baseline. After destination reset, the "
    "governed copier reads enrollment records from the source Kubernetes API and compares the exact "
    "endpoint pair. A peer-cluster ServiceAccount with get access to only the approved destination "
    "Service provides a current UID observation over a case-owned TLS endpoint. A separate approver "
    "binds that UID to the pair; replacing the Service invalidates the approval until refreshed. "
    "This tests one governed copier path, not third-party endpoint ownership or all replication routes."
)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Required adjacent fixture helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def create(lab, kind, name, api="v1", **fields):
    return lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})


def registry_pod(name):
    unit = container(
        "registry", image=REGISTRY, imagePullPolicy="IfNotPresent",
        ports=[{"containerPort": 5000}],
        env=[{"name": "REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY", "value": "/tmp/registry"}],
    )
    del unit["command"]
    unit["readinessProbe"] = {"httpGet": {"port": 5000, "path": "/v2/"}, "periodSeconds": 1}
    definition = pod(name, [unit], automountServiceAccountToken=False, terminationGracePeriodSeconds=2)
    definition["metadata"]["labels"] = {"app": name}
    return definition


def registry(lab, name, peer=None):
    definition = registry_pod(name)
    spec = {"selector": {"app": name}, "ports": [{"port": 5000, "targetPort": 5000}]}
    if peer is None:
        lab.create(definition)
        create(lab, "Service", name, spec=spec)
        ready(lab, name)
        return None
    spec["type"] = "NodePort"
    service = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name}, "spec": spec}
    peer("create", "-f", "-", payload=json.dumps(definition))
    result = peer("create", "-f", "-", "-o", "json", payload=json.dumps(service))
    peer("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=90s", timeout=100)
    return json.loads(result.stdout)["spec"]["ports"][0]["nodePort"]


def accounts(lab):
    for actor in (ENROLLER, APPROVER, COPIER, OBSERVER, SOURCE_OWNER, DESTINATION_CLAIM_WRITER):
        create(lab, "ServiceAccount", actor)
    rules = {
        ENROLLER: [(REQUEST, ["get", "patch"]), (PEER_REQUEST, ["get", "patch"])],
        APPROVER: [(REQUEST, ["get"]), (APPROVAL, ["get", "patch"]),
                   (PEER_REQUEST, ["get"]), (PEER_APPROVAL, ["get", "patch"]),
                   (PEER_POLICY, ["get", "patch"])],
        COPIER: [(APPROVAL, ["get"]), (PEER_APPROVAL, ["get"]), (PEER_POLICY, ["get"]),
                 (SOURCE_CLAIM, ["get"]), (DESTINATION_CLAIM, ["get"])],
        OBSERVER: [(REQUEST, ["get"]), (APPROVAL, ["get"]),
                   (SOURCE_CLAIM, ["get"]), (DESTINATION_CLAIM, ["get"])],
        SOURCE_OWNER: [(SOURCE_CLAIM, ["get", "patch"])],
        DESTINATION_CLAIM_WRITER: [(DESTINATION_CLAIM, ["get", "patch"])],
    }
    for actor, grants in rules.items():
        permissions = [{"apiGroups": [""], "resources": ["configmaps"],
                        "resourceNames": [name], "verbs": verbs}
                       for name, verbs in grants]
        create(lab, "Role", actor, RBAC, rules=permissions)
        create(lab, "RoleBinding", actor, RBAC,
               roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": actor},
               subjects=[{"kind": "ServiceAccount", "name": actor, "namespace": NS}])


def runner(lab, image, actor, env, peer_route):
    unit = container(
        "fixture", image=image, imagePullPolicy="Never", command=["sleep", "360"],
        volumeMounts=[{"name": "code", "mountPath": "/fixture", "readOnly": True},
                      {"name": "peer-owner-ca", "mountPath": "/peer-owner", "readOnly": True}],
        env=env + [
            {"name": "PEER_OWNER_HOST", "value": peer_route["host"]},
            {"name": "PEER_OWNER_PORT", "value": str(peer_route["port"])},
        ],
    )
    lab.create(pod(actor, [unit], serviceAccountName=actor,
                   hostAliases=[{"ip": peer_route["node_ip"], "hostnames": [peer_route["host"]]}],
                   volumes=[{"name": "code", "configMap": {"name": CODE}},
                            {"name": "peer-owner-ca", "configMap": {
                                "name": "fixture-destination-owner-ca"}}]))
    ready(lab, actor)


def replace_destination_service(peer, port):
    """Replace only the enrolled destination Service and its inert registry Pod."""
    peer("delete", "pod", APPROVED, "--ignore-not-found=true", "--wait=true",
         "--timeout=35s", timeout=45)
    peer("delete", "service", APPROVED, "--wait=true", "--timeout=30s", timeout=40)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        result = peer("get", "service", APPROVED, "-o", "json", allow_failure=True)
        if result.returncode and "NotFound" in result.stderr:
            break
        time.sleep(0.2)
    else:
        raise RuntimeError("Owned destination Service did not clear before replacement")
    service = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": APPROVED},
        "spec": {"type": "NodePort", "selector": {"app": APPROVED},
                 "ports": [{"port": 5000, "targetPort": 5000, "nodePort": int(port)}]}}
    peer("create", "-f", "-", payload=json.dumps(service))
    peer("create", "-f", "-", payload=json.dumps(registry_pod(APPROVED)))
    peer("wait", "--for=condition=Ready", f"pod/{APPROVED}", "--timeout=75s", timeout=85)
    current = json.loads(peer("get", "service", APPROVED, "-o", "json").stdout)
    return current["metadata"]["uid"], current["spec"]["ports"][0]["nodePort"]


def run(lab):
    runtime = load(HERE.parent / "SAF-K8S-0908-001" / "case.py", "saf_enrollment_runtime")
    bridge = load(HERE / "owned_peer.py", "saf_enrollment_owned_peer")
    fixture = load(HERE / "enrollment_fixture.py", "saf_endpoint_enrollment_program")
    peer_identity = load(HERE / "peer_activation.py", "saf_endpoint_peer_identity")
    image = runtime.load_runtime(lab)
    digest = fixture.MANIFEST_DIGEST
    with bridge.owned_peer(lab, image) as (peer, peer_ip):
        create(lab, "ConfigMap", CODE, immutable=True,
               data={"enrollment_fixture.py": (HERE / "enrollment_fixture.py").read_text()})
        accounts(lab)
        create(lab, "ConfigMap", REQUEST, data={})
        create(lab, "ConfigMap", APPROVAL, data={})
        create(lab, "ConfigMap", SOURCE_CLAIM, data={})
        create(lab, "ConfigMap", DESTINATION_CLAIM, data={})
        create(lab, "ConfigMap", PEER_REQUEST, data={})
        create(lab, "ConfigMap", PEER_APPROVAL, data={})
        create(lab, "ConfigMap", PEER_POLICY, data={"mode": "disabled"})
        registry(lab, SOURCE)
        approved_port = registry(lab, APPROVED, peer)
        unapproved_port = registry(lab, UNAPPROVED, peer)
        with tempfile.TemporaryDirectory(prefix="saf-0910-031-peer-owner-") as temporary:
            peer_route = peer_identity.install(lab, peer, image, peer_ip, approved_port,
                                               Path(temporary))
        endpoint_map = fixture.endpoint_map(peer_ip, approved_port, unapproved_port)
        source_uid = lab.kubectl("get", "service", SOURCE, "-o", "jsonpath={.metadata.uid}").stdout.strip()
        destination_uid = json.loads(peer("get", "service", APPROVED, "-o", "json").stdout)["metadata"]["uid"]
        if not source_uid or not destination_uid or source_uid == destination_uid:
            lab.block("The two approved registry Services must have distinct Kubernetes identities")
        env = [{"name": name, "value": str(value)} for name, value in
               (("PEER_IP", peer_ip), ("APPROVED_PORT", approved_port), ("UNAPPROVED_PORT", unapproved_port),
                ("SOURCE_SERVICE_UID", source_uid), ("DESTINATION_SERVICE_UID", destination_uid))]
        peer_route["node_ip"] = peer_ip
        for actor in (ENROLLER, APPROVER, COPIER, OBSERVER, SOURCE_OWNER, DESTINATION_CLAIM_WRITER):
            runner(lab, image, actor, env, peer_route)

        def invoke(actor, operation):
            result = lab.kubectl("exec", actor, "--", "python", "/fixture/enrollment_fixture.py",
                                 "call", operation, timeout=40)
            return json.loads(result.stdout)

        if invoke(OBSERVER, "wait-ready") != {"ready": True}:
            lab.block("The three owned Distribution endpoints did not become ready")
        seeded = invoke(COPIER, "seed")
        source_state = invoke(OBSERVER, "observe-source")
        if seeded.get("digest") != digest or source_state.get("digest") != digest:
            lab.block("The observer could not verify the deterministic source manifest")

        baseline = invoke(COPIER, "baseline-open-copy")
        baseline_state = invoke(OBSERVER, "observe-approved")
        red = {"open_path_writes_same_pair": baseline.get("decision") == "baseline-written",
               "observer_reads_locked_manifest": baseline_state.get("digest") == digest}
        lab.check("red", "Without enrollment enforcement the exact candidate pair transfers the artifact",
                  all(red.values()), red)

        # Recreate the same NodePort destination with fresh ephemeral registry storage.
        peer("delete", "pod", APPROVED, "--wait=true", "--timeout=38s", timeout=45)
        peer("create", "-f", "-", payload=json.dumps(registry_pod(APPROVED)))
        peer("wait", "--for=condition=Ready", f"pod/{APPROVED}", "--timeout=75s", timeout=85)
        if invoke(OBSERVER, "wait-ready") != {"ready": True}:
            lab.block("The exact destination Service did not return after the owned Pod reset")
        if invoke(OBSERVER, "observe-approved") != {"digest": None, "status": 404}:
            lab.block("Approved destination reset did not remove the baseline artifact")

        missing = invoke(COPIER, "governed-copy-approved")
        missing_state = invoke(OBSERVER, "observe-approved")
        wrong_request = invoke(ENROLLER, "submit-wrong-pair")
        wrong_approval = invoke(APPROVER, "approver-approve-request")
        wrong_record = invoke(OBSERVER, "observe-approval").get("pair")
        wrong_pair = invoke(COPIER, "governed-copy-approved")
        wrong_state = invoke(OBSERVER, "observe-approved")
        wrong_source_request = invoke(ENROLLER, "submit-wrong-source")
        wrong_source_approval = invoke(APPROVER, "approver-approve-request")
        wrong_source_record = invoke(OBSERVER, "observe-approval").get("pair")
        wrong_source = invoke(COPIER, "governed-copy-approved")
        wrong_source_state = invoke(OBSERVER, "observe-approved")
        wrong_role = invoke(ENROLLER, "try-enroll-wrong-role")
        record_after_wrong_role = invoke(OBSERVER, "observe-approval").get("pair")

        normalized_wrong = {
            "source": "source" if wrong_record and
            wrong_record.get("source") == endpoint_map["source"] else None,
            "destination": "unapproved" if wrong_record and
            wrong_record.get("destination") == endpoint_map["unapproved"] else None,
        }
        green = {
            "missing_approval_denied": missing == {"decision": "denied-missing-approval"}
            and missing_state == {"digest": None, "status": 404},
            "distinct_approver_enrolled_the_submitted_wrong_pair":
                wrong_request == {"http_status": 200} and wrong_approval == {"http_status": 200}
                and normalized_wrong == {"source": "source", "destination": "unapproved"},
            "approved_pair_mismatch_denied_without_transfer":
                wrong_pair == {"decision": "denied-endpoint-pair"}
                and wrong_state == {"digest": None, "status": 404},
            "approved_different_source_is_denied_without_transfer":
                wrong_source_request == wrong_source_approval == {"http_status": 200}
                and wrong_source_record == {"source": endpoint_map["unapproved"],
                                            "destination": endpoint_map["approved"]}
                and wrong_source == {"decision": "denied-endpoint-pair"}
                and wrong_source_state == {"digest": None, "status": 404},
            "enroller_cannot_write_approval": wrong_role == {"http_status": 403}
                and record_after_wrong_role == wrong_source_record,
        }
        lab.check("green", "Missing approval, a mismatched endpoint pair, and enrollment by the wrong role are refused",
                  all(green.values()), green)

        # An exact independent approval cannot activate copying until both endpoint owners
        # attest the fixed case-owned endpoint identities through separately scoped records.
        exact_request_before_claims = invoke(ENROLLER, "submit-exact-pair")
        exact_approval_before_claims = invoke(APPROVER, "approver-approve-request")
        before_claims = invoke(COPIER, "governed-copy-approved")
        empty_before_claims = invoke(OBSERVER, "observe-approved")
        destination_claim = invoke(DESTINATION_CLAIM_WRITER, "claim-destination-endpoint")
        wrong_uid_claim = invoke(SOURCE_OWNER, "claim-source-wrong-uid")
        wrong_uid_blocked = invoke(COPIER, "governed-copy-approved")
        still_empty = invoke(OBSERVER, "observe-approved")
        source_claim = invoke(SOURCE_OWNER, "claim-source-endpoint")
        unauthorized_claim = invoke(ENROLLER, "claim-source-endpoint")
        claims = invoke(OBSERVER, "observe-owner-claims")
        destination_uid = json.loads(peer("get", "service", APPROVED, "-o", "json").stdout)["metadata"]["uid"]
        expected_claims = {
            "source": {"endpoint": endpoint_map["source"], "registry": "source", "service_uid": source_uid},
            "destination": {"endpoint": endpoint_map["approved"],
                            "registry": "approved-destination", "service_uid": destination_uid},
        }
        ownership = {
            "exact_pair_approval_alone_does_not_activate":
                exact_request_before_claims == {"http_status": 200}
                and exact_approval_before_claims == {"http_status": 200}
                and before_claims == {"decision": "denied-missing-endpoint-ownership"}
                and empty_before_claims == {"digest": None, "status": 404},
            "wrong_service_uid_leaves_destination_empty":
                wrong_uid_claim == {"http_status": 200}
                and wrong_uid_blocked == {"decision": "denied-missing-endpoint-ownership"}
                and still_empty == {"digest": None, "status": 404},
            "distinct_source_and_destination_owners_submit_exact_claims":
                source_claim == destination_claim == {"http_status": 200}
                and claims == expected_claims,
            "unrelated_enroller_cannot_write_endpoint_claim":
                unauthorized_claim == {"http_status": 403}
                and invoke(OBSERVER, "observe-owner-claims") == expected_claims,
        }
        lab.check("ownership", "Exact authorized pair remains inactive until both scoped endpoint owners prove the fixture pair",
                  all(ownership.values()), ownership)

        exact_request = invoke(ENROLLER, "submit-exact-pair")
        exact_approval = invoke(APPROVER, "approver-approve-request")
        approved_record = invoke(OBSERVER, "observe-approval").get("pair")
        exact_pair = {"source": endpoint_map["source"], "destination": endpoint_map["approved"]}
        copied = invoke(COPIER, "governed-copy-approved")
        destination_state = invoke(OBSERVER, "observe-approved")
        positive = {
            "enroller_submitted_and_distinct_approver_approved_exact_pair":
                exact_request == {"http_status": 200} and exact_approval == {"http_status": 200}
                and approved_record == exact_pair,
            "trusted_pair_allows_real_distribution_transfer":
                copied == {"decision": "allowed", "digest": digest}
                and destination_state == {"digest": digest, "status": 200},
        }
        lab.check("positive", "The separately approved exact source and destination pair transfers the inert artifact",
                  all(positive.values()), positive)

        # Recheck live destination ownership through the peer-cluster ServiceAccount.
        initial_claim = invoke(DESTINATION_CLAIM_WRITER, "claim-destination-endpoint")
        initial_request = invoke(ENROLLER, "submit-peer-approval-request")
        initial_approval = invoke(APPROVER, "approve-peer-service")
        peer_gate_enabled = invoke(APPROVER, "enable-peer-binding")
        attempted_disable = invoke(APPROVER, "try-disable-peer-binding")
        peer_old_uid = json.loads(peer("get", "service", APPROVED, "-o", "json").stdout)["metadata"]["uid"]
        replacement_uid, replacement_port = replace_destination_service(peer, approved_port)
        replacement = json.loads(peer("get", "service", APPROVED, "-o", "json").stdout)
        replacement_uid = replacement["metadata"]["uid"]
        empty_after_replacement = invoke(OBSERVER, "observe-approved-after-replacement")
        stale_copy = invoke(COPIER, "governed-copy-approved")
        empty_after_stale = invoke(OBSERVER, "observe-approved-after-replacement")
        stale = {
            "peer_workload_read_exact_service_and_refused_other_service":
                initial_claim == {"http_status": 200}
                and initial_request == {"http_status": 200}
                and initial_approval == {"http_status": 200}
                and peer_gate_enabled == {"http_status": 200, "enabled_immutable": True}
                and attempted_disable == {"patch_status": 422, "remains_enabled": True},
            "same_registry_endpoint_now_has_a_new_peer_api_uid":
                bool(peer_old_uid) and replacement_uid != peer_old_uid
                and replacement_port == approved_port
                and replacement["spec"]["ports"][0]["nodePort"] == approved_port,
            "old_uid_approval_denied_without_registry_write":
                stale_copy == {"decision": "denied-stale-peer-approval"}
                and empty_after_replacement == {"digest": None, "status": 404,
                                                "registry_v2_status": 200}
                and empty_after_stale == {"digest": None, "status": 404,
                                          "registry_v2_status": 200},
        }
        refreshed_claim = invoke(DESTINATION_CLAIM_WRITER, "claim-destination-endpoint")
        refreshed_request = invoke(ENROLLER, "submit-peer-approval-request")
        refreshed_approval = invoke(APPROVER, "approve-peer-service")
        refreshed_copy = invoke(COPIER, "governed-copy-approved")
        refreshed_state = invoke(OBSERVER, "observe-approved")
        refreshed = {
            "fresh_peer_observation_requires_new_approval":
                refreshed_claim == {"http_status": 200}
                and refreshed_request == {"http_status": 200}
                and refreshed_approval == {"http_status": 200},
            "refreshed_peer_approval_allows_expected_inert_transfer":
                refreshed_copy == {"decision": "allowed", "digest": digest}
                and refreshed_state == {"digest": digest, "status": 200},
        }
        lab.check("peer-binding", "Peer workload identity and current Service UID gate destination reactivation",
                  all(stale.values()) and all(refreshed.values()), {**stale, **refreshed})

        # Omit bridge addresses, NodePorts, Kubernetes UIDs, and API metadata from stable evidence.
        evidence = {
            "scope": SCOPE,
            "artifact": {"repository": REPOSITORY, "tag": TAG, "digest": digest},
            "pair": {"baseline": ["source", "approved"],
                     "wrong_enrollment": ["source", "unapproved"],
                     "approved": ["source", "approved"]},
            "red": red,
            "green": green,
            "ownership": ownership,
            "positive": positive,
            "peer_binding": {**stale, **refreshed},
        }
        (lab.evidence / "endpoint-enrollment-observations.json").write_text(
            json.dumps(evidence, sort_keys=True, indent=2) + "\n")
