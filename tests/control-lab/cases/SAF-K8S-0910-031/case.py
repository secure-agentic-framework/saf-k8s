"""Verify initial enrollment approval for one exact cross-cluster registry pair."""
import importlib.util
import json
from pathlib import Path

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
    "governed copier reads an enrollment record from the source Kubernetes API and compares both "
    "exact endpoint strings. A distinct approver account is the only principal allowed to write "
    "that record; a separate observer verifies the record and Distribution manifest digest."
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
    for actor in (ENROLLER, APPROVER, COPIER, OBSERVER):
        create(lab, "ServiceAccount", actor)
    rules = {
        ENROLLER: [(REQUEST, ["get", "patch"])],
        APPROVER: [(REQUEST, ["get"]), (APPROVAL, ["get", "patch"])],
        COPIER: [(APPROVAL, ["get"])],
        OBSERVER: [(REQUEST, ["get"]), (APPROVAL, ["get"])],
    }
    for actor, grants in rules.items():
        permissions = [{"apiGroups": [""], "resources": ["configmaps"],
                        "resourceNames": [name], "verbs": verbs}
                       for name, verbs in grants]
        create(lab, "Role", actor, RBAC, rules=permissions)
        create(lab, "RoleBinding", actor, RBAC,
               roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": actor},
               subjects=[{"kind": "ServiceAccount", "name": actor, "namespace": NS}])


def runner(lab, image, actor, env):
    unit = container(
        "fixture", image=image, imagePullPolicy="Never", command=["sleep", "360"],
        volumeMounts=[{"name": "code", "mountPath": "/fixture", "readOnly": True}],
        env=env,
    )
    lab.create(pod(actor, [unit], serviceAccountName=actor,
                   volumes=[{"name": "code", "configMap": {"name": CODE}}]))
    ready(lab, actor)


def run(lab):
    runtime = load(HERE.parent / "SAF-K8S-0908-001" / "case.py", "saf_enrollment_runtime")
    bridge = load(HERE.parent / "SAF-K8S-0910-020" / "owned_peer.py", "saf_enrollment_owned_peer")
    fixture = load(HERE / "enrollment_fixture.py", "saf_endpoint_enrollment_program")
    image = runtime.load_runtime(lab)
    digest = fixture.MANIFEST_DIGEST
    with bridge.owned_peer(lab, image) as (peer, peer_ip):
        create(lab, "ConfigMap", CODE, immutable=True,
               data={"enrollment_fixture.py": (HERE / "enrollment_fixture.py").read_text()})
        accounts(lab)
        create(lab, "ConfigMap", REQUEST, data={})
        create(lab, "ConfigMap", APPROVAL, data={})
        registry(lab, SOURCE)
        approved_port = registry(lab, APPROVED, peer)
        unapproved_port = registry(lab, UNAPPROVED, peer)
        endpoint_map = fixture.endpoint_map(peer_ip, approved_port, unapproved_port)
        env = [{"name": name, "value": str(value)} for name, value in
               (("PEER_IP", peer_ip), ("APPROVED_PORT", approved_port),
                ("UNAPPROVED_PORT", unapproved_port))]
        for actor in (ENROLLER, APPROVER, COPIER, OBSERVER):
            runner(lab, image, actor, env)

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

        # Omit bridge addresses, NodePorts, Kubernetes UIDs, and API metadata from stable evidence.
        evidence = {
            "scope": SCOPE,
            "artifact": {"repository": REPOSITORY, "tag": TAG, "digest": digest},
            "pair": {"baseline": ["source", "approved"],
                     "wrong_enrollment": ["source", "unapproved"],
                     "approved": ["source", "approved"]},
            "red": red,
            "green": green,
            "positive": positive,
        }
        (lab.evidence / "endpoint-enrollment-observations.json").write_text(
            json.dumps(evidence, sort_keys=True, indent=2) + "\n")
