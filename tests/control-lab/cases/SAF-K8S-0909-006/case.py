"""Live lifecycle checks for a fixture-owned SQLite vector index on a PVC."""
import importlib.util
import json
from pathlib import Path
import sys

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
NS = "saf-test"
NAME = "fixture-vector-index"
PVC = "fixture-vector-index-data"
APPROVAL = "fixture-vector-index-approval"
CODE = "fixture-vector-index-code"
APPROVED = {
    "generation": "v1-approved",
    "model_version": "synthetic-hash-embed-v1",
    "documents": [
        {"id": "doc-cedar", "text": "cedar fixture token is amber", "vector": [1.0, 0.0, 0.0]},
        {"id": "doc-maple", "text": "maple fixture token is blue", "vector": [0.0, 1.0, 0.0]},
        {"id": "doc-birch", "text": "birch fixture token is green", "vector": [0.0, 0.0, 1.0]},
    ],
    "document_count": 3,
    "corpus_sha256": "9cbab62c7c8680f6c3404460dba18bb72c720bb379d97f7f82fa49744788dcf7",
    "known_query": [1.0, 0.0, 0.0],
    "expected_top_id": "doc-cedar",
}
SCOPE = (
    "A temporary Kind pod stores an owned synthetic vector index in SQLite on a PVC. The case "
    "creates a versioned approved snapshot and a benign altered snapshot, observes an unsafe "
    "activation fail the known-vector query, then verifies activation blocking against separately "
    "mounted approved metadata while preserving the live index. The snapshot persists across Pod replacement. "
    "It performs an approved-source "
    "rebuild and known-query check, then unlinks one named retired fixture generation."
)


def create(lab, kind, name, api="v1", **fields):
    return lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})


def load_runtime(lab):
    source = HERE.parent / "SAF-K8S-0908-001" / "case.py"
    if not source.is_file():
        lab.block("The adjacent pinned runtime helper is unavailable")
    spec = importlib.util.spec_from_file_location("saf_k8s_0908_001_runtime", source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.load_runtime(lab)


def exec_fixture(lab, operation):
    result = lab.kubectl("exec", NAME, "--", "python", "/fixture/index_fixture.py", operation, timeout=35)
    return json.loads(result.stdout)


def run(lab):
    image = load_runtime(lab)
    create(lab, "ConfigMap", APPROVAL, immutable=True,
           data={"approved.json": json.dumps(APPROVED, sort_keys=True, separators=(",", ":"))})
    create(lab, "ConfigMap", CODE, immutable=True,
           data={"index_fixture.py": (HERE / "index_fixture.py").read_text()})
    create(lab, "PersistentVolumeClaim", PVC, spec={
        "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}
    })
    def start_index():
        unit = container("index", image=image, imagePullPolicy="Never",
                         command=["sleep", "3600"], volumeMounts=[
                             {"name": "code", "mountPath": "/fixture", "readOnly": True},
                             {"name": "approval", "mountPath": "/approval", "readOnly": True},
                             {"name": "index", "mountPath": "/data"},
                         ])
        request = pod(NAME, [unit], automountServiceAccountToken=False, volumes=[
            {"name": "code", "configMap": {"name": CODE}},
            {"name": "approval", "configMap": {"name": APPROVAL, "defaultMode": 0o444}},
            {"name": "index", "persistentVolumeClaim": {"claimName": PVC}},
        ], securityContext={"fsGroup": 65534})
        request["spec"]["containers"][0]["securityContext"]["readOnlyRootFilesystem"] = True
        lab.create(request)
        ready(lab, NAME)

        lab.kubectl("wait", "--for=jsonpath={.status.phase}=Bound", "pvc/" + PVC, "--timeout=15s")

    start_index()
    prepared = exec_fixture(lab, "prepare")
    lab.kubectl("delete", "pod", NAME, "--wait=true", timeout=45)
    start_index()
    retained = exec_fixture(lab, "inspect-retained")
    red = exec_fixture(lab, "red")
    red_ok = (prepared["active_initial"] == "doc-cedar" and prepared["retired_generation_present"]
              and retained == {"approved_snapshot_retained": True, "known_query_retained": True}
              and red["unsafe_activation_occurred"] and red["altered_snapshot_query_wrong"]
              and red["integrity_still_passes"] and red["after"]["active_query"] != "doc-cedar")
    lab.check("red", "A benign altered but structurally valid snapshot can be activated without observed verification",
              red_ok, {"prepare": prepared, "retained_after_pod_replacement": retained, "unsafe_activation": red})

    restored = exec_fixture(lab, "restore-approved")
    green = exec_fixture(lab, "guard-altered")
    green_ok = (not restored["activation_blocked"] and all(restored["approved_checks"].values())
                and restored["restored_query"] == APPROVED["expected_top_id"]
                and green["altered_snapshot_integrity_ok"]
                and green["approved_metadata_rejects_altered_snapshot"]
                and green["observed_query_rejects_altered_snapshot"]
                and green["activation_blocked"] and green["active_file_unchanged"]
                and green["live_query_preserved"])
    lab.check("green", "Approved metadata and a known-vector observation block altered activation and preserve live state",
              green_ok, {"approved_restore": restored, "guard": green})

    rebuilt = exec_fixture(lab, "rebuild-approved")
    retired = exec_fixture(lab, "retire")
    positive_ok = (not rebuilt["activation_blocked"] and all(rebuilt["active_checks"].values())
                   and rebuilt["observed_query"] == APPROVED["expected_top_id"]
                   and rebuilt["model_version"] == APPROVED["model_version"]
                   and retired["fixture_generation_existed"]
                   and retired["fixture_generation_absent_after_unlink"]
                   and retired["active_generation_preserved"]
                   and retired["active_query"] == APPROVED["expected_top_id"])
    lab.check("positive", "Controlled approved-source rebuild retrieves the known result and retires only its fixture generation",
              positive_ok, {"rebuild": rebuilt, "retirement": retired})

    (lab.evidence / "vector-index-lifecycle.json").write_text(json.dumps({
        "scope": "owned-benign-synthetic-sqlite-index",
        "approved_generation": APPROVED["generation"],
        "approved_model_version": APPROVED["model_version"],
        "red": red, "green": {"restore": restored, "guard": green},
        "positive": {"rebuild": rebuilt, "retirement": retired},
    }, sort_keys=True, indent=2) + "\n")
