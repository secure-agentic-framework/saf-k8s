"""Preserve synthetic model-read and training-lineage records across cleanup."""
import hashlib
import json
from pathlib import Path
import time


NAMESPACE = "saf-1005-028-forensic-fixture"
MODEL_RECORD = "saf-1005-028-model-read"
LINEAGE_RECORD = "saf-1005-028-training-lineage"
DECOY_RECORD = "saf-1005-028-unapproved-record"
COLLECTOR = "saf-lab-1005-028-collector"
SCOPE = (
    "A disposable Kubernetes v1.36.1 Kind cluster stores two case-owned ConfigMaps containing "
    "approved mock model access and training records, plus a benign unapproved comparator. The case captures "
    "authorized mock record bytes via the Kubernetes API, writes a completeness manifest and SHA-256 "
    "sidecars to the runner evidence directory, removes the source ConfigMaps to model cleanup, "
    "and independently verifies the captured bytes and required records remain complete. The "
    "dataset digest is a hash of a fabricated label, not dataset content. This does not prove "
    "production collection, audit coverage, evidence-store durability/access controls, chain of "
    "custody, or legal retention."
)


def load_fixture():
    fixture_path = Path(__file__).with_name("fixtures.json")
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    records = fixture.get("records")
    if not isinstance(records, list) or len(records) != 2:
        raise ValueError("Expected exactly two synthetic fixture records")
    by_kind = {record.get("kind"): record for record in records}
    if set(by_kind) != {"model_read", "training_lineage"}:
        raise ValueError("Fixture must contain one model-read and one training-lineage record")
    if any(record.get("approval") != "approved" for record in records):
        raise ValueError("Only approved fixture records are in scope")
    if any("dataset_content" in record or "model_content" in record for record in records):
        raise ValueError("Fixture must not contain model or dataset content")
    digest = by_kind["training_lineage"].get("dataset_digest", "")
    if len(digest) != 71 or not digest.startswith("sha256:") or any(
        char not in "0123456789abcdef" for char in digest[7:]
    ):
        raise ValueError("Training-lineage fixture must use an inert SHA-256 label digest")
    expected_digest = hashlib.sha256(b"saf-k8s synthetic dataset label").hexdigest()
    if digest != f"sha256:{expected_digest}":
        raise ValueError("Training-lineage digest must hash only the documented synthetic label")
    return fixture, by_kind


def config_map(name, record):
    # Compact, deterministic JSON in data.record.json is the raw evidence payload.
    payload = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "labels": {"saf-k8s.example/fixture": "1005-028-synthetic"},
        },
        "data": {"record.json": payload},
    }


def create_fixture(lab, resource):
    return json.loads(lab.kubectl(
        "-n", NAMESPACE, "create", "-f", "-", "-o", "json",
        payload=json.dumps(resource),
    ).stdout)


def role_rules(names):
    return [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"],
             "resourceNames": names}]


def wait_for_collector_grant(lab, name):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        grant = lab.kubectl("--as", COLLECTOR, "-n", NAMESPACE, "auth", "can-i", "get",
                            f"configmap/{name}", allow_failure=True)
        if grant.returncode == 0 and grant.stdout.strip() == "yes":
            return
        time.sleep(0.5)
    lab.block(f"The fixture collector did not receive explicit access to {name}")


def collector_read(lab, name, *, denied=False):
    result = lab.kubectl("--as", COLLECTOR, "-n", NAMESPACE, "get", "configmap", name, "-o", "json",
                         allow_failure=denied)
    if denied:
        denied_by_rbac = (result.returncode != 0 and "(Forbidden)" in result.stderr
                          and COLLECTOR in result.stderr and f'configmaps "{name}"' in result.stderr)
        return denied_by_rbac
    resource = json.loads(result.stdout)
    if resource.get("metadata", {}).get("namespace") != NAMESPACE:
        lab.block("A fixture record was returned from outside the case namespace")
    return resource.get("data", {}).get("record.json", "").encode("utf-8")


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def run(lab):
    fixture, expected = load_fixture()
    lab.kubectl("create", "namespace", NAMESPACE)
    create_fixture(lab, config_map(MODEL_RECORD, expected["model_read"]))
    create_fixture(lab, config_map(LINEAGE_RECORD, expected["training_lineage"]))

    create_fixture(lab, config_map(DECOY_RECORD, {"kind": "synthetic-unapproved-comparator"}))
    if json.loads(lab.kubectl("-n", NAMESPACE, "get", "configmap", LINEAGE_RECORD, "-o", "json").stdout
                  )["metadata"]["name"] != LINEAGE_RECORD:
        lab.block("Required lineage source was not present before the access comparison")
    role_metadata = {"name": COLLECTOR, "namespace": NAMESPACE}
    create_fixture(lab, {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                         "metadata": role_metadata, "rules": role_rules([MODEL_RECORD])})
    create_fixture(lab, {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": role_metadata,
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": COLLECTOR},
        "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": COLLECTOR}],
    })
    wait_for_collector_grant(lab, MODEL_RECORD)
    partial_capture = {"model_read": collector_read(lab, MODEL_RECORD)}
    lineage_denied = collector_read(lab, LINEAGE_RECORD, denied=True)
    decoy_denied_initial = collector_read(lab, DECOY_RECORD, denied=True)
    required_kinds = set(expected)
    missing = sorted(required_kinds - set(partial_capture))
    incomplete = {"captured_record_kinds": sorted(partial_capture), "missing_record_kinds": missing,
                  "lineage_source_present": True, "lineage_access_denied": lineage_denied,
                  "unapproved_record_denied": decoy_denied_initial}
    (lab.evidence / "incomplete-capture.json").write_text(
        json.dumps(incomplete, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    lab.check("red", "Incomplete collector access leaves an existing lineage record uncaptured",
              missing == ["training_lineage"] and lineage_denied and decoy_denied_initial,
              incomplete)

    lab.kubectl("-n", NAMESPACE, "patch", "role", COLLECTOR, "--type=merge", "-p",
                json.dumps({"rules": role_rules([MODEL_RECORD, LINEAGE_RECORD])}))
    wait_for_collector_grant(lab, LINEAGE_RECORD)
    observed = {"model_read": collector_read(lab, MODEL_RECORD),
                "training_lineage": collector_read(lab, LINEAGE_RECORD)}
    unapproved_still_denied = collector_read(lab, DECOY_RECORD, denied=True)
    lab.check("green", "Exact-name read access covers both required records while the unapproved record stays denied",
              unapproved_still_denied and set(observed) == required_kinds
              and observed["model_read"] == partial_capture["model_read"],
              {"collector": COLLECTOR, "captured": sorted(observed),
               "unapproved_record_denied": unapproved_still_denied})

    filenames = {
        "model_read": "model-read-record.json",
        "training_lineage": "training-lineage-record.json",
    }
    digests = {}
    for kind, raw in observed.items():
        (lab.evidence / filenames[kind]).write_bytes(raw)
        digests[kind] = sha256(raw)
        (lab.evidence / f"{filenames[kind]}.sha256").write_text(
            f"{digests[kind]}  {filenames[kind]}\n", encoding="ascii"
        )
    capture_manifest = {
        "fixture_id": fixture["fixture_id"],
        "captured_record_kinds": sorted(observed),
        "records": {
            kind: {"file": filenames[kind], "sha256": digests[kind]}
            for kind in sorted(observed)
        },
        "contains_model_or_dataset_content": False,
    }
    (lab.evidence / "preservation-manifest.json").write_text(
        json.dumps(capture_manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )

    # Model rollback/artifact cleanup by removing the ephemeral source records.
    lab.kubectl("-n", NAMESPACE, "delete", "configmap", MODEL_RECORD, LINEAGE_RECORD, "--wait=true")
    absent = {}
    for kind, name in (("model_read", MODEL_RECORD), ("training_lineage", LINEAGE_RECORD)):
        result = lab.kubectl("-n", NAMESPACE, "get", "configmap", name, "-o", "name",
                             allow_failure=True)
        absent[kind] = result.returncode != 0 and "NotFound" in result.stderr

    preserved = {}
    for kind, raw in observed.items():
        path = lab.evidence / filenames[kind]
        saved = path.read_bytes()
        checksum = path.with_name(path.name + ".sha256").read_text(encoding="ascii")
        preserved[kind] = (
            saved == raw
            and sha256(saved) == digests[kind]
            and checksum == f"{digests[kind]}  {filenames[kind]}\n"
        )
    lab.check(
        "green",
        "Both complete records remain byte-identical and hash-verified after source cleanup",
        all(absent.values()) and all(preserved.values())
        and capture_manifest["captured_record_kinds"] == sorted(required_kinds)
        and set(observed) == required_kinds,
        {"source_records_absent": absent, "preserved_records_match": preserved,
         "captured_record_kinds": capture_manifest["captured_record_kinds"]},
    )

    model_read = json.loads((lab.evidence / filenames["model_read"]).read_bytes())
    lineage = json.loads((lab.evidence / filenames["training_lineage"]).read_bytes())
    positive = (
        model_read == expected["model_read"]
        and model_read.get("action") == "read"
        and model_read.get("approval") == "approved"
        and lineage == expected["training_lineage"]
        and lineage.get("approval") == "approved"
        and lineage.get("dataset_digest") == expected["training_lineage"]["dataset_digest"]
        and capture_manifest["contains_model_or_dataset_content"] is False
    )
    lab.check(
        "positive",
        "The approved mock model-read and training-lineage records retain their full metadata and inert digest",
        positive,
        {"approved_model_read_preserved": model_read.get("approval") == "approved"
         and model_read.get("action") == "read",
         "approved_training_lineage_preserved": lineage.get("approval") == "approved",
         "dataset_digest_preserved": lineage.get("dataset_digest"),
         "model_or_dataset_content_present": False},
    )
