"""Defensive synthetic dataset-integrity Kind fixture; harness entry point run(lab)."""
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SIBLING = HERE.parent / "SAF-K8S-0908-001" / "case.py"
CRYPTO = HERE.parent / "SAF-K8S-0906-006" / "signature_crypto_base.py"
NS = "saf-test"
APP = "dataset-integrity-fixture"
PVC = "dataset-integrity-data"
CODE = "dataset-integrity-code"
MANIFEST = "dataset-integrity-manifest"

SCOPE = (
    "A local Kind lab streams four fixed synthetic 4 KiB partitions in 257-byte chunks, "
    "compares inventory, lengths, SHA-256 digests and a Merkle root to an immutable trusted "
    "manifest, denies deterministic changed or missing content, and accepts the explicitly "
    "named approved synthetic dataset. Separate read-only consumer Jobs then stream the approved "
    "fixture only after the same verification gate and record zero consumption for a changed "
    "copy. A distinct fixture authority signs the approved manifest with an ephemeral OpenSSL Ed25519 "
    "key. An unmatched signature prevents any input consumption. A guarded restore revalidates the "
    "signed commitment before a reader resumes on a distinct PVC. The reference uses one disposable "
    "cluster and one synthetic dataset."
)


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load required case module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_runtime(lab):
    """Import the actual adjacent published helper and use its runtime setup."""
    if not SIBLING.is_file():
        lab.block("Required adjacent SAF-K8S-0908-001/case.py is unavailable")
    helper = _load_module("saf_k8s_0908_001_case", SIBLING)
    return helper.load_runtime(lab)


def _create(lab, kind, name, api="v1", **fields):
    return lab.create({
        "apiVersion": api,
        "kind": kind,
        "metadata": {"name": name, "namespace": NS},
        **fields,
    })


def run(lab):
    """Create one bounded PVC consumer and record deterministic lab assertions."""
    image = load_runtime(lab)
    if not CRYPTO.is_file():
        lab.block("Required adjacent SAF-K8S-0906-006 signature helper is unavailable")
    _create(lab, "ConfigMap", CODE, immutable=True,
            data={
                "dataset_fixture.py": (HERE / "dataset_fixture.py").read_text(encoding="utf-8"),
                "training_consumer.py": (HERE / "training_consumer.py").read_text(encoding="utf-8"),
                "restore_dataset.py": (HERE / "restore_dataset.py").read_text(encoding="utf-8"),
                "manifest_auth.py": (HERE / "manifest_auth.py").read_text(encoding="utf-8"),
                "signature_crypto_base.py": CRYPTO.read_text(encoding="utf-8"),
            })
    _create(lab, "ConfigMap", MANIFEST, immutable=True,
            data={"manifest.json": (HERE / "manifest.json").read_text(encoding="utf-8")})
    _create(lab, "PersistentVolumeClaim", PVC, spec={
        "accessModes": ["ReadWriteOnce"],
        "resources": {"requests": {"storage": "64Mi"}},
    })
    # The consumer is created before any wait so WaitForFirstConsumer storage can bind.
    _create(lab, "Pod", APP, spec={
        "restartPolicy": "Never",
        "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                            "fsGroup": 65534, "fsGroupChangePolicy": "OnRootMismatch",
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{
            "name": "fixture",
            "image": image,
            "imagePullPolicy": "Never",
            "command": ["python", "/fixture/dataset_fixture.py", "/data/segments", "/manifest/manifest.json"],
            "env": [{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}],
            "volumeMounts": [
                {"name": "code", "mountPath": "/fixture", "readOnly": True},
                {"name": "manifest", "mountPath": "/manifest", "readOnly": True},
                {"name": "dataset", "mountPath": "/data"},
            ],
            "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                          "limits": {"cpu": "200m", "memory": "96Mi"}},
            "securityContext": {"allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
        }],
        "volumes": [
            {"name": "code", "configMap": {"name": CODE}},
            {"name": "manifest", "configMap": {"name": MANIFEST}},
            {"name": "dataset", "persistentVolumeClaim": {"claimName": PVC}},
        ],
    })
    lab.kubectl("-n", NS, "wait", "--for=jsonpath={.status.phase}=Succeeded",
                f"pod/{APP}", "--timeout=95s", timeout=105)
    raw = lab.kubectl("-n", NS, "logs", f"pod/{APP}").stdout.strip()
    observations = json.loads(raw.splitlines()[-1])

    red = observations["red"]
    lab.check("red", "Baseline accepts deterministic altered synthetic partition; governed verifier denies it",
              red == {"baseline_accepted_deterministic_change": True,
                      "baseline_partition_count": 4, "governed_denied_change": True}, red)

    missing = observations["missing"]
    lab.check("green", "Governed verifier denies a missing partition and a mismatched Merkle root",
              missing == {"governed_denied_missing_partition": True,
                          "governed_denied_wrong_root": True,
                          "reason": "inventory_or_dataset_id"}, missing)

    positive = observations["positive"]
    expected_positive = {
        "approved_dataset_id": "synthetic-approved-v1",
        "approved_dataset_accepted": True,
        "partition_count": 4,
        "max_parallel_workers": 2,
        "bounded_output_partitions": 4,
        "stream_chunk_bytes": 257,
        "merkle_root": "b7c253078bb623fdab4352f577115c434eb1fef43622e5f925623d845f80f94b",
    }
    lab.check("positive", "Explicit approved dataset streams and verifies with bounded parallel output",
              positive == expected_positive, positive)
    (lab.evidence / "dataset-integrity-observations.json").write_text(
        json.dumps(observations, sort_keys=True, indent=2) + "\n"
    )

    # A distinct Kubernetes Job consumes the same case-owned PVC content and
    # immutable manifest using read-only mounts. It performs a separate complete
    # verification before its actual bounded input-streaming phase.
    consumer_case = _load_module("saf_k8s_0906_002_consumer_case", HERE / "consumer_case.py")
    signature_case = _load_module("saf_k8s_0906_002_signature_case", HERE / "signature_case.py")
    signature_case.prepare(lab, image, consumer_case)
    consumer_case.run(lab, image)
    signature_case.check(lab, image, consumer_case)

    recovery_case = _load_module("saf_k8s_0906_002_recovery_case", HERE / "recovery_case.py")
    recovery_case.run(lab, image, consumer_case)
