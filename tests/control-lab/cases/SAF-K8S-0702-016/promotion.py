"""Synthetic, local-only model artifact promotion workflow for SAF-K8S-0702-016."""
import argparse
import hashlib
import json
from pathlib import Path
import sys


STAGES = ("development", "staging", "production")
CLASSIFICATION_LABELS = {
    "data-sensitivity": "saf-k8s.example/data-sensitivity",
    "model-risk": "saf-k8s.example/model-risk",
    "training-data-class": "saf-k8s.example/training-data-class",
}
DIGEST_ANNOTATION = "saf-k8s.example/artifact-digest"
STAGE_LABEL = "saf-k8s.example/lifecycle-stage"
APP_LABEL = "app.kubernetes.io/name"


class Rejected(ValueError):
    """The synthetic promotion contract rejected the source artifact."""


def read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise Rejected(f"cannot read JSON input: {error}") from error


def validate_and_promote(source, contract, source_stage, target_stage):
    if source_stage not in STAGES or target_stage not in STAGES:
        raise Rejected("stage is not in the synthetic promotion sequence")
    if STAGES.index(target_stage) != STAGES.index(source_stage) + 1:
        raise Rejected("promotion must advance exactly one lifecycle stage")
    if not isinstance(source, dict) or not isinstance(contract, dict):
        raise Rejected("artifact and release contract must be JSON objects")

    artifact = source.get("artifact")
    expected = contract.get("artifact")
    if not isinstance(artifact, dict) or not isinstance(expected, dict):
        raise Rejected("artifact identity is missing")
    if source.get("stage") != source_stage:
        raise Rejected("source stage does not match requested promotion")
    if artifact.get("name") != expected.get("name"):
        raise Rejected("artifact name does not match release contract")
    if artifact.get("digest") != expected.get("digest"):
        raise Rejected("artifact digest does not match release contract")

    classification = source.get("classification")
    if classification != contract.get("classification"):
        raise Rejected("classification missing or changed from release contract")
    if (not isinstance(classification, dict) or not classification
            or any(not isinstance(key, str) or not isinstance(value, str) or not value
                   for key, value in classification.items())):
        raise Rejected("classification must be a non-empty string map")
    return {**source, "stage": target_stage}


def serving_manifest(promoted, stage):
    labels = {APP_LABEL: "synthetic-model-serving", STAGE_LABEL: stage}
    labels.update({CLASSIFICATION_LABELS[key]: value
                   for key, value in promoted["classification"].items()})
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": f"synthetic-model-{stage}",
            "namespace": f"saf-0702-016-{stage}",
            "labels": {STAGE_LABEL: stage},
        },
        "spec": {
            "replicas": 0,
            "selector": {"matchLabels": {APP_LABEL: "synthetic-model-serving"}},
            "template": {
                "metadata": {
                    "labels": labels,
                    "annotations": {DIGEST_ANNOTATION: promoted["artifact"]["digest"]},
                },
                "spec": {
                    "automountServiceAccountToken": False,
                    "containers": [{
                        "name": "synthetic-model",
                        "image": "registry.k8s.io/pause:3.10.1@sha256:278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c",
                        "resources": {
                            "requests": {"cpu": "10m", "memory": "8Mi"},
                            "limits": {"cpu": "50m", "memory": "16Mi"},
                        },
                    }],
                },
            },
        },
    }


def write_json(path, value):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--promoted-payload", required=True, type=Path)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--source-stage", required=True, choices=STAGES)
    parser.add_argument("--target-stage", required=True, choices=STAGES)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--serving-manifest", required=True, type=Path)
    args = parser.parse_args()
    try:
        promoted = validate_and_promote(
            read_json(args.source), read_json(args.contract),
            args.source_stage, args.target_stage,
        )
        with args.payload.open("rb") as source_payload:
            payload = source_payload.read(65537)
        if len(payload) > 65536:
            raise Rejected("synthetic fixture payload exceeds its documented limit")
        if "sha256:" + hashlib.sha256(payload).hexdigest() != promoted["artifact"]["digest"]:
            raise Rejected("payload digest does not match release contract")
        manifest = serving_manifest(promoted, args.target_stage)
        args.promoted_payload.write_bytes(payload)
        write_json(args.output, promoted)
        write_json(args.serving_manifest, manifest)
    except (Rejected, OSError) as error:
        print(f"promotion rejected: {error}", file=sys.stderr)
        return 1
    print(f"promoted synthetic artifact {promoted['artifact']['name']} "
          f"from {args.source_stage} to {args.target_stage}; classification preserved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
