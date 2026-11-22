"""Exercise synthetic classification preservation and Kubernetes admission."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import time

HERE = Path(__file__).parent
CONTRACT = HERE / "release-contract.json"
DEV_ARTIFACT = HERE / "development-artifact.json"
DEV_PAYLOAD = HERE / "development-payload.txt"
PROMOTER = HERE / "promotion.py"
NAMESPACE = "saf-0702-016-production"
DENIAL = "synthetic production model must retain its approved classification and artifact digest"
DIGEST = "sha256:8b633223ecb485b9274a80e226b8421d9625317898903c07fbc2b1a150212c34"
CLASSIFICATION = {
    "data-sensitivity": "synthetic-confidential",
    "model-risk": "synthetic-high",
    "training-data-class": "synthetic-restricted",
}
CLASSIFICATION_LABELS = {
    "data-sensitivity": "saf-k8s.example/data-sensitivity",
    "model-risk": "saf-k8s.example/model-risk",
    "training-data-class": "saf-k8s.example/training-data-class",
}
DIGEST_ANNOTATION = "saf-k8s.example/artifact-digest"
SCOPE = (
    "A local synthetic promotion CLI checks exact artifact identity and classification against "
    "an approved fixture contract on development-to-staging and staging-to-production edges, "
    "and emits serving Deployment metadata. Kubernetes v1.36.1 ValidatingAdmissionPolicy "
    "denies missing or changed classification and digest on one small production Deployment. "
    "Local payload bytes are synthetic, and their SHA-256 is validated and carried across both stages. No registry, provider, production signing, attestations, or governance "
    "process is exercised; trust in the release contract and its approval is out of scope."
)


def read_json(path):
    return json.loads(Path(path).read_text())


def invoke_promotion(lab, source, source_stage, target_stage, output, manifest, payload):
    return lab.command(
        "python3", str(PROMOTER), "--source", str(source), "--contract", str(CONTRACT),
        "--source-stage", source_stage, "--target-stage", target_stage,
        "--output", str(output), "--serving-manifest", str(manifest), "--payload", str(payload),
        "--promoted-payload", str(output.with_suffix(".payload")), allow_failure=True,
    )


def artifact_rejects_drift(lab, source, source_stage, target_stage, directory, payload, kind):
    bad_source = Path(directory) / f"{source_stage}-{kind}-source.json"
    output = Path(directory) / f"{source_stage}-{kind}-output.json"
    manifest = Path(directory) / f"{source_stage}-{kind}-serving.json"
    data = read_json(source)
    if kind == "dropped":
        del data["classification"]["data-sensitivity"]
    elif kind == "changed":
        data["classification"]["data-sensitivity"] = "synthetic-public"
    else:
        payload = directory / f"{source_stage}-substituted.payload"
        payload.write_bytes(b"unapproved synthetic substitution")
    bad_source.write_text(json.dumps(data))
    result = invoke_promotion(lab, bad_source, source_stage, target_stage, output, manifest, payload)
    reason = ("payload digest does not match" if kind == "payload-substituted"
              else "classification missing or changed")
    clean = not any(path.exists() for path in (output, manifest, output.with_suffix(".payload")))
    return (result.returncode != 0 and reason in result.stderr and clean,
            {"expected_denial": reason in result.stderr, "no_promotion_outputs": clean})


def denied(result):
    return (result.returncode != 0 and "(Forbidden)" in result.stderr
            and DENIAL in result.stderr)


def server_deployment(lab, deployment):
    return lab.kubectl(
        "-n", NAMESPACE, "create", "-f", "-", "--dry-run=server", "-o", "json",
        payload=json.dumps(deployment), allow_failure=True,
    )


def mutate_serving_manifest(manifest, kind):
    changed = copy.deepcopy(manifest)
    labels = changed["spec"]["template"]["metadata"]["labels"]
    if kind == "dropped":
        del labels[CLASSIFICATION_LABELS["data-sensitivity"]]
    elif kind == "changed":
        labels[CLASSIFICATION_LABELS["data-sensitivity"]] = "synthetic-public"
    else:
        changed["spec"]["template"]["metadata"]["annotations"][DIGEST_ANNOTATION] = "sha256:" + "b" * 64
    return changed


def run(lab):
    with tempfile.TemporaryDirectory(prefix="saf-0702-016-") as temp:
        work = Path(temp)
        dev = DEV_ARTIFACT
        stage_manifests = {}
        for source_stage, target_stage, source in (
            ("development", "staging", dev),
            ("staging", "production", work / "staging-artifact.json"),
        ):
            if source_stage == "staging":
                payload = work / "staging-artifact.payload"
            else:
                payload = DEV_PAYLOAD
            for kind in ("dropped", "changed", "payload-substituted"):
                accepted, observed = artifact_rejects_drift(
                    lab, source, source_stage, target_stage, work, payload, kind,
                )
                lab.check(
                    "red", f"Local {source_stage}-to-{target_stage} promotion rejects {kind} input",
                    accepted, observed,
                )
            output = work / f"{target_stage}-artifact.json"
            manifest = work / f"{target_stage}-serving.json"
            result = invoke_promotion(lab, source, source_stage, target_stage, output, manifest, payload)
            if result.returncode != 0:
                lab.check("positive", f"Permitted {source_stage}-to-{target_stage} promotion succeeds",
                          False, result.stderr.strip())
            artifact = read_json(output)
            serving = read_json(manifest)
            metadata = serving["spec"]["template"]["metadata"]
            emitted_classification = {
                key: metadata["labels"].get(label)
                for key, label in CLASSIFICATION_LABELS.items()
            }
            carried_bytes = output.with_suffix(".payload").read_bytes()
            verified_payload = ("sha256:" + hashlib.sha256(carried_bytes).hexdigest() == DIGEST
                                and carried_bytes == DEV_PAYLOAD.read_bytes())
            ok = (verified_payload and artifact["stage"] == target_stage
                  and artifact["classification"] == CLASSIFICATION
                  and artifact["artifact"]["digest"] == DIGEST
                  and metadata["labels"].get("saf-k8s.example/lifecycle-stage") == target_stage
                  and emitted_classification == CLASSIFICATION
                  and metadata["annotations"].get(DIGEST_ANNOTATION) == DIGEST)
            lab.check(
                "positive", f"Permitted {source_stage}-to-{target_stage} promotion preserves artifact metadata",
                ok,
                {"stage": artifact.get("stage"), "classification": artifact.get("classification"),
                 "serving_classification": emitted_classification,
                 "payload_digest_verified": verified_payload,
                 "digest_matches": metadata["annotations"].get(DIGEST_ANNOTATION) == DIGEST},
            )
            stage_manifests[target_stage] = manifest

        production = read_json(stage_manifests["production"])
        production["metadata"]["namespace"] = NAMESPACE
        production["metadata"]["name"] = "synthetic-production-model"
        production["spec"]["replicas"] = 1

        lab.kubectl("create", "namespace", NAMESPACE)
        lab.kubectl("label", "namespace", NAMESPACE,
                    "saf-k8s.example/classification-enforcement=0702-016")

        inactive_probes = [mutate_serving_manifest(production, kind)
                           for kind in ("dropped", "changed", "digest")]
        inactive = [server_deployment(lab, probe) for probe in inactive_probes]
        lab.check(
            "red", "Inactive admission permits dropped or changed production classification and changed digest",
            all(result.returncode == 0 for result in inactive),
            [{"accepted": result.returncode == 0, "detail": result.stderr.strip()}
             for result in inactive],
        )

        lab.apply(HERE / "admission-policy.yaml")
        deadline = time.monotonic() + 20
        while True:
            green = [server_deployment(lab, probe) for probe in inactive_probes]
            if all(denied(result) for result in green) or time.monotonic() >= deadline:
                break
            time.sleep(0.5)
        lab.check(
            "green", "Production admission rejects missing or changed classification and changed digest with the exact denial",
            all(denied(result) for result in green),
            [{"denied_by_policy": denied(result), "detail": result.stderr.strip()}
             for result in green],
        )

        permitted = server_deployment(lab, production)
        lab.check("positive", "Classification-preserving production Deployment remains admissible",
                  permitted.returncode == 0,
                  permitted.stderr.strip() or "server-side dry-run admitted")
        live = copy.deepcopy(production)
        live["metadata"]["name"] = "synthetic-production-model-live"
        lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(live))
        ready = lab.kubectl(
            "-n", NAMESPACE, "rollout", "status", "deployment/synthetic-production-model-live",
            "--timeout=60s", timeout=70,
        ).returncode == 0
        pods = json.loads(lab.kubectl(
            "-n", NAMESPACE, "get", "pods", "-l", "app.kubernetes.io/name=synthetic-model-serving",
            "-o", "json",
        ).stdout)["items"]
        pod_labels = pods[0]["metadata"].get("labels", {}) if len(pods) == 1 else {}
        classes_match = all(pod_labels.get(label) == CLASSIFICATION[key]
                            for key, label in CLASSIFICATION_LABELS.items())
        pod_annotation = pods[0]["metadata"].get("annotations", {}).get(DIGEST_ANNOTATION, "") if len(pods) == 1 else ""
        lab.check(
            "positive", "Permitted production workload becomes Ready with carried classification and digest",
            ready and classes_match and pod_annotation == DIGEST,
            {"deployment_ready": ready, "one_pod": len(pods) == 1,
             "classification_match": classes_match, "digest_match": pod_annotation == DIGEST},
        )


        bad_update = {"spec": {"template": {"metadata": {
            "annotations": {DIGEST_ANNOTATION: "sha256:" + "b" * 64}
        }}}}
        updated = lab.kubectl("-n", NAMESPACE, "patch", "deployment/synthetic-production-model-live",
                              "--type=merge", "-p", json.dumps(bad_update),
                              "--dry-run=server", allow_failure=True)
        lab.check("green", "Serving admission rejects changing a live Deployment's retained digest",
                  denied(updated), {"exact_policy_denial": denied(updated)})
