"""Exercise classical, dual, and post-quantum artifact signing policies in Kind."""
from hashlib import sha256
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PYTHON = ("docker.io/library/python:3.13-slim@sha256:"
          "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
ARTIFACTS = {kind: f"SAF-K8S-0603-004 synthetic {kind}\n" for kind in
             ("training-inputs", "model-weights", "checkpoint", "embedding-index", "inference-output")}
VERIFY = "saf-0603-004-signature-check"
RELEASE = "saf-0603-004-workload"
INSTALL = ("python -m pip --isolated --disable-pip-version-check install --index-url https://pypi.org/simple "
           "--only-binary=:all: --require-hashes --no-cache-dir --target /tmp/fixture-lib "
           "-r /fixture/requirements.txt >/tmp/install.log 2>&1 || { cat /tmp/install.log; exit 1; }; "
           "export PYTHONPATH=/tmp/fixture-lib; exec python /fixture/checkpoint_policy.py")
SCOPE = (
    "One disposable Kind cluster. A pinned Cryptography build uses real ECDSA P-256/SHA-256 "
    "and ML-DSA-65 signatures over a canonical manifest of five immutable, synthetic lifecycle "
    "artifacts. A release gate checks approved public keys, digest coverage and the independently "
    "chosen migration stage before starting a workload consuming the same synthetic bytes. "
    "Actual model retention, signer custody, and organization-wide transitions require separate evidence."
)


def pod(name, command, *, needs_verifier=False):
    volumes = [{"name": "artifacts", "configMap": {"name": "saf-0603-004-artifacts"}}]
    mounts = [{"name": "artifacts", "mountPath": "/artifacts", "readOnly": True}]
    if needs_verifier:
        volumes.append({"name": "fixture", "configMap": {"name": "saf-0603-004-fixture"}})
        mounts.append({"name": "fixture", "mountPath": "/fixture", "readOnly": True})
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534},
        "volumes": volumes, "containers": [{
            "name": "fixture", "image": PYTHON, "command": command, "volumeMounts": mounts,
            "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
        }],
    }}


def logs(lab, name):
    completed = lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{name}",
                            "--timeout=80s", timeout=90, allow_failure=True)
    if completed.returncode:
        lab.kubectl("describe", "pod", name, allow_failure=True)
        lab.kubectl("logs", name, allow_failure=True)
        lab.block(f"Signature fixture {name} did not complete")
    return json.loads(lab.kubectl("logs", name).stdout)


def gated_release(lab, judgement, manifest):
    if judgement != "verified":
        return False
    code = ("import hashlib,json;from pathlib import Path;"
            "print(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() "
            "for p in Path('/artifacts').iterdir() if not p.name.startswith('..')}))")
    lab.create(pod(RELEASE, ["python", "-c", code]))
    return logs(lab, RELEASE) == manifest


def run(lab):
    expected = {name: sha256(data.encode()).hexdigest() for name, data in ARTIFACTS.items()}
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "saf-0603-004-artifacts"},
                "immutable": True, "data": ARTIFACTS})
    lab.kubectl("create", "configmap", "saf-0603-004-fixture",
                f"--from-file={HERE / 'requirements.txt'}", f"--from-file={HERE / 'checkpoint_policy.py'}")
    lab.create(pod(VERIFY, ["sh", "-ec", INSTALL], needs_verifier=True))
    states = logs(lab, VERIFY)
    legacy = states["legacy"] == "verified"
    lab.check("red", "Legacy policy accepts the digest manifest with only the classical signature",
              legacy, {"legacy_classical_only_accepted": legacy})
    for name, reason in (
        ("dual_missing_pq", "missing:ml-dsa-65"),
        ("dual_missing_classical", "missing:ecdsa-p256-sha256"),
        ("dual_wrong_pq_identity", "invalid:ml-dsa-65"),
        ("dual_incomplete_artifact_list", "artifact-manifest-mismatch"),
        ("dual_changed_digest", "artifact-manifest-mismatch"),
        ("pq_only_old_signer", "missing:ml-dsa-65"),
    ):
        verified_denial = states[name] == reason and not gated_release(lab, states[name], expected)
        lab.check("green", f"Release policy rejects {name}", verified_denial, {"decision": states[name]})
    no_target = not lab.kubectl("get", "pod", RELEASE, "--ignore-not-found", "-o", "name").stdout.strip()
    lab.check("green", "Authenticated but incomplete lifecycle coverage is denied before release",
              states["incomplete_signatures_genuinely_verify"] and no_target,
              {"valid_signatures_on_incomplete_manifest": states["incomplete_signatures_genuinely_verify"],
               "release_pod_absent": no_target})
    dual = states["dual"] == "verified" and states["artifacts"] == expected
    pq = states["pq_only"] == "verified"
    lab.check("positive", "The declared dual-signature policy and post-quantum cutover accept the exact manifest",
              dual and pq, {"dual_verified": dual, "post_quantum_only_verified": pq, "lifecycle_artifacts": len(expected)})
    consumed = gated_release(lab, states["pq_only"], expected)
    lab.check("positive", "The released Kind workload reads the same verified lifecycle artifact bytes",
              consumed, {"verified_manifest_matches_runtime_inputs": consumed})
    (lab.evidence / "signature-migration-observations.json").write_text(json.dumps(states, indent=2) + "\n")
