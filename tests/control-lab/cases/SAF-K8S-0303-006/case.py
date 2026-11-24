"""Verify AppArmor refinement, signed approval, promotion and rollback."""

import base64
import hashlib
import json
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAME = "fixture-apparmor-refinement-next"
BUILD_LABEL = "org.saf.fixture.apparmor-build"
SOURCE = hashlib.sha256((HERE / "Dockerfile").read_bytes()).hexdigest()
IMAGE = "saf-lab-apparmor:source-" + SOURCE[:24]
MARKERS = (
    "SAF-REFINE: two ordinary cycles are clean despite coverage excluding recovery",
    "SAF-REFINE: the original policy misses the recovery path and enforcing blocks it",
    "SAF-REFINE: specified recovery and excluded probe events calibrated against clean normal reads",
    "SAF-REFINE: modified unapproved revision rejected; active profile unchanged",
    "SAF-REFINE: approved exact revision promoted and allows normal and recovery while denying excluded",
    "SAF-REFINE: rollback restored prior exact profile; normal allowed and recovery denied",
    "SAF-REFINE: synthetic workload change re-triggered; new path observed and enforcing profile denied it",
    "SAF-REFINE: fixture profile removed",
)
SCOPE = (
    "Verify calibration, exact profile approval, promotion, enforcement and rollback in an "
    "isolated Linux guest run by a restricted Kind Job. The runner authenticates the synthetic "
    "reviewer's detached signature and passes the approved digest through an immutable ConfigMap. "
    "The guest performs the actual AppArmor loads and workload probes."
)
APPROVER_SHA256 = "02d9ed54beb93fa70251c38a5565fffd41539b72e6ae75ccb95a0b4f747ef99c"


def verify_approval(lab, digests):
    key = HERE / "approval.pub"
    identity = hashlib.sha256(key.read_bytes()).hexdigest()
    payload = HERE / "approval.payload"
    inventory = hashlib.sha256((HERE / "coverage.txt").read_bytes()).hexdigest()
    expected = (
        f"SAF-K8S-0303-006\noriginal_sha256={digests[0]}\nprofile_sha256={digests[1]}\n"
        f"coverage_sha256={inventory}\ndecision=approve\napprover={APPROVER_SHA256}\n"
    )
    same_inputs = payload.read_text() == expected and identity == APPROVER_SHA256
    if not same_inputs:
        lab.block("The reviewed approver or exact signed profile and coverage inputs do not match")
    with tempfile.TemporaryDirectory(prefix="saf-review-signature-") as scratch:
        signature = Path(scratch) / "signature"
        signature.write_bytes(base64.b64decode((HERE / "approval.sig.b64").read_text().strip(), validate=True))
        command = ("openssl", "dgst", "-sha256", "-verify", str(key), "-signature", str(signature))
        good = lab.command(*command, str(payload))
        altered = Path(scratch) / "altered"
        altered.write_text(expected.replace("decision=approve", "decision=deny"))
        bad = lab.command(*command, str(altered), allow_failure=True)
    lab.check("green", "The pinned reviewer signature validates exactly the approved profiles and coverage",
              good.stdout.strip() == "Verified OK" and bad.returncode != 0
              and "verification fail" in (bad.stdout + bad.stderr).lower(),
              {"pinned_signer": True, "approved_exact_inputs": True,
               "signed_payload_change_rejected": bad.returncode != 0})
    return digests[1]


def profile_job():
    security = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]}}
    guest = {
        "name": "guest", "image": IMAGE, "imagePullPolicy": "Never",
        "command": ["sh", "/fixture/boot.sh", "/fixture/original", "/fixture/revision",
                    "/fixture/approved.sha256"],
        "securityContext": security,
        "resources": {"requests": {"cpu": "200m", "memory": "160Mi"},
                      "limits": {"cpu": "1500m", "memory": "768Mi"}},
        "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True},
                         {"name": "scratch", "mountPath": "/tmp"}],
    }
    return {
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": NAME},
        "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 90, "template": {"spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [guest],
            "volumes": [{"name": "fixture", "configMap": {"name": NAME}},
                        {"name": "scratch", "emptyDir": {}}],
        }}},
    }


def run(lab):
    original = (HERE / "original.apparmor").read_text()
    revision = (HERE / "revision.apparmor").read_text()
    digests = [hashlib.sha256(text.encode()).hexdigest() for text in (original, revision)]
    approved = verify_approval(lab, digests)
    if lab.command("docker", "image", "inspect", IMAGE, allow_failure=True).returncode:
        lab.command("docker", "build", "-q", "-t", IMAGE, "--label", f"{BUILD_LABEL}={SOURCE}",
                    "-f", str(HERE / "Dockerfile"), str(HERE), timeout=420)
    image, = json.loads(lab.command("docker", "image", "inspect", IMAGE).stdout)
    if image["Config"].get("Labels", {}).get(BUILD_LABEL) != SOURCE:
        lab.block("The guest fixture image does not match the pinned build recipe")
    lab.command("kind", "load", "docker-image", IMAGE, "--name", lab.cluster, timeout=220)
    data = {
        "original": original, "revision": revision,
        "boot.sh": (HERE / "apparmor-refinement.sh").read_text(),
        "approved.sha256": approved + "\n",
    }
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME},
                "immutable": True, "data": data})
    lab.create(profile_job())
    completion = lab.kubectl("wait", "--for=condition=Complete", "job/" + NAME,
                             "--timeout=98s", timeout=108, allow_failure=True)
    logs = lab.kubectl("logs", "job/" + NAME, allow_failure=True)
    rows = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={NAME}", "-o", "json").stdout)["items"]
    if completion.returncode or logs.returncode or len(rows) != 1:
        lab.block("The AppArmor refinement guest did not complete; inspect the owned Job evidence")
    pod, = rows
    status, = pod["status"]["containerStatuses"]
    messages = set(logs.stdout.splitlines())
    matched = f"SAF-REFINE-INPUT: {' '.join(digests)}" in messages
    results = {marker: marker in messages for marker in MARKERS}
    if not matched:
        lab.block("Guest did not report the exact original and revision digests")
    phases = ("red", "red", "green", "green", "positive", "green", "green", "positive")
    for phase, (marker, present) in zip(phases, results.items()):
        lab.check(phase, marker.removeprefix("SAF-REFINE: "), present, {"observed": present})
    (lab.evidence / "apparmor-refinement-observations.json").write_text(json.dumps({
        "original_sha256": digests[0], "revision_sha256": digests[1],
        "guest_image": image["Id"], "running_guest_image": status["imageID"],
        "input_digest_marker_observed": matched, "guest_assertions": results,
    }, indent=2) + "\n")
