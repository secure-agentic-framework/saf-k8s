"""Verify synthetic source and build provenance before deploying an exact artifact."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
IMAGE = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
BUILDER = "https://example.invalid/synthetic-builder/v1"
SOURCE_URI = "https://example.invalid/source.json"
BUILD_TYPE = "https://example.invalid/normalize-config/v1"
SCOPE = (
    "A synthetic promotion gate checks signed builder provenance, source, and the digest of "
    "a deterministically generated configuration artifact. The allowed bytes are mounted in "
    "a digest-pinned Kubernetes Job and independently read and hashed there. This covers a "
    "selected CI/CD provenance control and artifact propagation check. Production trust, "
    "image admission, organization-wide threat modeling, AI pipeline coverage and ongoing "
    "deployment monitoring need separate evidence."
)


class Rejected(ValueError):
    """The declared fixture or its approved provenance failed verification."""


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def build(source):
    record = json.loads(source)
    return (json.dumps({"flags": sorted(record["flags"]), "release": record["release"]},
                       sort_keys=True, separators=(",", ":")) + "\n").encode()


def verify(source, artifact, statement, signature):
    if statement is None or signature is None:
        raise Rejected("missing provenance")
    with tempfile.TemporaryDirectory(prefix="saf-1004-002-") as temp:
        path = Path(temp)
        (path / "statement.json").write_bytes(statement)
        (path / "proof.sig").write_bytes(signature)
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(FIXTURES / "trusted-builder.pub"),
             "-signature", str(path / "proof.sig"), str(path / "statement.json")],
            capture_output=True, text=True, timeout=10,
        )
    if result.returncode:
        raise Rejected("invalid builder signature")
    doc = json.loads(statement)
    if (doc["_type"] != "https://in-toto.io/Statement/v1" or
            doc["predicateType"] != "https://slsa.dev/provenance/v1"):
        raise Rejected("unexpected statement type")
    definition = doc["predicate"]["buildDefinition"]
    builder = doc["predicate"]["runDetails"]["builder"]["id"]
    if builder != BUILDER or definition["buildType"] != BUILD_TYPE:
        raise Rejected("unexpected build identity")
    if definition["resolvedDependencies"] != [{"uri": SOURCE_URI, "digest": {"sha256": sha256(source)}}]:
        raise Rejected("source digest mismatch")
    subject = {"name": "generated-config.json", "digest": {"sha256": sha256(artifact)}}
    if doc["subject"] != [subject] or artifact != build(source):
        raise Rejected("artifact does not match signed build output")
    return {"source_sha256": sha256(source), "artifact_sha256": sha256(artifact), "builder": builder}


def promote(lab, name, source, artifact, statement, signature):
    binding = verify(source, artifact, statement, signature)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "immutable": True,
                "binaryData": {"generated-config.json": base64.b64encode(artifact).decode("ascii")}})
    container = {
        "name": "validator", "image": IMAGE,
        "command": ["/bin/sh", "-ec",
                    "test \"$(sha256sum /fixture/generated-config.json | cut -d' ' -f1)\" = \"$1\"; "
                    "sha256sum /fixture/generated-config.json; cat /fixture/generated-config.json",
                    "validate-artifact", binding["artifact_sha256"]],
        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]}},
        "volumeMounts": [{"name": "artifact", "mountPath": "/fixture", "readOnly": True}],
    }
    pod = {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [container],
        "volumes": [{"name": "artifact", "configMap": {"name": name}}],
    }
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 110, "template": {"spec": pod}}})
    return binding


def run(lab):
    source = (FIXTURES / "source.json").read_bytes()
    artifact = build(source)
    statement = (FIXTURES / "provenance.json").read_bytes()
    signature = base64.b64decode((FIXTURES / "provenance.sig.b64").read_text(), validate=False)
    invalid = (
        ("missing", source, artifact, None, None, "missing provenance"),
        ("source", source + b" ", artifact, statement, signature, "source digest mismatch"),
        ("artifact", source, artifact + b" ", statement, signature, "artifact does not match signed build output"),
        ("signature", source, artifact, statement + b" ", signature, "invalid builder signature"),
    )
    for label, candidate_source, candidate_artifact, candidate_statement, candidate_signature, reason in invalid:
        name = f"saf-1004-002-{label}"
        rejection = None
        try:
            promote(lab, name, candidate_source, candidate_artifact, candidate_statement, candidate_signature)
        except Rejected as exc:
            rejection = str(exc)
        objects = lab.kubectl("get", f"job/{name}", f"configmap/{name}", "--ignore-not-found", "-o", "name")
        lab.check("red", reason, rejection == reason and not objects.stdout.strip(),
                  {"rejection": rejection, "release_objects_created": bool(objects.stdout.strip())})

    name = "saf-1004-002-approved"
    binding = promote(lab, name, source, artifact, statement, signature)
    job = json.loads(lab.kubectl("get", f"job/{name}", "-o", "json").stdout)
    image = job["spec"]["template"]["spec"]["containers"][0]["image"]
    lab.check("green", "The gate promotes an artifact bound to the signed source and builder",
              binding["artifact_sha256"] == sha256(artifact) and image == IMAGE, binding)
    lab.kubectl("wait", "--for=condition=complete", f"job/{name}", "--timeout=125s")
    logs = lab.kubectl("logs", f"job/{name}").stdout
    (lab.evidence / "workload.raw.log").write_text(logs)
    actual_hash, _, content = logs.partition("\n")
    lab.check("positive", "The native Job completes after reading and hashing the mounted build bytes",
              actual_hash.split()[0] == binding["artifact_sha256"] and content.encode() == artifact,
              {"mounted_sha256": sha256(content.encode()), "job_completed": True, "image": image})
