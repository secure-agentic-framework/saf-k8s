"""Verify exact OpenVEX vocabulary and conservative assessment intake in Kind."""
from base64 import b64encode
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
VEXCTL = ("ghcr.io/openvex/vexctl:v0.4.4@sha256:"
          "ce15c9c85ffc66cb630c0ce9c50a85e9241be77ca4e6e841ab14a0bf2a96bf7e")
PYTHON = ("docker.io/library/python:3.13-slim@sha256:"
          "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
AUTHOR = "synthetic-review@saf-vex.example.test"
RECORD = "https://saf-vex.example.test/reviews/synthetic"
RELEASE = "https://saf-vex.example.test/releases/sha256/"
LIB = "pkg:generic/saf-fictional@1.0"
OTHER = "pkg:generic/saf-fictional@1.1"
ABSENT = "pkg:generic/saf-fictional-obsolete@0.1"
SCOPE = (
    "Pinned vexctl checks OpenVEX vocabulary on fictional identifiers. A disposable Kind "
    "Pod enforces an explicit signed-document and exact released-artifact matching policy "
    "over synthetic findings. No vulnerability scanner or real advisory is used. "
    "Production evidence and version-specific scanner integration require separate verification."
)


def compact(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def create_examples(lab, product):
    dictionary = ("affected", "not_affected", "fixed", "under_investigation")
    examples = []
    for state in dictionary:
        flags = []
        if state == "affected":
            flags = ["--action-statement", "Review the fictional update record."]
        if state == "not_affected":
            flags = ["--justification", "component_not_present"]
        result = lab.command(
            "docker", "run", "--rm", "--network", "none", VEXCTL, "create",
            product, "SYNTH-VEX-000", state, *flags,
        )
        examples.append(json.loads(result.stdout)["statements"][0]["status"])
    invalid = lab.command("docker", "run", "--rm", "--network", "none", VEXCTL, "create",
                          product, "SYNTH-VEX-000", "exploitable", allow_failure=True)
    strict = invalid.returncode != 0 and "a valid impact status is required" in invalid.stderr
    lab.check("green", "Pinned OpenVEX CLI uses four defined statuses and rejects the catalog's mixed label",
              tuple(examples) == dictionary and strict, {"statuses": examples, "mixed_label_rejected": strict})


def key(lab, directory, name):
    private = directory / f"{name}.pem"
    public = directory / f"{name}.pub"
    lab.command("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-out", str(private))
    private.chmod(0o600)
    lab.command("openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public))
    return private, public


def sign(lab, directory, name, doc, private):
    raw = compact(doc)
    input_path, sig_path = directory / f"{name}.json", directory / f"{name}.sig"
    input_path.write_text(raw)
    lab.command("openssl", "dgst", "-sha256", "-sign", str(private), "-out", str(sig_path), str(input_path))
    return [raw, b64encode(sig_path.read_bytes()).decode()]


def reviewed_inputs(lab, artifact, adjacent):
    directory = lab.kubeconfig.parent / "vex-fixture"
    directory.mkdir(mode=0o700)
    private, public = key(lab, directory, "review")
    stranger, _ = key(lab, directory, "untrusted")
    statuses = {"absent": ("not_affected", ABSENT), "remediate": ("affected", LIB),
                "investigate": ("under_investigation", LIB), "claimed-fixed": ("fixed", LIB)}
    findings, statements = [], []
    for name, (state, component) in statuses.items():
        advisory = f"SYNTH-{name.upper()}"
        findings.append({"key": name, "advisory": advisory, "artifact": artifact, "component": component})
        statement = {"vulnerability": {"name": advisory}, "status": state,
                     "products": [{"@id": artifact, "subcomponents": [{"@id": component}]}]}
        if state == "not_affected":
            statement["justification"] = "component_not_present"
        if state == "affected":
            statement["action_statement"] = "Review the fictional update record."
        statements.append(statement)
    source = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": RECORD, "author": AUTHOR,
              "timestamp": "2026-01-10T00:00:00Z", "version": 2, "statements": statements}
    findings.extend([
        {**findings[0], "key": "adjacent-artifact", "artifact": adjacent},
        {**findings[0], "key": "adjacent-component", "component": OTHER},
    ])
    valid = sign(lab, directory, "accepted", source, private)
    unexplained = deepcopy(source)
    del unexplained["statements"][0]["justification"]
    conflict = deepcopy(source)
    variant = deepcopy(conflict["statements"][0])
    variant["status"] = "under_investigation"
    del variant["justification"]
    conflict["statements"].append(variant)
    contradictory = deepcopy(source)
    misleading = contradictory["statements"][1]
    misleading["status"] = "not_affected"
    del misleading["action_statement"]
    misleading["justification"] = "component_not_present"
    return {"findings": findings, "evaluation_time": "2026-01-11T00:00:00Z",
            "documents": {
                "unavailable": [None, None],
                "approved": valid,
                "untrusted": sign(lab, directory, "untrusted-claim", source, stranger),
                "changed-bytes": [" " + valid[0], valid[1]],
                "obsolete": sign(lab, directory, "obsolete", {**source, "version": 1}, private),
                "missing-explanation": sign(lab, directory, "unexplained-document", unexplained, private),
                "conflicting-claims": sign(lab, directory, "conflicting-document", conflict, private),
                "unsubstantiated": sign(lab, directory, "unsubstantiated-document", contradictory, private),
            }}, public.read_text()


def run_intake(lab, inputs, public):
    name = "saf-vex-intake"
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name}, "immutable": True,
                "data": {"intake.py": (HERE / "intake.py").read_text(),
                         "inputs.json": compact(inputs), "review.pub": public}})
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "containers": [{
            "name": "review", "image": PYTHON, "command": ["python", "-B", "/fixture/intake.py"],
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
            "volumeMounts": [{"name": "fixture", "mountPath": "/fixture", "readOnly": True},
                             {"name": "scratch", "mountPath": "/tmp"}],
        }], "volumes": [{"name": "fixture", "configMap": {"name": name}},
                       {"name": "scratch", "emptyDir": {"sizeLimit": "16Mi"}}],
    }})
    end = time.monotonic() + 90
    while time.monotonic() < end:
        status = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)["status"]
        if status["phase"] in {"Succeeded", "Failed"}:
            logs = lab.kubectl("logs", name).stdout
            if status["phase"] != "Succeeded":
                lab.block("The fixture verifier did not produce a decision: " + logs)
            return json.loads(logs)
        time.sleep(1)
    lab.block("The fixture verifier did not reach a terminal state")


def run(lab):
    release_payload = compact({"release": "1", "packages": [LIB]})
    adjacent_payload = compact({"release": "2", "packages": [LIB]})
    artifact = RELEASE + sha256(release_payload.encode()).hexdigest()
    adjacent = RELEASE + sha256(adjacent_payload.encode()).hexdigest()
    create_examples(lab, artifact)
    inputs, public = reviewed_inputs(lab, artifact, adjacent)
    inputs["release_manifests"] = [release_payload, adjacent_payload]
    result = run_intake(lab, inputs, public)
    decisions = result["reviews"]
    baseline = decisions["unavailable"]
    present = all(row["needs_review"] for row in baseline["decisions"].values())
    lab.check("red", "Without authenticated assessment evidence the fixture retains every finding for review",
              baseline["source"] == "document-unavailable" and present, {"all_findings_still_active": present})
    expected = {"untrusted": "signature-invalid", "changed-bytes": "signature-invalid",
                "obsolete": "document-outside-release-window", "missing-explanation": "missing-impact-explanation"}
    declined = {name: decisions[name]["source"] == reason and all(
        row["needs_review"] for row in decisions[name]["decisions"].values()
    ) for name, reason in expected.items()}
    lab.check("green", "Invalid source, altered bytes, invalid release version and missing explanation keep findings active",
              all(declined.values()), declined)
    approved = decisions["approved"]["decisions"]
    wanted = {"absent": ("not_affected", False), "remediate": ("affected", True),
              "investigate": ("under_investigation", True), "claimed-fixed": ("fixed", True),
              "adjacent-artifact": ("no-exact-match", True), "adjacent-component": ("no-exact-match", True)}
    valid = {name: approved[name] == {"disposition": status, "needs_review": active}
             for name, (status, active) in wanted.items()}
    lab.check("green", "Only the independently corroborated marking changes priority for the exact artifact and component",
              decisions["approved"]["source"] == "accepted" and all(valid.values()), valid)
    conflict = decisions["conflicting-claims"]["decisions"]["absent"]
    unsubstantiated = decisions["unsubstantiated"]["decisions"]["remediate"]
    kept = result["raw_findings"] == inputs["findings"]
    lab.check("positive", "Conflicting or unsupported assertions keep review active and retain the original report",
              conflict == {"disposition": "ambiguous", "needs_review": True}
              and unsubstantiated == {"disposition": "not_affected", "needs_review": True} and kept,
              {"conflicting_finding_active": conflict["needs_review"],
               "uncorroborated_finding_active": unsubstantiated["needs_review"],
               "all_original_findings_retained": kept})
    (lab.evidence / "synthetic-vex-decisions.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
