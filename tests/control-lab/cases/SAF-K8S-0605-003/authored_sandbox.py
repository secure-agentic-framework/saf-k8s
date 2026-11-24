"""Build and exercise the owned Kubewarden WASM policy with pinned tools."""
import hashlib
import json
import os
from pathlib import Path
import shutil


HERE = Path(__file__).resolve().parent
TOOLCHAIN = "1.92.0"
TARGET = "wasm32-wasip1"
ARTIFACT = Path(TARGET) / "release" / "saf0605003_label_policy.wasm"
REFUSAL = "required label saf-k8s.example/approved must equal yes"


def _compiler(lab, scratch):
    provided = os.environ.get("SAF_KUBEWARDEN_RUST_BIN")
    if provided:
        root = Path(provided)
    else:
        rustup_home = scratch / "rustup"
        lab.command("env", f"RUSTUP_HOME={rustup_home}", "rustup", "toolchain", "install",
                    TOOLCHAIN, "--profile", "minimal", "--target", TARGET, timeout=240)
        selected = lab.command("env", f"RUSTUP_HOME={rustup_home}", "rustup", "which",
                               "--toolchain", TOOLCHAIN, "rustc")
        root = Path(selected.stdout.strip()).parent
    compiler = root / "rustc"
    build_tool = root / "cargo"
    version = lab.command(str(compiler), "--version").stdout.strip()
    if not version.startswith(f"rustc {TOOLCHAIN} "):
        lab.block("The authored policy build requires the pinned Rust compiler")
    return compiler, build_tool, version


def _build(lab, source, output, toolchain, kwctl):
    compiler, cargo, _version = toolchain
    lab.command("env", f"RUSTC={compiler}", f"CARGO_TARGET_DIR={output}",
                str(cargo), "build", "--manifest-path", str(source / "Cargo.toml"),
                "--locked", "--release", "--target", TARGET, timeout=180)
    annotated = output / "authored-policy.wasm"
    lab.command(str(kwctl), "annotate", str(output / ARTIFACT), "--metadata-path",
                str(source / "metadata.yml"), "--output-path", str(annotated))
    return annotated


def run(lab):
    scratch = lab.kubeconfig.parent / "authored-policy"
    scratch.mkdir(mode=0o700)
    source = scratch / "source"
    shutil.copytree(HERE / "authored_policy", source)
    kwctl = lab.kubeconfig.parent / "kwctl"
    compiler = _compiler(lab, scratch)
    primary = _build(lab, source, scratch / "first", compiler, kwctl)
    repeated = _build(lab, source, scratch / "second", compiler, kwctl)
    digest = hashlib.sha256(primary.read_bytes()).hexdigest()
    reproducible = primary.read_bytes() == repeated.read_bytes()
    lab.check("positive", "Two independent locked builds reproduce the same annotated policy",
              reproducible, {"toolchain": TOOLCHAIN, "reproducible": reproducible})
    result = {}
    for sample, allowed in (("valid", True), ("invalid", False)):
        reply = lab.command(str(kwctl), "--no-color", "run", "--request-path",
                            str(source / "requests" / (sample + ".json")), "--settings-json", "{}",
                            str(primary), timeout=70)
        decision = json.loads(reply.stdout)
        matched = decision.get("allowed") is allowed and (
            allowed or decision.get("status", {}).get("message") == REFUSAL)
        lab.check("positive" if allowed else "green",
                  f"The authored sandbox policy returns the expected decision for the {sample} fixture",
                  matched, {"allowed": decision.get("allowed"), "scoped_decision_matched": matched})
        result[sample] = decision
    (lab.evidence / "authored-policy-sandbox.json").write_text(json.dumps({
        "annotated_module_sha256": digest,
        "two_builds_match": reproducible,
        "compiler": compiler[2],
        "lock_sha256": hashlib.sha256((source / "Cargo.lock").read_bytes()).hexdigest(),
        "sandbox_decisions": result,
    }, indent=2) + "\n")
    return primary
