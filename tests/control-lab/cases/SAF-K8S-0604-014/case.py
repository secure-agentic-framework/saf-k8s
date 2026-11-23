"""Verify the signed source linkage of an exact OCI image in Kind."""
import hashlib
import importlib.util
import io
import json
import os
import platform
import shutil
import subprocess
import tarfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "source"
APPROVAL = json.loads((HERE / "approved-snapshot.json").read_text())
BUSYBOX = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
BUILDKIT = "docker.io/moby/buildkit:v0.28.0@sha256:37539dd4d60fc70968d164d3850d903a2c56f6402214a1953fbf9fcb81ada731"
STATEMENT_TYPES = {"https://in-toto.io/Statement/v1", "https://in-toto.io/Statement/v0.1"}
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
BUILDER_ID = "https://saf-k8s.invalid/lab/buildkit/v0.28.0"
SOURCE_FILES = ("Dockerfile", "build-config.json", "dependencies.lock", "payload.txt")
SCOPE = (
    "A case-owned inert Git repository is committed with fixed metadata and checked against an approved "
    "commit/tree snapshot. BuildKit builds only git-archive output with pinned lock/config inputs, exports "
    "a real OCI image and SLSA Provenance v1, and Kind must execute the exact exported manifest digest. "
    "Cosign authenticates the fixture build claims. Production trust and reproduced bytes require separate evidence."
)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git(repo, *args):
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "SAF Case", "GIT_AUTHOR_EMAIL": "saf-case@example.invalid",
        "GIT_COMMITTER_NAME": "SAF Case", "GIT_COMMITTER_EMAIL": "saf-case@example.invalid",
        "GIT_AUTHOR_DATE": APPROVAL["git_author_time"], "GIT_COMMITTER_DATE": APPROVAL["git_author_time"],
    })
    return subprocess.run(["git", "-C", str(repo), "-c", "core.autocrlf=false",
                           "-c", f"core.hooksPath={os.devnull}", *args], capture_output=True,
                          check=True, env=env, timeout=20).stdout


def initialize(destination, source):
    shutil.copytree(source, destination)
    git(destination, "init", "--quiet", "--object-format=sha1", "--template=")
    git(destination, "add", "--all")
    git(destination, "commit", "--quiet", "--no-gpg-sign", "-m", APPROVAL["commit_message"])
    return tuple(git(destination, "rev-parse", item).decode().strip() for item in ("HEAD", "HEAD^{tree}"))


def approved_snapshot(repo, source=SOURCE):
    commit, tree = initialize(repo, source)
    if (commit, tree) != (APPROVAL["commit"], APPROVAL["tree"]):
        raise ValueError("the Git commit or tree differs from the approved source")
    entries = git(repo, "ls-tree", "-r", "--full-tree", commit,
                  "--format=%(objectmode) %(path)").decode().splitlines()
    if entries != [f"100644 {name}" for name in SOURCE_FILES]:
        raise ValueError("the approved tree contains an unexpected path or file mode")
    return commit, tree


def extract_approved(repo, commit, context):
    (repo / "payload.txt").write_text("unreviewed working copy change\n")
    archive = git(repo, "archive", "--format=tar", commit)
    context.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as snapshot:
        if snapshot.pax_headers.get("comment") != commit or sorted(snapshot.getnames()) != list(SOURCE_FILES):
            raise ValueError("the archive differs from the reviewed snapshot")
        for name in SOURCE_FILES:
            data = snapshot.extractfile(name).read()
            if data != git(repo, "cat-file", "blob", f"{commit}:{name}"):
                raise ValueError(f"archive and commit differ for {name}")
            (context / name).write_bytes(data)
    return sha256(archive)


def digest_matches_subject(statement, expected):
    """Policy: exactly one in-toto subject, carrying the complete expected sha256 value."""
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1:
        return False
    digest = subjects[0].get("digest")
    return isinstance(digest, dict) and digest.get("sha256") == expected and len(expected) == 64


def claims_match(statement, image_digest, expected):
    if (statement.get("_type") not in STATEMENT_TYPES
            or statement.get("predicateType") != PREDICATE_TYPE
            or not digest_matches_subject(statement, image_digest)):
        return False
    predicate = statement.get("predicate", {})
    request = predicate["buildDefinition"]["externalParameters"]["request"]
    run = predicate["runDetails"]
    return (run["builder"]["id"] == BUILDER_ID and bool(run["metadata"].get("invocationId"))
            and request.get("frontend") == "dockerfile.v0" and request.get("args") == expected)


def load_registry():
    # In the SAF control-lab checkout this shared disposable TLS registry helper is supplied by 0605-002.
    helper = HERE.parent / "SAF-K8S-0605-002" / "image_admission.py"
    spec = importlib.util.spec_from_file_location("saf_case_registry", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build(registry, repo, commit):
    staging = registry.work / "approved-build"
    staging.mkdir(mode=0o700)
    context = staging / "context"
    archive = extract_approved(repo, commit, context)
    lock = (context / "dependencies.lock").read_bytes()
    config = (context / "build-config.json").read_bytes()
    lock_hash, config_hash = sha256(lock), sha256(config)
    if (lock_hash, config_hash) != (APPROVAL["lock_sha256"], APPROVAL["config_sha256"]):
        raise ValueError("the staged lock or configuration differs from its approved bytes")
    if lock.decode().strip() != f"busybox={BUSYBOX}" or (context / "Dockerfile").read_text().splitlines()[0] != f"FROM {BUSYBOX}":
        raise ValueError("the actual base image differs from the locked reference")
    config_values = json.loads(config)
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64"}.get(platform.machine())
    if (f"linux/{arch}" not in config_values["platforms"] or config_values["buildkit"] != BUILDKIT
            or config_values["frontend"] != "dockerfile.v0" or config_values["target"] != "default"):
        registry.lab.block("The approved build configuration could not be applied")
    args = {"build-arg:SAF_SOURCE_COMMIT": commit, "build-arg:SAF_LOCK_SHA256": lock_hash,
            "build-arg:SAF_CONFIG_SHA256": config_hash, "build-arg:SAF_SOURCE_ARCHIVE_SHA256": archive}
    options = [part for key, value in args.items() for part in ("--opt", f"{key}={value}")]
    name = f"{registry.lab.cluster}-0604-buildkit"
    registry.docker("run", "--detach", "--name", name, "--privileged", "--volume", f"{staging}:/io",
                    BUILDKIT, "--addr", "unix:///run/buildkit/buildkitd.sock", timeout=160)
    try:
        end = time.monotonic() + 25
        while registry.docker("exec", name, "buildctl", "debug", "workers", allow_failure=True).returncode:
            if time.monotonic() >= end:
                registry.lab.block("BuildKit did not become ready")
            time.sleep(0.4)
        registry.docker("exec", name, "buildctl", "build", "--frontend", config_values["frontend"],
                        "--local", "context=/io/context", "--local", "dockerfile=/io/context",
                        "--opt", f"platform=linux/{arch}", *options,
                        "--opt", f"attest:provenance=mode=max,version=v1,builder-id={BUILDER_ID}",
                        "--output", f"type=oci,name={registry.registry}/fixture/saf-provenance:case,dest=/io/image.tar",
                        timeout=180)
    finally:
        registry.docker("rm", "-fv", name)
    return staging / "image.tar", arch, args


def run_exact_image(lab, registry, ref):
    """Require the pod request and container runtime report to identify the same exact manifest."""
    host = registry.registry
    node = f"{lab.cluster}-control-plane"
    cert_dir = f"/etc/containerd/certs.d/{host}"
    hosts = registry.work / "image-hosts.toml"
    hosts.write_text(f'[host."https://{host}"]\ncapabilities = ["pull", "resolve"]\nca = "{cert_dir}/ca.crt"\n')
    registry.docker("exec", node, "mkdir", "-p", cert_dir)
    registry.docker("cp", str(hosts), f"{node}:{cert_dir}/hosts.toml")
    registry.docker("cp", str(registry.registry_ca), f"{node}:{cert_dir}/ca.crt")
    created = lab.create({
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": "saf-0604-build-output"},
        "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never",
                 "containers": [{"name": "output", "image": ref, "imagePullPolicy": "Always",
                                 "command": ["/bin/cat", "/fixture-payload"]}]},
    })
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", "pod/saf-0604-build-output",
                "--timeout=90s", timeout=100)
    live = json.loads(lab.kubectl("get", "pod", "saf-0604-build-output", "-o", "json").stdout)
    expected = ref.rsplit("@", 1)[1]
    statuses = live["status"].get("containerStatuses", [])
    image_id = statuses[0].get("imageID", "") if len(statuses) == 1 else ""
    runtime_digest = image_id.rsplit("@", 1)[1] if "@" in image_id else ""
    request_exact = (live["metadata"].get("uid") == created["metadata"].get("uid")
                     and live["spec"]["containers"][0]["image"] == ref)
    executed_exact = runtime_digest == expected
    output = lab.kubectl("logs", "saf-0604-build-output").stdout.strip()
    lab.check("positive", "Kind executed the exact BuildKit output manifest digest",
              request_exact and executed_exact and output == "SAF-K8S-0604-014 inert build output",
              {"requested_digest_exact": request_exact, "runtime_digest_exact": executed_exact,
               "payload": output})


def signed_claim(registry, example, fixture, signing, ref, predicate):
    (signing / "predicate.json").write_text(json.dumps(predicate, sort_keys=True))
    registry.cosign(signing, "attest", *fixture.FIXTURE_SIGNING, "--type", PREDICATE_TYPE,
                    "--predicate", "/work/predicate.json", ref)
    result = example.cosign_verify(registry, signing, ref)
    if result.returncode:
        registry.lab.block("The fixture key could not verify the stored provenance")
    claim, = (row for row in example.decoded_statements(result) if row["predicate"] == predicate)
    return claim


def run(lab):
    path = HERE.parent / "SAF-K8S-0603-009" / "case.py"
    spec = importlib.util.spec_from_file_location("approved_source_oci", path)
    example = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(example)
    fixture = load_registry()
    with fixture.registry(lab) as (registry, port, _):
        repo = registry.work / "inert-source"
        commit, tree = approved_snapshot(repo)
        changed_source = registry.work / "changed-source"
        shutil.copytree(SOURCE, changed_source)
        (changed_source / "payload.txt").write_text("unapproved commit bytes\n")
        try:
            approved_snapshot(registry.work / "changed-checkout", changed_source)
        except ValueError:
            changed_source_denied = True
        else:
            changed_source_denied = False
        layout, arch, args = build(registry, repo, commit)
        ref, statement, manifest = example.publish_layout(registry, port, layout, arch)
        digest = ref.rsplit("@sha256:", 1)[1]
        signing = registry.work / "provenance-signer"
        signing.mkdir(mode=0o700)
        registry.cosign(signing, "generate-key-pair")
        baseline = example.cosign_verify(registry, signing, ref)
        absent = baseline.returncode != 0 and "no matching attestations" in baseline.stderr.lower()
        lab.check("red", "The exact image exists before its signed source linkage is present",
                  absent, {"unsigned_artifact_present": absent})

        wrong = json.loads(json.dumps(statement["predicate"]))
        wrong["buildDefinition"]["externalParameters"]["request"]["args"]["build-arg:SAF_LOCK_SHA256"] = "f" * 64
        wrong_claim = signed_claim(registry, example, fixture, signing, ref, wrong)
        claim = signed_claim(registry, example, fixture, signing, ref, statement["predicate"])
        negatives = {
            "unapproved_commit_rejected": changed_source_denied,
            "signed_wrong_lock_rejected": not claims_match(wrong_claim, digest, args),
            "wrong_subject_rejected": not claims_match(claim, "0" * 64, args),
            "wrong_config_rejected": not claims_match(claim, digest, {**args, "build-arg:SAF_CONFIG_SHA256": "a" * 64}),
        }
        lab.check("green", "The release rejects incorrect source, lock, configuration and image claims",
                  all(negatives.values()), negatives)
        verified = claims_match(claim, digest, args) and sha256(manifest) == digest
        lab.check("green", "Authenticated BuildKit evidence binds the approved archive and inputs to the exact manifest",
                  verified, {"signed_source_link_verified": verified, "working_copy_change_excluded": True})
        run_exact_image(lab, registry, ref)
        (lab.evidence / "source-image-linkage.json").write_text(json.dumps({
            "source": APPROVAL["source_uri"], "commit": commit, "tree": tree, "build_args": args,
            "artifact_sha256": digest, "authenticated_build_statement": claim, "negative_results": negatives,
        }, indent=2, sort_keys=True) + "\n")
