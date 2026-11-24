"""Verify Flux Git commit signature enforcement at the source-to-reconcile path."""
from base64 import b64encode
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import tempfile
import time

HERE = Path(__file__).resolve().parent
FLUX_RELEASE = "v2.9.0"
FLUX_INSTALL_URL = (
    "https://github.com/fluxcd/flux2/releases/download/"
    f"{FLUX_RELEASE}/install.yaml"
)
INSTALL_SHA256 = "52f93e9c17710c55eb3cc547eeef54c86c72cf93063317fbec498743dccbcbf2"
SOURCE_TAG = "ghcr.io/fluxcd/source-controller:v1.9.1"
KUSTOMIZE_TAG = "ghcr.io/fluxcd/kustomize-controller:v1.9.1"
SOURCE_IMAGE = SOURCE_TAG + "@sha256:773a90fa26e014d4f23d5c6a48ca5875c4686bdc6aac2ea73951b9cd9fda48dd"
KUSTOMIZE_IMAGE = KUSTOMIZE_TAG + "@sha256:ae1a90c0c76d518618c5e2a64b82b6476c8213aa7a2b17ec8b94828f0230a6b8"
GIT_IMAGE = ("docker.io/library/buildpack-deps:bookworm-scm@sha256:"
             "5bac6b3020afcf0358de87990605d5dc4c3f060629381912266b9b9278375af3")
BUILDER_IMAGE = ("docker.io/library/golang:1.26.0-alpine@sha256:"
                 "d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5")
NAMESPACE = "saf-test"
GIT_SERVER = "saf-signed-git"
GIT_BASE = f"http://{GIT_SERVER}.{NAMESPACE}.svc.cluster.local:8080/fixture"
NEGATIVE_NAMESPACE = "saf-signature-negative"
VERIFICATION_FAILED = {"status": "False", "reason": "InvalidCommitSignature"}
CASES = {
    "baseline-unsigned": ("baseline-unsigned", False, NAMESPACE),
    "trusted-signed": ("trusted-signed", True, NAMESPACE),
    "verified-unsigned": ("baseline-unsigned", True, NEGATIVE_NAMESPACE),
    "untrusted-signed": ("untrusted-signed", True, NEGATIVE_NAMESPACE),
}
SCOPE = (
    "One disposable framework-runner Kind cluster. Flux v2.9.0 installs the "
    "source-controller v1.9.1 and kustomize-controller v1.9.1. Three independent "
    "case-owned Git checkouts serve inert ConfigMap markers over in-cluster Smart "
    "read-only HTTP: unsigned without verification, trusted signed with HEAD "
    "verification, unsigned with verification, and signed by an untrusted key. "
    "Synthetic private keys are generated in the runner temporary directory. "
    "A separate local Gitea repository verifies signed commits, exact protected branch "
    "rules, required review and status, and fast-forward promotion of the exact signed "
    "PR head. Actual hosted policy and production key custody require deployed evidence."
)


def require_commands(lab):
    for binary in ("git", "gpg", "gpgconf", "curl"):
        if not shutil.which(binary):
            lab.block(f"Required host command is unavailable: {binary}")


def wait_until(lab, predicate, description, timeout=240):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(3)
    lab.block(f"Timed out waiting for {description}")


def json_resource(lab, *args, allow_failure=False):
    result = lab.kubectl(*args, "-o", "json", allow_failure=allow_failure)
    if result.returncode:
        return None
    return json.loads(result.stdout)


def condition(resource, kind):
    for item in resource.get("status", {}).get("conditions", []):
        if item.get("type") == kind:
            return {"status": item.get("status"), "reason": item.get("reason")}
    return None


def flux_images(lab):
    rows = json_resource(lab, "-n", "flux-system", "get", "deployments")
    actual = {}
    for row in rows["items"]:
        name = row["metadata"]["name"]
        if name in {"source-controller", "kustomize-controller"}:
            actual[name] = [c["image"] for c in row["spec"]["template"]["spec"]["containers"]]
    return actual


def install_flux(lab):
    manifest = lab.kubeconfig.with_name("flux-v2.9.0-install.yaml")
    lab.command("curl", "-fsSL", "--max-time", "60", FLUX_INSTALL_URL,
                "-o", str(manifest), timeout=70)
    if sha256(manifest.read_bytes()).hexdigest() != INSTALL_SHA256:
        lab.block("Flux v2.9.0 install artifact failed the SHA-256 check")
    text = manifest.read_text()
    expected = {SOURCE_TAG, KUSTOMIZE_TAG}
    if not expected.issubset(set(re.findall(r"^\s*image:\s*(\S+)", text, re.MULTILINE))):
        lab.block("Flux v2.9.0 artifact did not contain both expected controller tags")
    documents = []
    for document in text.split("\n---\n"):
        if re.search(r"^kind: Deployment$", document, re.MULTILINE) and not any(tag in document for tag in expected):
            continue
        documents.append(document.replace(SOURCE_TAG, SOURCE_IMAGE).replace(KUSTOMIZE_TAG, KUSTOMIZE_IMAGE))
    manifest.write_text("\n---\n".join(documents))
    lab.kubectl("-n", "flux-system", "apply", "--server-side", "-f", str(manifest), timeout=180)
    wait_until(lab, lambda: all(
        (json_resource(lab, "-n", "flux-system", "get", "deployment", name)
         or {}).get("status", {}).get("availableReplicas", 0) >= 1
        for name in ("source-controller", "kustomize-controller")
    ), "the Flux source and Kustomize controllers to become available", timeout=360)
    images = flux_images(lab)
    lab.check("positive", "The source and downstream consumer use the pinned Flux v2.9.0 component images",
              images == {"source-controller": [SOURCE_IMAGE],
                         "kustomize-controller": [KUSTOMIZE_IMAGE]},
              {"source_controller": images.get("source-controller", []),
               "kustomize_controller": images.get("kustomize-controller", [])})


def key_fingerprint(lab, home):
    output = lab.command("gpg", "--batch", "--homedir", str(home),
                         "--with-colons", "--list-secret-keys").stdout
    for line in output.splitlines():
        fields = line.split(":")
        if fields[0] == "fpr":
            return fields[9]
    lab.block("Could not read the synthetic GPG key fingerprint")


def create_key(lab, root, username, email):
    home = root / username
    home.mkdir(mode=0o700, parents=True)
    lab.command("gpg", "--batch", "--homedir", str(home), "--pinentry-mode", "loopback",
                "--passphrase", "", "--quick-generate-key",
                f"{username} <{email}>", "rsa2048", "sign", "0", timeout=90)
    return home, key_fingerprint(lab, home)


def commit_fixture(lab, root, name, key_home=None, fingerprint=None):
    work = root / f"work-{name}"
    shutil.copytree(HERE / "fixtures" / name, work)
    lab.command("git", "init", "--template=", "--object-format=sha1", "--initial-branch=main", str(work))
    lab.command("git", "-C", str(work), "-c", "core.autocrlf=false", "add", "--", "source")
    home_arg = [f"GNUPGHOME={key_home}"] if key_home else []
    args = ["git", "-C", str(work), "-c", "user.name=SAF isolated fixture",
            "-c", f"user.email={name}@example.invalid", "-c", "core.hooksPath=/dev/null",
            "-c", "commit.gpgsign=true" if key_home else "commit.gpgsign=false"]
    if key_home:
        args += ["-c", "gpg.format=openpgp", "-c", f"user.signingkey={fingerprint}",
                 "-c", "gpg.program=gpg"]
    args += ["commit", "-m", f"inert {name} fixture"]
    lab.command("env", "GIT_AUTHOR_DATE=2026-01-01T00:00:00+00:00",
                "GIT_COMMITTER_DATE=2026-01-01T00:00:00+00:00", *home_arg, *args, timeout=90)
    revision = lab.command("git", "-C", str(work), "rev-parse", "HEAD").stdout.strip()
    if key_home:
        lab.command("env", f"GNUPGHOME={key_home}", "git", "-C", str(work),
                    "-c", "gpg.format=openpgp", "-c", "gpg.program=gpg", "verify-commit", revision)
    else:
        commit = lab.command("git", "-C", str(work), "cat-file", "commit", revision).stdout
        if any(line.startswith("gpgsig ") for line in commit.partition("\n\n")[0].splitlines()):
            lab.block("Unsigned fixture unexpectedly contains a commit signature")
    bare = root / f"{name}.git"
    lab.command("git", "clone", "--bare", "--template=", str(work), str(bare), timeout=90)
    # File projection into the fixture Pod cannot preserve empty directories.
    # Keep a loose branch so Git sees a refs tree even when the clone packed it.
    branch = bare / "refs" / "heads" / "main"
    branch.parent.mkdir(parents=True, exist_ok=True)
    branch.write_text(revision + "\n")
    (bare / "git-daemon-export-ok").touch()
    lab.command("git", "--git-dir", str(bare), "config", "http.receivepack", "false")
    return bare, revision


def install_git_server(lab, repositories):
    data = {"git-server.go": b64encode((HERE / "git-server.go").read_bytes()).decode("ascii")}
    projection = [{"key": "git-server.go", "path": "git-server.go"}]
    container_security = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                          "capabilities": {"drop": ["ALL"]}}
    for case_name, bare in repositories.items():
        for path in sorted(p for p in bare.rglob("*") if p.is_file()):
            key = f"file-{len(data):05d}"
            data[key] = b64encode(path.read_bytes()).decode("ascii")
            relative = path.relative_to(bare).as_posix()
            projection.append({"key": key, "path": f"repos/{case_name}.git/{relative}"})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": GIT_SERVER}, "immutable": True,
                "binaryData": data})
    lab.create({"apiVersion": "apps/v1", "kind": "Deployment",
                "metadata": {"name": GIT_SERVER},
                "spec": {"replicas": 1,
                         "selector": {"matchLabels": {"app": GIT_SERVER}},
                         "template": {"metadata": {"labels": {"app": GIT_SERVER}},
                                      "spec": {
                                          "automountServiceAccountToken": False,
                                          "securityContext": {
                                              "runAsNonRoot": True, "runAsUser": 10001,
                                              "runAsGroup": 10001, "fsGroup": 10001,
                                              "seccompProfile": {"type": "RuntimeDefault"}},
                                          "volumes": [{"name": "repos", "configMap": {
                                              "name": GIT_SERVER, "items": projection}},
                                                      {"name": "tools", "emptyDir": {}}],
                                          "initContainers": [{
                                              "name": "build-fixture-server", "image": BUILDER_IMAGE,
                                              "command": ["/bin/sh", "-ec",
                                                  "mkdir /tools/repos && cp -RL /git/repos/. /tools/repos/"
                                                  " && /usr/local/go/bin/go build -trimpath"
                                                  " -o /tools/git-fixture /git/git-server.go"],
                                              "env": [{"name": key, "value": value} for key, value in {
                                                  "CGO_ENABLED": "0", "GOCACHE": "/tools/cache",
                                                  "GOTMPDIR": "/tools", "GOPROXY": "off",
                                                  "GOTOOLCHAIN": "local"}.items()],
                                              "volumeMounts": [{"name": "tools", "mountPath": "/tools"},
                                                               {"name": "repos", "mountPath": "/git", "readOnly": True}],
                                              "securityContext": container_security}],
                                          "containers": [{
                                              "name": "http", "image": GIT_IMAGE,
                                              "command": ["/tools/git-fixture"],
                                              "ports": [{"name": "http", "containerPort": 8080}],
                                              "readinessProbe": {"httpGet": {
                                                  "path": "/ready",
                                                  "port": "http"},
                                                  "periodSeconds": 2},
                                              "resources": {
                                                  "requests": {"cpu": "10m", "memory": "24Mi"},
                                                  "limits": {"cpu": "100m", "memory": "64Mi"}},
                                              "securityContext": container_security,
                                              "volumeMounts": [{"name": "tools", "mountPath": "/tools",
                                                                "readOnly": True}]}]}}}})
    lab.create({"apiVersion": "v1", "kind": "Service",
                "metadata": {"name": GIT_SERVER},
                "spec": {"selector": {"app": GIT_SERVER},
                         "ports": [{"name": "http", "port": 8080, "targetPort": "http"}]}})
    lab.kubectl("rollout", "status", f"deployment/{GIT_SERVER}", "--timeout=90s", timeout=100)


def install_trusted_key(lab, trusted_home, fingerprint, root):
    public_key = lab.command("gpg", "--batch", "--homedir", str(trusted_home),
                             "--armor", "--export", fingerprint).stdout
    path = root / "trusted.asc"
    path.write_text(public_key)
    lab.kubectl("create", "secret", "generic", "saf-commit-trust",
                f"--from-file=trusted.asc={path}", "--type=Opaque")


def resource_pair(name, repository, verify, target_namespace):
    source = {"apiVersion": "source.toolkit.fluxcd.io/v1", "kind": "GitRepository",
              "metadata": {"name": f"source-{name}"},
              "spec": {"interval": "30s", "url": f"{GIT_BASE}/{repository}.git",
                       "ref": {"branch": "main"}}}
    if verify:
        source["spec"]["verify"] = {"mode": "HEAD",
                                     "secretRef": {"name": "saf-commit-trust"}}
    reconcile = {"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization",
                 "metadata": {"name": f"apply-{name}"},
                 "spec": {"interval": "30s", "timeout": "1m", "path": "./source",
                          "prune": True, "wait": True, "targetNamespace": target_namespace,
                          "sourceRef": {"kind": "GitRepository", "name": f"source-{name}"}}}
    return source, reconcile


def apply_fixtures(lab, revisions):
    for name, (repository, verify, target_namespace) in CASES.items():
        source, reconcile = resource_pair(name, repository, verify, target_namespace)
        lab.create(source)
        lab.create(reconcile)
    wait_until(lab, lambda: (
        condition(json_resource(lab, "get", "kustomization", "apply-baseline-unsigned") or {}, "Ready")
        == {"status": "True", "reason": "ReconciliationSucceeded"}
        and configmap_value(lab, "marker-baseline-unsigned") == "saf-fixture-baseline-unsigned"
    ), "the unsigned baseline source to reconcile its inert marker")
    baseline_source = json_resource(lab, "get", "gitrepository", "source-baseline-unsigned")
    baseline_kustomization = json_resource(lab, "get", "kustomization", "apply-baseline-unsigned")
    baseline = {
        "source_ready": condition(baseline_source, "Ready")["status"],
        "verification_condition_absent": condition(baseline_source, "SourceVerified") is None,
        "kustomization_ready": condition(baseline_kustomization, "Ready")["status"],
        "marker_present": configmap_value(lab, "marker-baseline-unsigned") == "saf-fixture-baseline-unsigned",
        "applied_revision_matches_checkout": baseline_kustomization.get("status", {}).get("lastAppliedRevision", "").endswith(revisions["baseline-unsigned"]),
    }
    lab.check("red", "Without source verification, Flux consumes the unsigned HEAD and applies its inert marker",
              baseline["source_ready"] == "True" and baseline["verification_condition_absent"]
              and baseline["kustomization_ready"] == "True" and baseline["marker_present"]
              and baseline["applied_revision_matches_checkout"], baseline)

    wait_until(lab, lambda: (
        condition(json_resource(lab, "get", "kustomization", "apply-trusted-signed") or {}, "Ready")
        == {"status": "True", "reason": "ReconciliationSucceeded"}
        and condition(json_resource(lab, "get", "gitrepository", "source-trusted-signed") or {},
                      "SourceVerified") == {"status": "True", "reason": "Succeeded"}
        and configmap_value(lab, "marker-trusted-signed") == "saf-fixture-trusted-signed"
    ), "the trusted signed source to verify and reconcile")
    trusted_source = json_resource(lab, "get", "gitrepository", "source-trusted-signed")
    trusted_kustomization = json_resource(lab, "get", "kustomization", "apply-trusted-signed")
    trusted = {
        "source_ready": condition(trusted_source, "Ready")["status"],
        "source_verified": condition(trusted_source, "SourceVerified"),
        "kustomization_ready": condition(trusted_kustomization, "Ready")["status"],
        "marker_present": configmap_value(lab, "marker-trusted-signed") == "saf-fixture-trusted-signed",
        "applied_revision_matches_checkout": trusted_kustomization.get("status", {}).get("lastAppliedRevision", "").endswith(revisions["trusted-signed"]),
    }
    lab.check("positive", "A trusted synthetic signed HEAD verifies and reaches the downstream Flux Kustomization",
              trusted["source_ready"] == "True" and trusted["source_verified"]
              == {"status": "True", "reason": "Succeeded"}
              and trusted["kustomization_ready"] == "True" and trusted["marker_present"]
              and trusted["applied_revision_matches_checkout"], trusted)

    rejected = {}
    for name in ("verified-unsigned", "untrusted-signed"):
        wait_until(lab, lambda n=name: (
            condition(json_resource(lab, "get", "gitrepository", f"source-{n}") or {}, "Ready")
            and condition(json_resource(lab, "get", "gitrepository", f"source-{n}") or {},
                          "SourceVerified") == VERIFICATION_FAILED
            and condition(json_resource(lab, "get", "kustomization", f"apply-{n}") or {}, "Ready")
            and condition(json_resource(lab, "get", "kustomization", f"apply-{n}") or {}, "Ready")["status"] == "False"
            and configmap_value(lab, f"marker-{CASES[n][0]}", NEGATIVE_NAMESPACE) is None
        ), f"the {name} source to fail verification without applying its marker")
        source = json_resource(lab, "get", "gitrepository", f"source-{name}")
        reconcile = json_resource(lab, "get", "kustomization", f"apply-{name}")
        rejected[name] = {
            "source_not_ready": condition(source, "Ready")["status"] != "True",
            "source_verified": condition(source, "SourceVerified"),
            "kustomization_ready": condition(reconcile, "Ready")["status"],
            "marker_absent": configmap_value(lab, f"marker-{CASES[name][0]}", NEGATIVE_NAMESPACE) is None,
            "source_artifact_absent": source.get("status", {}).get("artifact") is None,
            "exact_commit_named": any(revisions[CASES[name][0]] in item.get("message", "")
                                      for item in source["status"]["conditions"]
                                      if item["type"] == "SourceVerified"),
        }
    lab.check("green", "Unsigned and untrusted signed HEADs fail Flux verification and do not reconcile their inert markers",
              all(row["source_not_ready"]
                  and row["source_verified"] == VERIFICATION_FAILED
                  and row["kustomization_ready"] == "False" and row["marker_absent"]
                  and row["source_artifact_absent"] and row["exact_commit_named"]
                  for row in rejected.values()), rejected)


def configmap_value(lab, name, namespace=NAMESPACE):
    output = lab.kubectl("-n", namespace, "get", "configmap", name,
                         "--ignore-not-found", "-o", "json").stdout
    return json.loads(output).get("data", {}).get("value") if output.strip() else None


def run(lab):
    require_commands(lab)
    from importlib.util import module_from_spec, spec_from_file_location

    spec = spec_from_file_location("saf_gitea_branch", HERE / "gitea_branch.py")
    gitea = module_from_spec(spec)
    spec.loader.exec_module(gitea)
    gitea.run(lab)
    root = lab.kubeconfig.parent / "signed-commit-fixture"
    root.mkdir(mode=0o700)
    repositories, revisions = {}, {}
    # Avoid the UNIX socket path limit on hosts with a long default temp path.
    with tempfile.TemporaryDirectory(prefix="saf-sign-", dir="/tmp") as directory:
        key_root = Path(directory).resolve()
        try:
            trusted = create_key(lab, key_root, "trusted", "trusted@example.invalid")
            untrusted = create_key(lab, key_root, "untrusted", "untrusted@example.invalid")
            for name, key in (("baseline-unsigned", ()), ("trusted-signed", trusted),
                              ("untrusted-signed", untrusted)):
                repositories[name], revisions[name] = commit_fixture(lab, root, name, *key)
            install_trusted_key(lab, *trusted, root)
        finally:
            for key_home in key_root.iterdir():
                if key_home.is_dir():
                    lab.command("gpgconf", "--homedir", str(key_home), "--kill", "gpg-agent",
                                allow_failure=True)
    install_flux(lab)
    lab.kubectl("create", "namespace", NEGATIVE_NAMESPACE)
    install_git_server(lab, repositories)
    trusted_repo = "/tools/repos/trusted-signed.git"
    local_head = lab.kubectl("exec", f"deployment/{GIT_SERVER}", "-c", "http", "--",
                             "git", "--git-dir", trusted_repo, "rev-parse", "HEAD", timeout=20).stdout.strip()
    reached = lab.kubectl("exec", f"deployment/{GIT_SERVER}", "-c", "http", "--",
                          "git", "ls-remote", f"{GIT_BASE}/trusted-signed.git",
                          "refs/heads/main", allow_failure=True, timeout=20)
    matches = local_head == revisions["trusted-signed"] and reached.returncode == 0 and reached.stdout.strip().split() == [
        revisions["trusted-signed"], "refs/heads/main",
    ]
    if not matches:
        lab.kubectl("logs", f"deployment/{GIT_SERVER}", "-c", "http", "--tail=30", allow_failure=True)
    lab.check("positive", "The owned Git Smart HTTP service advertises the exact signed fixture HEAD",
              matches, {"advertised_revision_matches": matches})
    apply_fixtures(lab, revisions)
