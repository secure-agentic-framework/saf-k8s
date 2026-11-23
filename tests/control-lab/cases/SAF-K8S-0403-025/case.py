"""Test the coverage of independent synthetic secret-detection sources."""
from hashlib import sha256
from io import BytesIO
import json
import tarfile
from zipfile import ZipFile

from fixtures import container, pod

SCOPE = (
    "Exact public-marker detection in real local Git history, BuildKit OCI layers, retained "
    "ZIP artifacts, Kubernetes Pod stdout and a Kubernetes-backed fixture log sink. The "
    "case routes source-specific findings into a fixture alert queue. Production scanner "
    "rules, centralized log platforms, alert delivery targets and timelines need separate evidence."
)
MARKER = "SAF_PUBLIC_SYNTHETIC_SCAN_FIXTURE_0403"
CLEAN = "SAF_PUBLIC_SYNTHETIC_SCAN_EXAMPLE_0403"
SURFACES = ("artifact", "image", "log-sink", "repo", "runtime")
LABEL = "saf-k8s.example/fixture-alert"
RELATIVE = "release-note.txt"


def git(lab, root, *args, allow_failure=False):
    return lab.command(
        "env", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
        "GIT_AUTHOR_NAME=SAF fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid",
        "GIT_COMMITTER_NAME=SAF fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid",
        "git", "-C", str(root), *args, allow_failure=allow_failure,
    )


def source_history(lab, root, message):
    root.mkdir()
    git(lab, root, "init", "--template=", "--initial-branch=main")
    (root / RELATIVE).write_text(message + "\n")
    git(lab, root, "add", "--", RELATIVE)
    git(lab, root, "commit", "-m", "old fixture content")
    git(lab, root, "rm", "--", RELATIVE)
    git(lab, root, "commit", "-m", "fixture content no longer at head")


def repo_findings(lab, root):
    findings = []
    for rev in git(lab, root, "rev-list", "--all").stdout.splitlines():
        grep = git(lab, root, "grep", "-l", "-F", MARKER, rev, "--", allow_failure=True)
        if grep.returncode not in (0, 1):
            lab.block("The isolated repository could not be scanned")
        if grep.returncode == 0:
            findings.append(RELATIVE)
    return sorted(set(findings))


def release_image(lab, root, message):
    source = root / "build"
    source.mkdir()
    (source / "Dockerfile").write_text(f"FROM scratch\nCOPY {RELATIVE} /{RELATIVE}\n")
    (source / RELATIVE).write_text(message + "\n")
    archive = root / "image.oci.tar"
    lab.command("docker", "buildx", "build", "--provenance=false",
                "--output", f"type=oci,dest={archive}", str(source), timeout=100)
    return archive


def blob(archive, reference):
    algorithm, key = reference["digest"].split(":", 1)
    assert algorithm == "sha256"
    source = archive.extractfile(f"blobs/{algorithm}/{key}")
    data = source.read()
    if sha256(data).hexdigest() != key or len(data) != reference["size"]:
        raise ValueError("BuildKit OCI descriptor does not match its content")
    return data


def image_findings(filename):
    findings = []
    with tarfile.open(filename, "r:*") as archive:
        index = json.load(archive.extractfile("index.json"))
        manifest = json.loads(blob(archive, index["manifests"][0]))
        for layer in manifest["layers"]:
            with tarfile.open(fileobj=BytesIO(blob(archive, layer)), mode="r:*") as content:
                for entry in content.getmembers():
                    if entry.isfile() and MARKER.encode() in content.extractfile(entry).read():
                        findings.append(entry.name)
    return sorted(set(findings))


def make_artifact(root, message):
    filename = root / "retained.zip"
    with ZipFile(filename, "w") as archive:
        archive.writestr(RELATIVE, message + "\n")
    return filename


def artifact_findings(filename):
    with ZipFile(filename) as archive:
        return sorted(name for name in archive.namelist() if MARKER.encode() in archive.read(name))


def runtime_line(lab, name, message):
    unit = container("app", command=["sh", "-c", 'printf "%s\\n" "$1"', "probe", message])
    lab.create(pod(name, [unit], automountServiceAccountToken=False))
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{name}", "--timeout=95s", timeout=105)
    return lab.kubectl("logs", f"pod/{name}").stdout


def indexed_line(lab, name, stdout):
    record_name = f"{name}-sink"
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": record_name},
                "data": {"source": name, "line": stdout}})
    doc = json.loads(lab.kubectl("get", "configmap", record_name, "-o", "json").stdout)
    return doc["data"]["source"], doc["data"]["line"]


def route(lab, surface, location):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": f"alert-{surface}", "labels": {LABEL: "yes"}},
                "data": {"rule": "owned-public-fixture-rule", "surface": surface,
                         "location": location, "destination": "fixture-security-queue"}})


def recorded_alerts(lab):
    out = lab.kubectl("get", "configmaps", "-l", f"{LABEL}=yes", "-o", "json").stdout
    return {entry["data"]["surface"]: (entry["data"]["location"], entry["data"]["destination"])
            for entry in json.loads(out)["items"]}


def collect(lab, root, label, message):
    root.mkdir()
    repo = root / "source"
    source_history(lab, repo, message)
    image = release_image(lab, root, message)
    artifact = make_artifact(root, message)
    runtime = runtime_line(lab, label, message)
    indexed_source, indexed = indexed_line(lab, label, runtime)
    return {"repo": lambda: repo_findings(lab, repo),
            "image": lambda: image_findings(image),
            "artifact": lambda: artifact_findings(artifact),
            "runtime": lambda: [label] if MARKER in runtime else [],
            "log-sink": lambda: [indexed_source + "-sink"] if MARKER in indexed else []}


def run(lab):
    root = lab.kubeconfig.parent
    marked = collect(lab, root / "marked", "fixture-marked-runtime", MARKER)
    only_repo = marked["repo"]()
    if only_repo:
        route(lab, "repo", only_repo[0])
    baseline_findings = recorded_alerts(lab)
    baseline = {"covered_surfaces": sorted(baseline_findings),
                "unmeasured_surfaces": sorted(set(SURFACES) - {"repo"}),
                "historical_git_match": only_repo == [RELATIVE]}
    lab.check("red", "Repository-only scanning finds the historical marker and leaves four independent surfaces unmeasured",
              set(baseline_findings) == {"repo"} and baseline["historical_git_match"], baseline)

    for surface in SURFACES:
        if surface != "repo":
            locations = marked[surface]()
            if locations:
                route(lab, surface, locations[0])
    findings = recorded_alerts(lab)
    expected = {
        "artifact": RELATIVE, "image": RELATIVE, "repo": RELATIVE,
        "runtime": "fixture-marked-runtime", "log-sink": "fixture-marked-runtime-sink",
    }
    alert_queue = {surface: location for surface, (location, target) in findings.items()
                   if target == "fixture-security-queue"}
    lab.check("green", "Independent collectors send each marker with its own source to the fixture alert queue",
              alert_queue == expected, {"routed_alerts": alert_queue})

    clean = collect(lab, root / "clean", "fixture-clean-runtime", CLEAN)
    clean_matches = sorted(surface for surface, collector in clean.items() if collector())
    lab.check("positive", "The public nonmatching example produces no finding on any exercised surface",
              not clean_matches, {"clean_match_sources": clean_matches, "scanned_sources": sorted(clean)})
    (lab.evidence / "secret-detection-coverage-observations.json").write_text(json.dumps({
        "repository_only": baseline, "source_specific_alerts": alert_queue,
        "clean_match_sources": clean_matches,
    }, indent=2) + "\n")
