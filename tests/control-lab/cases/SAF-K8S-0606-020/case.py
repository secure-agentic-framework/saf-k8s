"""Check the merged values and exact local dependency bytes before installing a fixture chart."""

import hashlib
import json
from pathlib import Path
import tempfile

SCOPE = "An owned Helm chart and vendored dependency that create public ConfigMaps in Kind."
CHART = "saf-values"
DEPENDENCY = "saf-dependency"
TAG = "0.1.0"
TEMPLATE = '''apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}%s
data:
  marker: {{ .Values.marker | quote }}
'''


def fixture(path, name, marker, suffix, *, dependency=False):
    (path / "templates").mkdir(parents=True)
    metadata = f"apiVersion: v2\nname: {name}\nversion: {TAG}\n"
    if dependency:
        metadata += (f"dependencies:\n  - name: {DEPENDENCY}\n    version: {TAG}\n"
                     f"    repository: file://../{DEPENDENCY}\n")
    (path / "Chart.yaml").write_text(metadata)
    (path / "values.yaml").write_text(f"marker: {marker}\n")
    (path / "templates" / "marker.yaml").write_text(TEMPLATE % suffix)


def live_helm(lab, *args, **kwargs):
    return lab.command("helm", *args, "--namespace", "saf-test", "--kubeconfig", str(lab.kubeconfig),
                       "--kube-context", f"kind-{lab.cluster}", **kwargs)


def marker(lab, name):
    observed = lab.kubectl("get", "configmap", name, "-o", "json", "--ignore-not-found").stdout
    return json.loads(observed)["data"]["marker"] if observed.strip() else None


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def install_bound(lab, release, path, archive, expected, values):
    if sha(archive.read_bytes()) != expected:
        return False
    live_helm(lab, "install", release, str(path), "-f", str(values), "--set-string", "marker=approved-cli")
    return True


def demonstrate(lab, root):
    parent = root / CHART
    child = root / DEPENDENCY
    fixture(parent, CHART, "approved-default", "", dependency=True)
    fixture(child, DEPENDENCY, "public-dependency-v1", "-dependency")
    repo_config = root / "repositories.yaml"
    repo_config.write_text("repositories: []\n")
    repo_options = ("--skip-refresh", "--repository-config", str(repo_config), "--repository-cache", str(root / "cache"))
    lab.command("helm", "dependency", "update", str(parent), *repo_options)
    lockfile = parent / "Chart.lock"
    reviewed_lock = lockfile.read_bytes()
    dependency_archive = parent / "charts" / f"{DEPENDENCY}-{TAG}.tgz"
    reviewed_archive = dependency_archive.read_bytes()
    approved_hash = sha(reviewed_archive)
    live_helm(lab, "install", "unchecked-values", str(parent), "--set-string", "marker=outside-approved-values")
    ungoverned = marker(lab, "unchecked-values") == "outside-approved-values"
    lab.check("red", "The chart without schema accepts the extra public marker value", ungoverned,
              {"unchecked_override_reached_api": ungoverned})
    schema = {"type": "object", "required": ["marker"], "additionalProperties": False,
              "properties": {"marker": {"type": "string", "enum": ["approved-default", "approved-file", "approved-cli"]},
                             DEPENDENCY: {"type": "object"}, "global": {"type": "object"}}}
    (parent / "values.schema.json").write_text(json.dumps(schema))
    denied = live_helm(lab, "install", "checked-values", str(parent), "--set-string", "marker=outside-approved-values",
                       allow_failure=True)
    refused = denied.returncode != 0 and "specifications of the schema" in denied.stderr and "marker" in denied.stderr
    lab.check("green", "Helm validates the merged values and refuses the same unapproved override",
              refused and marker(lab, "checked-values") is None, {"schema_denied_override": refused})
    values = root / "approved-values.yaml"
    values.write_text("marker: approved-file\n")
    (child / "values.yaml").write_text("marker: public-dependency-v2\n")
    lab.command("helm", "dependency", "build", str(parent), *repo_options)
    rebuilt_hash = sha(dependency_archive.read_bytes())
    rendered = lab.command("helm", "template", "unchanged-lock", str(parent)).stdout
    same_lock = lockfile.read_bytes() == reviewed_lock
    different_package = rebuilt_hash != approved_hash and "public-dependency-v2" in rendered
    lab.check("red", "An unchanged Chart.lock permits reconstruction with different same-version fixture bytes",
              same_lock and different_package, {"lock_unchanged": same_lock, "changed_payload_rendered": different_package})
    rejected = not install_bound(lab, "changed-dependency", parent, dependency_archive, approved_hash, values)
    lab.check("green", "The independent archive digest gate stops the different dependency before install",
              rejected and marker(lab, "changed-dependency") is None, {"changed_dependency_denied": rejected})
    dependency_archive.write_bytes(reviewed_archive)
    installed = install_bound(lab, "approved-values", parent, dependency_archive, approved_hash, values)
    merged = marker(lab, "approved-values") == "approved-cli"
    correct_dependency = marker(lab, "approved-values-dependency") == "public-dependency-v1"
    lab.check("positive", "The allowed CLI value and exact approved dependency are deployed",
              installed and merged and correct_dependency,
              {"merged_value_confirmed": merged, "approved_dependency_confirmed": correct_dependency})
    return {"helm": lab.command("helm", "version", "--short").stdout.strip(),
            "approved_archive_sha256": approved_hash, "rebuilt_archive_sha256": rebuilt_hash,
            "lock_unchanged": same_lock, "schema_denial": refused, "approved_install_confirmed": installed and merged and correct_dependency}


def run(lab):
    with tempfile.TemporaryDirectory(prefix="saf-helm-values-") as tmp:
        report = demonstrate(lab, Path(tmp))
    (lab.evidence / "values-and-dependency-observations.json").write_text(json.dumps(report, indent=2) + "\n")
