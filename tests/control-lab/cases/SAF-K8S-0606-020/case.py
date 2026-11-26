"""Check the merged values and exact local dependency bytes before installing a fixture chart."""

import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
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
POD_TEMPLATE = '''{{- if .Values.pod.enabled }}
apiVersion: v1
kind: Pod
metadata:
  name: {{ .Release.Name }}-workload
spec:
  automountServiceAccountToken: {{ .Values.pod.automountServiceAccountToken }}
  containers:
    - name: inert-fixture
      image: example.invalid/never-executed:0
{{- end }}
'''


def fixture(path, name, marker, suffix, *, dependency=False):
    (path / "templates").mkdir(parents=True)
    metadata = f"apiVersion: v2\nname: {name}\nversion: {TAG}\n"
    if dependency:
        metadata += (f"dependencies:\n  - name: {DEPENDENCY}\n    version: {TAG}\n"
                     f"    repository: file://../{DEPENDENCY}\n")
    (path / "Chart.yaml").write_text(metadata)
    defaults = f"marker: {marker}\n"
    if name == CHART:
        defaults += "pod:\n  enabled: false\n  automountServiceAccountToken: false\n"
        (path / "templates" / "service-account-workload.yaml").write_text(POD_TEMPLATE)
    (path / "values.yaml").write_text(defaults)
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
                             DEPENDENCY: {"type": "object"}, "global": {"type": "object"},
                             "pod": {"type": "object", "required": ["enabled", "automountServiceAccountToken"],
                                     "additionalProperties": False,
                                     "properties": {"enabled": {"type": "boolean"},
                                                    "automountServiceAccountToken": {"enum": [False]}}}}}
    (parent / "values.schema.json").write_text(json.dumps(schema))
    denied = live_helm(lab, "install", "checked-values", str(parent), "--set-string", "marker=outside-approved-values",
                       allow_failure=True)
    refused = denied.returncode != 0 and "specifications of the schema" in denied.stderr and "marker" in denied.stderr
    lab.check("green", "Helm validates the merged values and refuses the same unapproved override",
              refused and marker(lab, "checked-values") is None, {"schema_denied_override": refused})
    token_override = live_helm(lab, "template", "unapproved-token-mount", str(parent),
                               "--set", "pod.enabled=true", "--set", "pod.automountServiceAccountToken=true",
                               allow_failure=True)
    token_override_refused = (token_override.returncode != 0
                              and "automountServiceAccountToken" in token_override.stderr)
    lab.check("green", "The merged values schema rejects enabling Pod service-account token automount",
              token_override_refused,
              {"token_automount_true_rejected_before_any_api_write": token_override_refused})
    safe_render = live_helm(lab, "template", "approved-token-policy", str(parent),
                            "--set", "pod.enabled=true", "--set", "pod.automountServiceAccountToken=false").stdout
    safe_rendered = ("name: approved-token-policy-workload" in safe_render
                     and "automountServiceAccountToken: false" in safe_render)
    lab.check("positive", "The approved security value renders false for the inert Pod fixture",
              safe_rendered,
              {"approved_false_value_in_rendered_pod_spec": safe_rendered,
               "render_only_no_api_submission": True})
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


def write_signed_chart(path, name, marker, suffix, *, dependency=None, workload=False):
    (path / "templates").mkdir(parents=True)
    chart = f"apiVersion: v2\nname: {name}\nversion: 0.1.0\n"
    if dependency:
        chart += ("dependencies:\n"
                  f"  - name: {dependency}\n    version: 0.1.0\n"
                  f"    repository: file://../{dependency}\n")
    (path / "Chart.yaml").write_text(chart)
    (path / "values.yaml").write_text(f"marker: {marker}\n")
    (path / "templates" / "marker.yaml").write_text(TEMPLATE % suffix)
    if workload:
        (path / "values.yaml").write_text(
            "marker: approved-parent\npod:\n  enabled: false\n  replicas: 0\n"
            "  automountServiceAccountToken: false\n"
            "direct:\n  marker: approved-direct\n  nested:\n    marker: approved-nested\n")
        (path / "templates" / "deployment.yaml").write_text(
            """{{- if .Values.pod.enabled }}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-workload
spec:
  replicas: {{ .Values.pod.replicas }}
  selector:
    matchLabels:
      app: {{ .Release.Name }}-workload
  template:
    metadata:
      labels:
        app: {{ .Release.Name }}-workload
    spec:
      automountServiceAccountToken: {{ .Values.pod.automountServiceAccountToken }}
      containers:
        - name: inert-fixture
          image: example.invalid/never-executed:0
{{- end }}
""")
        (path / "values.schema.json").write_text(json.dumps({
            "type": "object", "required": ["marker", "pod", "direct"],
            "additionalProperties": False,
            "properties": {
                "marker": {"type": "string", "enum": ["approved-parent", "approved-file", "approved-cli"]},
                "direct": {"type": "object", "additionalProperties": False,
                           "required": ["marker", "nested"],
                           "properties": {"marker": {"type": "string"},
                                          "global": {"type": "object", "maxProperties": 0},
                                          "nested": {"type": "object", "required": ["marker"],
                                                     "properties": {"marker": {"type": "string"}}}}},
                "pod": {"type": "object", "additionalProperties": False,
                        "required": ["enabled", "replicas", "automountServiceAccountToken"],
                        "properties": {"enabled": {"type": "boolean"},
                                       "replicas": {"enum": [0]},
                                       "automountServiceAccountToken": {"enum": [False]}}}}}))


def chart_tree(root_bytes):
    """Canonical per-chart file digests from Helm 3.17's flattened package archive."""
    archive_files = {}
    with tarfile.open(fileobj=io.BytesIO(root_bytes), mode="r:gz") as archive:
        members = archive.getmembers()
        if any(not member.isfile() and not member.isdir() for member in members):
            raise ValueError("Unexpected non-file member in Helm chart archive")
        if any(not member.name.startswith("saf-signed-root/") for member in members):
            raise ValueError("Helm archive contains a path outside its root chart")
        files = [member for member in members if member.isfile()]
        roots = {member.name.split("/", 1)[0] for member in members if "/" in member.name}
        if roots != {"saf-signed-root"}:
            raise ValueError("Unexpected Helm chart archive root")
        for member in members:
            path = member.name.removeprefix("saf-signed-root/").rstrip("/")
            if (not path or path.startswith("/") or any(part == ".." for part in path.split("/"))):
                raise ValueError("Unsafe or unexpected Helm chart archive path")
        for member in files:
            path = member.name.removeprefix("saf-signed-root/")
            if path in archive_files:
                raise ValueError("Duplicate Helm chart archive path")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"Could not read Helm archive file {member.name}")
            archive_files[path] = stream.read()
    specs = (
        ("saf-signed-root@0.1.0", "", "charts/", "saf-signed-root"),
        ("direct@0.1.0", "charts/direct/", "charts/", "direct"),
        ("nested@0.1.0", "charts/direct/charts/nested/", "charts/", "nested"),
    )
    result = {}
    classified = set()
    for identity, prefix, child_prefix, name in specs:
        selected = {}
        for path, content in archive_files.items():
            if path.startswith(prefix) and not (child_prefix and path.startswith(prefix + child_prefix)):
                relpath = path[len(prefix):] if prefix else path
                selected[relpath] = "sha256:" + hashlib.sha256(content).hexdigest()
                classified.add(path)
        chart_yaml = archive_files.get(prefix + "Chart.yaml")
        if chart_yaml is None:
            raise ValueError(f"Helm package omitted {identity} Chart.yaml")
        metadata = chart_yaml.decode("utf-8")
        if not re.search(rf"(?m)^name:\s*{re.escape(name)}\s*$", metadata):
            raise ValueError(f"Unexpected chart identity at {prefix or '.'}")
        if not re.search(r"(?m)^version:\s*0\.1\.0\s*$", metadata):
            raise ValueError(f"Unexpected chart version at {prefix or '.'}")
        selected_rows = [{"path": path, "digest": digest} for path, digest in sorted(selected.items())]
        canonical = json.dumps(selected_rows, sort_keys=True, separators=(",", ":")).encode()
        result[identity] = {"prefix": prefix or ".", "files": selected_rows,
                            "content_digest": "sha256:" + hashlib.sha256(canonical).hexdigest()}
    if classified != set(archive_files):
        raise ValueError("Helm chart archive contains files outside the exact root/direct/transitive tree")
    return result


def release_manifest(root_bytes):
    return {"schema": "saf-helm-v3.17-chart-tree/v1",
            "root_archive": {"name": "saf-signed-root-0.1.0.tgz", "digest": sha(root_bytes)},
            "charts": chart_tree(root_bytes)}


def verify_signed_tree(manifest_bytes, signature, public_key, root_bytes):
    openssl = shutil.which("openssl")
    if not openssl:
        return False, {"signature_valid": False, "root_archive_matches": False,
                       "chart_matches": {}}
    with tempfile.TemporaryDirectory(prefix="saf-helm-verify-") as tmp:
        base = Path(tmp)
        (base / "manifest.json").write_bytes(manifest_bytes)
        (base / "manifest.sig").write_bytes(signature)
        (base / "pinned-publisher.pub").write_bytes(public_key)
        signature_check = subprocess.run(
            [openssl, "dgst", "-sha256", "-verify", str(base / "pinned-publisher.pub"),
             "-signature", str(base / "manifest.sig"), str(base / "manifest.json")],
            capture_output=True, text=True, timeout=10)
        signature_valid = signature_check.returncode == 0
    expected = json.loads(manifest_bytes)
    observed = release_manifest(root_bytes)
    root_match = expected.get("root_archive") == observed["root_archive"]
    expected_charts = expected.get("charts", {})
    all_names = set(expected_charts) | set(observed["charts"])
    chart_matches = {name: expected_charts.get(name) == observed["charts"].get(name)
                     for name in sorted(all_names)}
    matched = (expected.get("schema") == "saf-helm-v3.17-chart-tree/v1"
               and signature_valid and root_match and bool(all_names) and all(chart_matches.values()))
    return matched, {"signature_valid": signature_valid, "root_archive_matches": root_match,
                     "chart_matches": chart_matches}


def replace_chart_member(archive_bytes, suffix, replacement):
    source = tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz")
    members = source.getmembers()
    target = [m for m in members if m.name.endswith(suffix) and m.isfile()]
    if len(target) != 1:
        source.close()
        raise ValueError(f"Expected one archive member ending in {suffix}")
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as rebuilt:
        for member in members:
            if member.isfile():
                stream = source.extractfile(member)
                if stream is None:
                    raise ValueError(f"Could not read archive member {member.name}")
                data = replacement if member.name == target[0].name else stream.read()
                cloned = tarfile.TarInfo(member.name)
                cloned.size = len(data)
                cloned.mode, cloned.mtime = member.mode, member.mtime
                rebuilt.addfile(cloned, io.BytesIO(data))
            else:
                rebuilt.addfile(member)
    source.close()
    return output.getvalue()


def install_if_verified(lab, release, archive_path, manifest_path, signature_path,
                        pinned_public_key, values, set_args=()):
    """The single fixture boundary verifies exact package closure before invoking Helm."""
    root_bytes = archive_path.read_bytes()
    try:
        verified, details = verify_signed_tree(manifest_path.read_bytes(), signature_path.read_bytes(),
                                               pinned_public_key.read_bytes(), root_bytes)
    except (ValueError, OSError, tarfile.TarError, json.JSONDecodeError):
        return {"verified": False, "install_attempted": False,
                "details": {"signature_valid": False, "root_archive_matches": False,
                            "chart_matches": {}}, "helm_result": None}
    if not verified:
        return {"verified": False, "install_attempted": False, "details": details, "helm_result": None}
    with tempfile.TemporaryDirectory(prefix="saf-approved-chart-") as tmp:
        approved_archive = Path(tmp) / "verified.tgz"
        approved_archive.write_bytes(root_bytes)
        result = live_helm(lab, "install", release, str(approved_archive), "-f", str(values), *set_args,
                           allow_failure=True)
    return {"verified": True, "install_attempted": True, "details": details, "helm_result": result}


def assert_release_absent(lab, release):
    secret = lab.kubectl("get", "secret", f"sh.helm.release.v1.{release}.v1", "-o", "name",
                         "--ignore-not-found").stdout.strip()
    configmaps = [lab.kubectl("get", "configmap", name, "-o", "name", "--ignore-not-found").stdout.strip()
                  for name in (release, f"{release}-direct", f"{release}-nested")]
    deployment = lab.kubectl("get", "deployment", f"{release}-workload", "-o", "name",
                             "--ignore-not-found").stdout.strip()
    return not secret and not any(configmaps) and not deployment


def demonstrate_signed_tree(lab, root):
    """Local signed direct/transitive chart closure, with a pinned fixture trust key."""
    charts = root / "charts"
    parent, direct, nested = charts / "saf-signed-root", charts / "direct", charts / "nested"
    write_signed_chart(parent, "saf-signed-root", "approved-parent", "", dependency="direct", workload=True)
    write_signed_chart(direct, "direct", "approved-direct", "-direct", dependency="nested")
    write_signed_chart(nested, "nested", "approved-nested", "-nested")
    repo_options = ("--skip-refresh", "--repository-config", str(root / "repositories.yaml"),
                    "--repository-cache", str(root / "cache"))
    (root / "repositories.yaml").write_text("repositories: []\n")
    # A disjoint fixture trust writer enrolls keys before the release producer runs.
    trust = root / "trust-anchor"
    approved_identity = root / "approved-publisher-identity"
    alternate_identity = root / "alternate-publisher-identity"
    trust.mkdir()
    approved_identity.mkdir()
    alternate_identity.mkdir()
    pinned_public_key = trust / "approved-publisher.pub"
    approved_private_key = approved_identity / "private.pem"
    alternate_public_key = trust / "unapproved-publisher.pub"
    alternate_private_key = alternate_identity / "private.pem"
    keygen = Path(__file__).with_name("fixture_trust_anchor.py")
    subprocess.run([sys.executable, str(keygen), str(approved_private_key), str(pinned_public_key),
                    str(alternate_private_key), str(alternate_public_key)],
                   check=True, capture_output=True, text=True, timeout=20)

    lab.command("helm", "dependency", "update", str(direct), *repo_options)
    lab.command("helm", "dependency", "update", str(parent), *repo_options)
    distribution = root / "distribution"
    distribution.mkdir()
    lab.command("helm", "package", str(parent), "--destination", str(distribution))
    root_archive = next(distribution.glob("saf-signed-root-0.1.0.tgz"))
    root_bytes = root_archive.read_bytes()
    manifest_bytes = json.dumps(release_manifest(root_bytes), sort_keys=True,
                                separators=(",", ":")).encode("utf-8")

    # Release output paths are distinct from the runner-enrolled trust input.
    manifest_path, sig_path = distribution / "release.json", distribution / "release.sig"
    manifest_path.write_bytes(manifest_bytes)
    helper = Path(__file__).with_name("fixture_publisher.py")
    subprocess.run([sys.executable, str(helper), str(approved_private_key), str(manifest_path), str(sig_path)],
                   check=True, capture_output=True, text=True, timeout=15)
    values = root / "approved-installed-values.yaml"
    values.write_text("pod:\n  enabled: true\n  replicas: 0\n  automountServiceAccountToken: false\n")
    set_args = ("--set-string", "marker=approved-cli", "--set-string", "direct.marker=approved-direct-cli",
                "--set-string", "direct.nested.marker=approved-nested-cli")

    # Change a real file in the flattened transitive chart tree as loaded by Helm 3.17.
    nested_marker_path = "saf-signed-root/charts/direct/charts/nested/templates/marker.yaml"
    altered_root = replace_chart_member(
        root_bytes, nested_marker_path,
        b'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}-nested\ndata:\n  marker: "changed-nested-marker"\n')
    altered_archive = distribution / "altered-signed-root-0.1.0.tgz"
    altered_archive.write_bytes(altered_root)
    refused_archive = install_if_verified(lab, "changed-tree", altered_archive, manifest_path,
                                          sig_path, pinned_public_key, values, set_args)
    altered_absent = assert_release_absent(lab, "changed-tree")
    nested_mismatch = not refused_archive["details"]["chart_matches"].get("nested@0.1.0", True)
    lab.check("green", "The common release boundary denies altered nested bytes before Helm and leaves no API objects",
              not refused_archive["verified"] and not refused_archive["install_attempted"]
              and nested_mismatch and altered_absent,
              {"verification_denied": not refused_archive["verified"],
               "helm_install_called": refused_archive["install_attempted"],
               "nested_digest_mismatch": nested_mismatch,
               "release_and_workload_objects_absent": altered_absent})

    # Sign the unchanged release record with a second valid but non-pinned identity.
    alternate_signature = distribution / "unapproved-release.sig"
    signer = Path(__file__).with_name("fixture_sign.py")
    alternate_signature_check = subprocess.run(
        [sys.executable, str(signer), str(alternate_private_key), str(manifest_path),
         str(alternate_signature), str(alternate_public_key)],
        capture_output=True, text=True, timeout=15)
    alternate_signature_valid = alternate_signature_check.returncode == 0
    valid_alternate, _ = verify_signed_tree(manifest_bytes, alternate_signature.read_bytes(),
                                            alternate_public_key.read_bytes(), root_bytes)
    refused_signer = install_if_verified(lab, "unapproved-signer", root_archive, manifest_path,
                                         alternate_signature, pinned_public_key, values, set_args)
    signer_absent = assert_release_absent(lab, "unapproved-signer")
    lab.check("green", "The common release boundary denies a valid signature from a non-pinned key before Helm",
              alternate_signature_valid and not refused_signer["verified"]
              and not refused_signer["install_attempted"] and signer_absent,
              {"alternate_signature_valid_for_unpinned_key": alternate_signature_valid,
               "pinned_signature_denied": not refused_signer["verified"],
               "helm_install_called": refused_signer["install_attempted"],
               "release_and_workload_objects_absent": signer_absent})

    approved = install_if_verified(lab, "signed-tree", root_archive, manifest_path, sig_path,
                                   pinned_public_key, values, set_args)
    if not approved["install_attempted"] or approved["helm_result"].returncode != 0:
        lab.block("The approved signed Helm archive did not install")
    installed_root = marker(lab, "signed-tree") == "approved-cli"
    installed_direct = marker(lab, "signed-tree-direct") == "approved-direct-cli"
    installed_nested = marker(lab, "signed-tree-nested") == "approved-nested-cli"
    deployment = json.loads(lab.kubectl("get", "deployment", "signed-tree-workload", "-o", "json").stdout)
    spec = deployment["spec"]
    security = (spec["replicas"] == 0
                and spec["template"]["spec"].get("automountServiceAccountToken") is False)
    lab.check("positive", "The common release boundary installs pinned packages and readback confirms approved merged values",
              approved["verified"] and approved["install_attempted"]
              and approved["helm_result"].returncode == 0
              and installed_root and installed_direct and installed_nested and security,
              {"root_direct_nested_markers_match": installed_root and installed_direct and installed_nested,
               "signature_valid_for_pinned_key": approved["details"]["signature_valid"],
               "package_count": len(approved["details"]["chart_matches"]),
               "installed_replicas": spec["replicas"], "installed_token_automount_false": security,
               "workload_pods_created_by_fixture": False})

    prohibited = install_if_verified(lab, "rejected-token-value", root_archive, manifest_path, sig_path,
                                     pinned_public_key, values,
                                     (*set_args, "--set", "pod.automountServiceAccountToken=true"))
    token_refused = (prohibited["verified"] and prohibited["install_attempted"]
                     and prohibited["helm_result"].returncode != 0
                     and "automountServiceAccountToken" in prohibited["helm_result"].stderr)
    no_release = assert_release_absent(lab, "rejected-token-value")
    lab.check("green", "The verified release path reaches Helm but schema blocks the unsafe value before release objects exist",
              token_refused and no_release,
              {"token_value_rejected": token_refused, "release_and_workload_objects_absent": no_release})
    return {"signature_valid": approved["details"]["signature_valid"],
            "pinned_public_key_sha256": sha(pinned_public_key.read_bytes()),
            "package_count": len(approved["details"]["chart_matches"]),
            "installed_zero_replica_workload_tokenless": security,
            "forbidden_install_refused": token_refused and no_release}


def run(lab):
    with tempfile.TemporaryDirectory(prefix="saf-helm-values-") as tmp:
        root = Path(tmp)
        report = demonstrate(lab, root)
        report["signed_transitive_tree"] = demonstrate_signed_tree(lab, root / "signed-tree")
    (lab.evidence / "values-and-dependency-observations.json").write_text(json.dumps(report, indent=2) + "\n")
