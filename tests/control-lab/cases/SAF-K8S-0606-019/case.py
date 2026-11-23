"""Install an owned chart only when its bytes match an approved signing key."""

import hashlib
import json
from pathlib import Path
import shutil
import tempfile

SCOPE = "Helm package provenance for an owned chart that installs one inert ConfigMap."
CHART = "saf-helm-provenance"
APPROVED = "SAF Approved Fixture"
UNAPPROVED = "SAF Other Fixture"
TEMPLATE = '''apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}
data:
  marker: {{ .Values.marker | quote }}
'''


def keys(lab, home, identity, path):
    base = ("gpg", "--homedir", str(home), "--batch", "--no-tty")
    lab.command(*base, "--pinentry-mode", "loopback", "--passphrase", "",
                "--quick-generate-key", identity + " <fixture@example.invalid>", "rsa2048", "sign", "1d")
    secret = path / (identity.replace(" ", "-") + ".private.gpg")
    public = path / (identity.replace(" ", "-") + ".public.gpg")
    lab.command(*base, "--output", str(secret), "--export-secret-keys", identity)
    lab.command(*base, "--output", str(public), "--export", identity)
    return secret, public


def package(lab, directory, marker, *, signer=None, secret=None):
    chart = directory / CHART
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text(f"apiVersion: v2\nname: {CHART}\nversion: 0.1.0\n")
    (chart / "values.yaml").write_text(f"marker: {marker}\n")
    (chart / "templates" / "configmap.yaml").write_text(TEMPLATE)
    options = ("--sign", "--key", signer, "--keyring", str(secret)) if signer else ()
    lab.command("helm", "package", str(chart), "--destination", str(directory), *options)
    return directory / f"{CHART}-0.1.0.tgz"


def provenance(archive):
    return Path(str(archive) + ".prov")


def helm_cluster(lab, *args, **kwargs):
    return lab.command("helm", *args, "--namespace", "saf-test", "--kubeconfig", str(lab.kubeconfig),
                       "--kube-context", f"kind-{lab.cluster}", **kwargs)


def config(lab, name):
    output = lab.kubectl("get", "configmap", name, "-o", "json", "--ignore-not-found").stdout
    return json.loads(output) if output.strip() else None


def verify_install(lab):
    with tempfile.TemporaryDirectory(prefix="safpgp-", dir="/private/tmp" if Path("/private/tmp").exists() else None) as tmp:
        directory = Path(tmp)
        key_home = directory / "keys"
        key_home.mkdir(mode=0o700)
        try:
            secret, trusted = keys(lab, key_home, APPROVED, directory)
            alternative_secret, alternative_public = keys(lab, key_home, UNAPPROVED, directory)
            approved = package(lab, directory / "approved", "approved-public-chart", signer=APPROVED, secret=secret)
            altered = package(lab, directory / "altered", "other-public-chart")
            other_signed = package(lab, directory / "other", "other-signer-public-chart",
                                   signer=UNAPPROVED, secret=alternative_secret)
            shutil.copyfile(provenance(approved), provenance(altered))
            detached = directory / "missing" / approved.name
            detached.parent.mkdir()
            shutil.copyfile(approved, detached)
            lab.command("helm", "verify", str(other_signed), "--keyring", str(alternative_public))
            helm_cluster(lab, "install", "unchecked-chart", str(altered))
            comparison = config(lab, "unchecked-chart")
            lab.check("red", "Without provenance verification Helm installs the changed fixture archive",
                      comparison and comparison["data"]["marker"] == "other-public-chart",
                      {"changed_marker_reached_api": bool(comparison and comparison["data"]["marker"] == "other-public-chart")})
            wrong_digest = helm_cluster(lab, "install", "wrong-chart-bytes", str(altered), "--verify", "--keyring",
                                        str(trusted), allow_failure=True)
            wrong_signer = helm_cluster(lab, "install", "different-chart-signer", str(other_signed), "--verify",
                                        "--keyring", str(trusted), allow_failure=True)
            missing_record = helm_cluster(lab, "install", "missing-chart-provenance", str(detached), "--verify",
                                          "--keyring", str(trusted), allow_failure=True)
            releases = json.loads(helm_cluster(lab, "list", "--all", "-o", "json").stdout)
            refused = {"digest_mismatch": wrong_digest.returncode != 0 and "sha256 sum does not match" in wrong_digest.stderr,
                       "unapproved_signer": wrong_signer.returncode != 0 and "unknown entity" in wrong_signer.stderr,
                       "missing_provenance": missing_record.returncode != 0
                       and "could not load provenance file" in missing_record.stderr,
                       "no_denied_resources": all(config(lab, name) is None for name in
                                                  ("wrong-chart-bytes", "different-chart-signer", "missing-chart-provenance")),
                       "no_denied_releases": {row["name"] for row in releases} == {"unchecked-chart"}}
            lab.check("green", "Native Helm verification refuses missing provenance, changed bytes and an unapproved signer",
                      all(refused.values()), refused)
            digest = "sha256:" + hashlib.sha256(approved.read_bytes()).hexdigest()
            verified = lab.command("helm", "verify", str(approved), "--keyring", str(trusted)).stdout
            helm_cluster(lab, "install", "verified-chart", str(approved), "--verify", "--keyring", str(trusted))
            installed = config(lab, "verified-chart")
            matches = bool(installed and installed["data"]["marker"] == "approved-public-chart"
                           and installed["metadata"]["annotations"]["meta.helm.sh/release-name"] == "verified-chart")
            verified_exact_archive = digest in verified and APPROVED in verified
            lab.check("positive", "Using the trusted key ring Helm installs the approved exact package",
                      verified_exact_archive and matches,
                      {"exact_archive_digest_verified": verified_exact_archive, "approved_marker_reached_api": matches})
            return {"helm": lab.command("helm", "version", "--short").stdout.strip(),
                    "positive_package_sha256": digest, "denials": refused, "positive_release_confirmed": matches}
        finally:
            lab.command("gpgconf", "--homedir", str(key_home), "--kill", "gpg-agent", allow_failure=True)


def run(lab):
    record = verify_install(lab)
    (lab.evidence / "chart-verification.json").write_text(json.dumps(record, indent=2) + "\n")
