#!/usr/bin/env python3
"""Offline verifier/comparator for the pinned containerd release metadata."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
EXPECTED_TAG = "97fb10bc3047298e43360d6054f74e9d8f996570"
EXPECTED_COMMIT = "6f589cf13dc01a5b493911355427e05b2ff005d7"
EXPECTED_SIGNER = "8C7A111C21105794B0E8A27BF58C5D0A4405ACDB"
EXPECTED_POLICY_SHA256 = "644d720cbb29f4760924b139a7f9922699f49985ae84fcb9edb31d3a4467d92f"
EXPECTED_OBSERVATION_SHA256 = "d757ad742b87eda1963d7813c371ccc7b30542e1bdf8b833da2369e6eb962328"
SIGNATURE_MARKER = b"-----BEGIN PGP SIGNATURE-----"


class VerificationError(Exception):
    pass


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError("cannot read valid JSON from " + str(path)) from error


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def git_object_id(data):
    header = b"tag " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(header + data).hexdigest()


def parse_tag(data):
    require(len(data) <= 65536, "tag artifact exceeds the bounded size limit")
    require(data.count(SIGNATURE_MARKER) == 1, "tag must contain one embedded OpenPGP signature")
    payload, signature = data.split(SIGNATURE_MARKER, 1)
    payload = payload.rstrip(b"\n") + b"\n"
    signature = SIGNATURE_MARKER + signature
    require(signature.endswith(b"-----END PGP SIGNATURE-----\n"), "malformed or truncated signature armor")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError("tag payload is not UTF-8") from error
    header_text = text.split("\n\n", 1)[0]
    headers = {}
    for line in header_text.splitlines():
        if " " in line:
            key, value = line.split(" ", 1)
            headers[key] = value
    require(headers.get("object") == EXPECTED_COMMIT, "tag points to an unexpected commit")
    require(headers.get("type") == "commit", "tag target is not a commit")
    require(headers.get("tag") == "v2.3.7", "tag name is not v2.3.7")
    require("tagger" in headers, "tagger header is missing")
    tagger_match = re.search(r" (\d{9,}) [+-]\d{4}$", headers["tagger"])
    require(tagger_match is not None, "tagger timestamp is malformed")
    tagger_date = dt.datetime.fromtimestamp(
        int(tagger_match.group(1)), tz=dt.timezone.utc).date().isoformat()
    return payload, signature, headers, tagger_date


def gpg_call(home, *args):
    command = ["gpg", "--no-options", "--batch", "--no-autostart", "--no-auto-key-retrieve",
               "--homedir", str(home)] + list(args)
    try:
        result = subprocess.run(command, text=True, capture_output=True,
                                timeout=30, env=dict(os.environ, GNUPGHOME=str(home)))
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VerificationError("local gpg failed to run") from error
    return result


def verify_signature(key_path, payload, signature):
    with tempfile.TemporaryDirectory(prefix="saf-k8s-gpg-") as temporary:
        home = Path(temporary)
        os.chmod(str(home), 0o700)
        imported = gpg_call(home, "--import", str(key_path))
        require(imported.returncode == 0, "public key import failed")
        listed = gpg_call(home, "--with-colons", "--fingerprint", "--list-keys")
        require(listed.returncode == 0, "cannot inspect isolated public keyring")
        fingerprints = [line.split(":")[9].upper() for line in listed.stdout.splitlines()
                        if line.startswith("fpr:") and len(line.split(":")) > 9]
        public_keys = [line for line in listed.stdout.splitlines() if line.startswith("pub:")]
        secret = gpg_call(home, "--with-colons", "--list-secret-keys")
        secret_keys = [line for line in secret.stdout.splitlines() if line.startswith("sec:")]
        require(len(public_keys) == 1,
                "key bundle must contain exactly one public key")
        require(fingerprints and fingerprints[0] == EXPECTED_SIGNER,
                "key bundle is not the pinned maintainer key")
        require(not secret_keys, "key bundle must not contain private key material")
        payload_path = home / "tag-payload"
        signature_path = home / "tag-signature.asc"
        payload_path.write_bytes(payload)
        signature_path.write_bytes(signature)
        checked = gpg_call(home, "--status-fd", "1", "--verify",
                           str(signature_path), str(payload_path))
        require(checked.returncode == 0, "tag signature verification failed")
        valid = [line.split() for line in checked.stdout.splitlines()
                 if line.startswith("[GNUPG:] VALIDSIG ")]
        require(len(valid) == 1 and len(valid[0]) > 2
                and valid[0][2].upper() == EXPECTED_SIGNER,
                "signature is valid but not from the pinned signer")


def verify_policy(path, tagger_date):
    raw = Path(path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    require(digest == EXPECTED_POLICY_SHA256, "reviewed policy facts file changed")
    facts = read_json(path)
    release = facts.get("reviewed_release", {})
    policy = facts.get("policy_facts", {})
    sources = facts.get("source_ids", {})
    require(facts.get("schema") == "saf-k8s-containerd-release-policy-v1", "unknown policy schema")
    require(release.get("version") == "2.3.7" and release.get("tag") == "v2.3.7",
            "unexpected reviewed release")
    require(release.get("tag_object_sha1") == EXPECTED_TAG
            and release.get("commit") == EXPECTED_COMMIT
            and release.get("signer_fingerprint") == EXPECTED_SIGNER,
            "policy facts do not identify the pinned signed tag")
    require(release.get("tagger_date") == tagger_date == "2026-10-13"
            and release.get("release_date") == "2026-10-13"
            and release.get("published_at") == "2026-10-13T22:46:58Z",
            "reviewed release date metadata differs from the signed tag/API snapshot")
    require(policy.get("lts_branches") == ["2.3"]
            and policy.get("support_ends", {}).get("2.3") == "2028-04-30",
            "reviewed LTS/support horizon facts differ")
    require(policy.get("kubernetes_recommendations", {}).get("1.36") ==
            {"minimum_containerd": "2.3.0", "cri": "v1"},
            "reviewed Kubernetes compatibility facts differ")
    require(policy.get("universal_vulnerability_sla_days") is None,
            "reviewed policy must not invent a universal vulnerability SLA")
    require(sources.get("release_policy", {}).get("id", "").endswith(
            "3bfcffe4f4f637d18689ca1893649af81b38fdaf"),
            "independent policy source ID is missing")
    return facts


def parse_version(value):
    match = re.fullmatch(r"(?:containerd://)?v?(\d+)\.(\d+)\.(\d+)", value)
    require(match is not None, "expected a stable containerd semantic version, got " + repr(value))
    return tuple(int(part) for part in match.groups())


def compare_observation(path, facts):
    raw = Path(path).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == EXPECTED_OBSERVATION_SHA256,
            "retained live observation record changed")
    observed = read_json(path)
    release = facts["reviewed_release"]
    policy = facts["policy_facts"]
    k8s_match = re.fullmatch(r"v?(\d+)\.(\d+)\.\d+", observed.get("kubernetes", ""))
    require(k8s_match is not None, "observation has an invalid Kubernetes version")
    k8s_minor = k8s_match.group(1) + "." + k8s_match.group(2)
    recommendation = policy["kubernetes_recommendations"].get(k8s_minor)
    require(recommendation is not None, "no reviewed compatibility row for observed Kubernetes minor")
    support_end = dt.date.fromisoformat(policy["support_ends"]["2.3"])
    as_of = dt.date.fromisoformat(observed["observed_at"])
    rows = []
    for node in observed.get("nodes", []):
        report_version = parse_version(node["runtime_report"])
        packaged_version = parse_version(node["packaged_containerd"])
        require(node.get("cri_matches_packaged_containerd")
                and report_version == packaged_version,
                "runtime report and packaged containerd do not match")
        minimum = parse_version(recommendation["minimum_containerd"])
        reviewed = parse_version(release["version"])
        rows.append({
            "node": node["node"],
            "observed_containerd": ".".join(map(str, report_version)),
            "older_than_reviewed_release": report_version < reviewed,
            "meets_kubernetes_recommendation": report_version >= minimum,
            "recommended_cri_version": recommendation["cri"],
            "support_line": "2.3 LTS",
            "support_end": support_end.isoformat(),
            "in_support_on_observation_date": as_of <= support_end,
            "advisory_applicability": "not_assessed_from_version_alone"
        })
    require(rows, "observation has no runtime nodes")
    return {
        "observation_date": observed["observed_at"],
        "kubernetes": observed["kubernetes"],
        "reviewed_release": "containerd " + release["version"],
        "nodes": rows,
        "policy_facts_basis": "independently reviewed and transcribed; not authenticated by the tag signature",
        "sla_days": None,
        "sla_meaning": "No universal upstream vulnerability SLA is supplied by this policy snapshot."
    }


def verify(tag_path, key_path, facts_path, observation_path):
    data = Path(tag_path).read_bytes()
    require(git_object_id(data) == EXPECTED_TAG,
            "annotated tag object ID mismatch (artifact is modified or not the pinned tag)")
    payload, signature, headers, tagger_date = parse_tag(data)
    verify_signature(key_path, payload, signature)
    facts = verify_policy(facts_path, tagger_date)
    comparison = compare_observation(observation_path, facts)
    return {
        "result": "verified",
        "tag": "v2.3.7",
        "tag_object_sha1": EXPECTED_TAG,
        "target_commit": EXPECTED_COMMIT,
        "signer_fingerprint": EXPECTED_SIGNER,
        "tagger": headers["tagger"],
        "signed_tagger_date": tagger_date,
        "signature": "valid under isolated keyring containing only the pinned public key",
        "policy_facts": "reviewed snapshot identity and required fields match",
        "comparison": comparison
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", default=str(HERE / "official-containerd-v2.3.7.tag"))
    parser.add_argument("--key", default=str(HERE / "containerd-maintainer-public.asc"))
    parser.add_argument("--facts", default=str(HERE / "official-policy-facts.json"))
    parser.add_argument("--observation", default=str(HERE / "live-observation.json"))
    args = parser.parse_args()
    try:
        result = verify(args.tag, args.key, args.facts, args.observation)
    except (OSError, VerificationError) as error:
        print(json.dumps({"result": "rejected", "reason": str(error)}, indent=2), file=sys.stderr)
        return 1
    except (AttributeError, KeyError, OverflowError, TypeError, ValueError) as error:
        print(json.dumps({"result": "rejected", "reason": "malformed metadata input: " + str(error)},
                         indent=2), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
