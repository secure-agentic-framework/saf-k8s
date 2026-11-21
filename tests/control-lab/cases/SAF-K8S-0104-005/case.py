"""Audit only case-owned fixture metadata for representative control-plane paths."""
from pathlib import Path
import shutil
import stat
import tempfile


SCOPE = (
    "Local metadata-only audit of synthetic fixture copies for exact kubeadm-style "
    "control-plane paths. The fixture tree contains public placeholder text only; "
    "the audit reads lstat metadata. Read-only stat on the same fixed path types "
    "measures stock kind v1.36.1 node mode and numeric ownership. Fixture chmod applies "
    "only to the temporary public copies. Production owner names, provisioner and "
    "recurring evidence remain outside the lab."
)

FIXTURE_ROOT = Path(__file__).with_name("fixtures")

# These absolute node paths are public kubeadm conventions; relative paths beneath
# the private temporary fixture root are the only paths this case may inspect.
RULES = {
    "etc/kubernetes/manifests/kube-apiserver.yaml": ("file", 0o600, "cis-2.0 1.1.1"),
    "etc/kubernetes/manifests/kube-controller-manager.yaml": ("file", 0o600, "cis-2.0 1.1.3"),
    "etc/kubernetes/manifests/kube-scheduler.yaml": ("file", 0o600, "cis-2.0 1.1.5"),
    "etc/kubernetes/manifests/etcd.yaml": ("file", 0o600, "cis-2.0 1.1.7"),
    "etc/kubernetes/admin.conf": ("file", 0o600, "cis-2.0 1.1.13, 1.1.14"),
    "etc/kubernetes/controller-manager.conf": ("file", 0o600, "cis-2.0 1.1.16, 1.1.18"),
    "etc/kubernetes/scheduler.conf": ("file", 0o600, "cis-2.0 1.1.15, 1.1.17"),
    "etc/kubernetes/pki/etcd/ca.key": ("file", 0o600, "cis-2.0 1.1.19, 1.1.21"),
    "var/lib/etcd": ("dir", 0o700, "cis-2.0 1.1.11, 1.1.12"),
}

def audit(root, expected_uid, expected_gid):
    """Return metadata-only results for a fixed allowlist; do not follow links."""
    root = Path(root).resolve(strict=True)
    result = {}
    for relative, (kind, allowed_mode, citation) in RULES.items():
        parts = relative.split("/")
        path = root
        try:
            for component in parts[:-1]:
                path = path / component
                parent_info = path.lstat()
                if not stat.S_ISDIR(parent_info.st_mode):
                    raise NotADirectoryError(component)
            path = path / parts[-1]
            info = path.lstat()
        except OSError:
            result[relative] = {"ok": False, "reason": "missing-or-unreadable"}
            continue
        actual_kind = "dir" if stat.S_ISDIR(info.st_mode) else (
            "file" if stat.S_ISREG(info.st_mode) else "other"
        )
        actual_mode = stat.S_IMODE(info.st_mode)
        owner_ok = info.st_uid == expected_uid and info.st_gid == expected_gid
        mode_ok = not (actual_mode & ~allowed_mode)
        result[relative] = {
            "ok": actual_kind == kind and owner_ok and mode_ok,
            "kind_ok": actual_kind == kind,
            "owner_matches_fixture_identity": owner_ok,
            "mode_allowed": mode_ok,
            "mode_octal": format(actual_mode, "04o"),
            "rule": citation,
        }
    return result


def all_ok(result):
    return len(result) == len(RULES) and all(row["ok"] for row in result.values())


def summary(result):
    return {"paths_checked": len(result), "compliant": sum(row["ok"] for row in result.values())}


def run(lab):
    # The fixture source and its working copy contain only public, seeded text.
    # All chmod calls below are confined to this disposable copy.
    with tempfile.TemporaryDirectory(prefix="saf-0104-005-fixtures-") as temporary:
        root = Path(temporary) / "node-root"
        shutil.copytree(FIXTURE_ROOT, root)
        sample = next(root.joinpath(*path.split("/")).lstat()
                      for path, (kind, _, _) in RULES.items() if kind == "file")
        expected_uid, expected_gid = sample.st_uid, sample.st_gid

        # Deliberately expose fixture metadata in the baseline. The check is
        # successful only when it detects the expected noncompliant sample.
        for relative, (kind, _, _) in RULES.items():
            path = root.joinpath(*relative.split("/"))
            path.chmod(0o755 if kind == "dir" else 0o644)
        baseline = audit(root, expected_uid, expected_gid)
        lab.check("red", "The audit detects permissive metadata on synthetic fixture copies",
                  all(row["kind_ok"] and row["owner_matches_fixture_identity"]
                      and not row["mode_allowed"] for row in baseline.values()),
                  summary(baseline))

        for relative, (_, allowed_mode, _) in RULES.items():
            root.joinpath(*relative.split("/")).chmod(allowed_mode)

        owner_mismatch = audit(root, expected_uid + 1, expected_gid)
        lab.check("red", "Correctly permissioned fixtures fail when the owner identity differs",
                  all(row["kind_ok"] and row["mode_allowed"]
                      and not row["owner_matches_fixture_identity"]
                      for row in owner_mismatch.values()), summary(owner_mismatch))

        compliant = audit(root, expected_uid, expected_gid)
        lab.check("green", "Exact fixture paths pass the CIS-mode and fixture-owner audit",
                  all_ok(compliant), summary(compliant))

        # A more restrictive mode remains accepted for both files and directory.
        positive_path = root / "etc/kubernetes/admin.conf"
        positive_path.chmod(0o400)
        positive = audit(root, expected_uid, expected_gid)
        lab.check("positive", "A stricter synthetic kubeconfig mode remains compliant",
                  all_ok(positive), summary(positive))


    node = f"{lab.cluster}-control-plane"
    observed = {}
    for path, (kind, allowed_mode, _) in RULES.items():
        mode, uid, gid, file_type = lab.command(
            "docker", "exec", node, "stat", "-c", "%a %u %g %F", "--", f"/{path}"
        ).stdout.strip().split(" ", 3)
        observed[path] = {
            "mode": mode,
            "uid": int(uid),
            "gid": int(gid),
            "type": file_type,
            "mode_within_reference": not (int(mode, 8) & ~allowed_mode),
            "expected_file_type": file_type == ("directory" if kind == "dir" else "regular file"),
        }
    lab.check("positive", "Stock node path types and modes can be sampled without reading contents",
              all(row["mode_within_reference"] and row["expected_file_type"]
                  for row in observed.values()), observed)
