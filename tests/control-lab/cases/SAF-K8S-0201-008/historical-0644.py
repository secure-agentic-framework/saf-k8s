"""Check metadata for selected kubelet paths without opening their contents."""
import json
from pathlib import Path
import stat
import tempfile


HERE = Path(__file__).resolve().parent
FIXTURE = json.loads((HERE / "fixtures.json").read_text())
MAXIMUM_MODES = {
    row["classification"]: int(row["maximum_mode"], 8)
    for row in FIXTURE["synthetic_files"]
}
SCOPE = (
    "On the disposable harness kind control-plane node, run stat -L only against "
    "the fixed kubelet path allowlist in fixtures.json. Record type, mode and numeric "
    "UID/GID; assert root UID and the catalog mode ceiling. No node file is opened, "
    "read, written, chmodded, or recursively enumerated. Harmless local temporary "
    "files exercise mode classification. Group policy, complete directory coverage, "
    "other node roles, providers and workload mount/access controls require separate evidence."
)


def compliant(mode, classification):
    """The catalog's mode is a ceiling; stricter permission bits remain valid."""
    maximum = MAXIMUM_MODES[classification]
    return not (mode & ~maximum)


def synthetic_mode_checks(lab):
    """Exercise both mode classes using harmless files owned by this case."""
    with tempfile.TemporaryDirectory(prefix="saf-kubelet-metadata-") as directory:
        root = Path(directory)
        files = {}
        for row in FIXTURE["synthetic_files"]:
            path = root / row["name"]
            path.write_text("public synthetic metadata fixture\n", encoding="utf-8")
            files[row["classification"]] = path

        config = files["configuration"]
        credential = files["credential"]
        config.chmod(0o644)
        credential.chmod(0o644)
        red = {
            "configuration_mode_allowed": compliant(
                stat.S_IMODE(config.stat().st_mode), "configuration"
            ),
            "credential_mode_rejected": not compliant(
                stat.S_IMODE(credential.stat().st_mode), "credential"
            ),
        }
        lab.check(
            "red",
            "The mode evaluator accepts 0644 configuration and detects an over-permissive 0644 credential",
            red["configuration_mode_allowed"] and red["credential_mode_rejected"],
            red,
        )

        credential.chmod(0o600)
        green = {
            "configuration_mode_allowed": compliant(
                stat.S_IMODE(config.stat().st_mode), "configuration"
            ),
            "credential_mode_allowed": compliant(
                stat.S_IMODE(credential.stat().st_mode), "credential"
            ),
        }
        lab.check(
            "green",
            "The mode evaluator accepts the catalog ceilings on synthetic files",
            all(green.values()),
            green,
        )

        config.chmod(0o400)
        credential.chmod(0o400)
        positive = {
            "stricter_configuration_allowed": compliant(
                stat.S_IMODE(config.stat().st_mode), "configuration"
            ),
            "stricter_credential_allowed": compliant(
                stat.S_IMODE(credential.stat().st_mode), "credential"
            ),
        }
        lab.check(
            "positive",
            "Stricter synthetic modes remain compliant",
            all(positive.values()),
            positive,
        )


def inspect_node(lab, node):
    observed = {}
    paths_ok = True
    for row in FIXTURE["node_paths"]:
        result = lab.command(
            "docker", "exec", node,
            "stat", "-L", "-c", "%F|%u|%g|%a", "--", row["path"],
            allow_failure=True,
        )
        if result.returncode:
            observed[row["path"]] = {
                "present": False,
                "required": row["required"],
                "classification": row["classification"],
            }
            if row["required"]:
                paths_ok = False
            continue

        fields = result.stdout.strip().split("|")
        if len(fields) != 4:
            lab.block("stat returned an unexpected metadata-only record")
        file_type, uid, gid, mode_text = fields
        try:
            mode = int(mode_text, 8)
            uid_value, gid_value = int(uid), int(gid)
        except ValueError:
            lab.block("stat returned non-numeric ownership or mode metadata")
        record = {
            "present": True,
            "required": row["required"],
            "classification": row["classification"],
            "type": file_type,
            "uid": uid_value,
            "gid": gid_value,
            "mode": format(mode, "04o"),
            "regular_file": file_type == "regular file",
            "root_uid": uid_value == 0,
            "mode_within_catalog_ceiling": compliant(mode, row["classification"]),
        }
        observed[row["path"]] = record
        if not all((record["regular_file"], record["root_uid"],
                    record["mode_within_catalog_ceiling"])):
            paths_ok = False

    lab.check(
        "positive",
        "Required kubelet paths on the case-owned kind node are root-owned and within the catalog mode ceiling",
        paths_ok,
        observed,
    )


def run(lab):
    synthetic_mode_checks(lab)
    inspect_node(lab, f"{lab.cluster}-control-plane")
