"""Serve a synthetic TUF repository and exercise its reference client."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from urllib.request import urlopen

from securesystemslib.signer import CryptoSigner
from tuf.api import exceptions
from tuf.api.metadata import Metadata, MetaFile, Root, Snapshot, TargetFile, Targets, Timestamp
from tuf.ngclient import Updater, UpdaterConfig


SERVICE = "http://saf-0603-006-repo.saf-test.svc:8080/"
TARGET = "release-note.txt"
CONTENTS = b"SAFE release note in the test repository\n"
ALTERNATE = b"OTHER text from the test repository.    \n"
CONFIG = UpdaterConfig(root_max_length=65536, timestamp_max_length=32768,
                       snapshot_max_length=65536, targets_max_length=65536,
                       max_root_rotations=8, max_delegations=8)
ROLES = {"root": 2, "targets": 3, "snapshot": 1, "timestamp": 1}


def signed(metadata, signers):
    envelope = Metadata(metadata)
    for key in signers:
        envelope.sign(key, append=True)
    return envelope.to_bytes()


def root_metadata(keys, serial, expiration, old_root=()):
    root = Root(version=serial, expires=expiration)
    root.roles["root"].threshold = 2
    root.roles["targets"].threshold = 2
    for role, signers in keys.items():
        for signer in signers:
            root.add_key(signer.public_key, role)
    return signed(root, [*old_root, *keys["root"]])


def create_repositories(path):
    now = datetime.now(timezone.utc)
    future = now + timedelta(hours=1)
    keys = {role: [CryptoSigner.generate_ed25519() for _ in range(count)]
            for role, count in ROLES.items()}
    trusted_root = root_metadata(keys, 1, future)
    next_keys = {**keys, "root": [CryptoSigner.generate_ed25519() for _ in range(2)]}
    rotated_root = root_metadata(next_keys, 2, future, keys["root"])
    unauthorized_rotation = root_metadata(next_keys, 2, future)
    path.parent.joinpath("bootstrap.json").write_bytes(trusted_root)
    settings = {
        "good": 2, "one-signature": 2, "expired": 2, "different-snapshot": 2,
        "different-version": 2, "oversize": 2, "other-target": 2, "previous": 1,
        "rotation": 2, "unapproved-rotation": 2,
    }
    target = TargetFile.from_data(TARGET, CONTENTS, ["sha256"])
    for scenario, serial in settings.items():
        repo = path / scenario
        metadata = repo / "metadata"
        targets = repo / "targets"
        metadata.mkdir(parents=True)
        targets.mkdir()
        if scenario in ("rotation", "unapproved-rotation"):
            metadata.joinpath("2.root.json").write_bytes(
                rotated_root if scenario == "rotation" else unauthorized_rotation
            )
        target_bytes = ALTERNATE if scenario == "other-target" else CONTENTS
        targets.joinpath(f"{target.hashes['sha256']}.{TARGET}").write_bytes(target_bytes)
        target_keys = keys["targets"][:1] if scenario == "one-signature" else keys["targets"][:2]
        targets_file = signed(Targets(serial, expires=future, targets={TARGET: target}), target_keys)
        targets_binding = MetaFile.from_data(serial, targets_file, ["sha256"])
        snapshot_serial = serial + 1 if scenario == "different-version" else serial
        snapshot = Snapshot(snapshot_serial, expires=future, meta={"targets.json": targets_binding})
        snapshot_file = signed(snapshot, keys["snapshot"])
        timestamp_binding = MetaFile.from_data(serial, snapshot_file, ["sha256"])
        expiration = now - timedelta(minutes=1) if scenario == "expired" else future
        timestamp_file = signed(Timestamp(serial, expires=expiration, snapshot_meta=timestamp_binding),
                                keys["timestamp"])
        if scenario == "oversize":
            timestamp_file += b" " * CONFIG.timestamp_max_length
        if scenario == "different-snapshot":
            snapshot.expires += timedelta(seconds=1)
            snapshot_file = signed(snapshot, keys["snapshot"])
        metadata.joinpath("timestamp.json").write_bytes(timestamp_file)
        metadata.joinpath(f"{serial}.snapshot.json").write_bytes(snapshot_file)
        metadata.joinpath(f"{serial}.targets.json").write_bytes(targets_file)
    path.joinpath("ready").write_text("ready")


def serve():
    root = Path("/tmp/served")
    create_repositories(root)
    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(root), **kwargs)
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()


def client_path(directory, scenario, initial_root):
    location = SERVICE + scenario + "/"
    return Updater(str(directory), location + "metadata/", target_base_url=location + "targets/",
                   bootstrap=initial_root, config=CONFIG)


def update(client, destination):
    client.refresh()
    target = client.get_targetinfo(TARGET)
    if target is None:
        raise RuntimeError("selected fixture target missing")
    client.download_target(target, filepath=str(destination))
    return destination.read_bytes()


def rejection(root, scenario, expect):
    with TemporaryDirectory() as location:
        work = Path(location)
        target = work / TARGET
        directory = work / "trusted"
        directory.mkdir()
        client = client_path(directory, scenario, root)
        try:
            update(client, target)
        except expect as error:
            return {"expected_error": type(error).__name__, "no_accepted_target": not target.exists()}
        return {"expected_error": None, "no_accepted_target": not target.exists()}


def trusted_versions(directory):
    return {role: Metadata.from_file(str(directory / f"{role}.json")).signed.version
            for role in ("root", "timestamp", "snapshot", "targets")}


def observe():
    assert len(CONTENTS) == len(ALTERNATE)
    root = Path("/bootstrap/root.json").read_bytes()
    name = f"{sha256(CONTENTS).hexdigest()}.{TARGET}"
    with urlopen(SERVICE + "other-target/targets/" + name, timeout=8) as result:
        raw_downloaded = result.read()
    accepted = {}
    with TemporaryDirectory() as location:
        work = Path(location)
        valid = update(client_path(work, "good", root), work / TARGET)
        accepted["target_sha256"] = sha256(valid).hexdigest()
        accepted["target_exact"] = valid == CONTENTS
        before = trusted_versions(work)
        rollback_target = work / "older-release-note.txt"
        rejected = False
        try:
            update(client_path(work, "previous", None), rollback_target)
        except exceptions.BadVersionNumberError:
            rejected = True
        rollback = {"rollback_rejected": rejected,
                    "trusted_versions_unchanged": before == trusted_versions(work),
                    "no_accepted_target": not rollback_target.exists()}
    with TemporaryDirectory() as location:
        work = Path(location)
        valid = update(client_path(work, "rotation", root), work / TARGET)
        rotation = {"new_root_and_exact_target_verified": trusted_versions(work)["root"] == 2 and valid == CONTENTS}
    checks = {
        "one-signature": exceptions.UnsignedMetadataError,
        "expired": exceptions.ExpiredMetadataError,
        "different-snapshot": exceptions.LengthOrHashMismatchError,
        "different-version": exceptions.BadVersionNumberError,
        "oversize": exceptions.DownloadLengthMismatchError,
        "other-target": exceptions.LengthOrHashMismatchError,
        "unapproved-rotation": exceptions.UnsignedMetadataError,
    }
    return {
        "tuf_version": version("tuf"), "raw_http_returned_alternate": raw_downloaded == ALTERNATE,
        "expected_sha256": name.split(".", 1)[0], "accepted": accepted, "rollback": rollback,
        "rotation": rotation, "cases": {name: rejection(root, name, error) for name, error in checks.items()},
    }


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve()
    else:
        print(json.dumps(observe(), sort_keys=True))
