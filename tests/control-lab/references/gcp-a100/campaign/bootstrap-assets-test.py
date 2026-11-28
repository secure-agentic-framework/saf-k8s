"""Offline tests for verified bootstrap asset staging and K3s preparation."""

from hashlib import sha256
from pathlib import Path
import runpy
import tempfile
import unittest

MODULE_PATH = Path(__file__).with_name("bootstrap_assets.py")
ASSETS_MODULE = runpy.run_path(str(MODULE_PATH))
stage_assets = ASSETS_MODULE["stage_assets"]
verify_assets = ASSETS_MODULE["verify_assets"]
prepare_k3s = ASSETS_MODULE["prepare_k3s"]


class BootstrapAssetsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bootstrap-assets-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.payloads = {
            "k3s": b"pinned test k3s executable\n",
            "install-k3s.sh": b"pinned test installer\n",
            "nvidia-device-plugin.yaml": b"pinned test device plugin manifest\n",
        }
        pins = {
            name: (f"https://assets.invalid/{name}", sha256(data).hexdigest(), len(data) + 32)
            for name, data in self.payloads.items()
        }
        ASSETS_MODULE["ASSETS"].clear()
        ASSETS_MODULE["ASSETS"].update(pins)
        for name, data in self.payloads.items():
            (self.source / name).write_bytes(data)

    def staged(self):
        directory = self.root / "staged"
        stage_assets(directory, source=self.source)
        return directory

    def test_stage_offline_source_and_verify_all_pins(self):
        directory = self.staged()
        self.assertEqual(
            verify_assets(directory),
            {name: sha256(data).hexdigest() for name, data in self.payloads.items()},
        )
        self.assertEqual({path.name for path in directory.iterdir()}, set(self.payloads))

    def test_reject_staged_tamper(self):
        directory = self.staged()
        (directory / "nvidia-device-plugin.yaml").write_bytes(b"changed manifest\n")
        with self.assertRaises(ValueError):
            verify_assets(directory)

    def test_reuse_exact_executable_for_active_server(self):
        directory = self.staged()
        binary = directory / "k3s"
        binary.chmod(0o700)
        target = self.root / "usr-local-bin-k3s"
        target.write_bytes(self.payloads["k3s"])
        target.chmod(0o700)
        self.assertEqual(prepare_k3s(directory, target, active=True), "reused")
        self.assertEqual(target.read_bytes(), self.payloads["k3s"])

    def test_install_staged_executable_when_inactive(self):
        directory = self.staged()
        (directory / "k3s").chmod(0o700)
        target = self.root / "usr-local-bin-k3s"
        self.assertEqual(prepare_k3s(directory, target, active=False), "installed")
        self.assertEqual(target.read_bytes(), self.payloads["k3s"])
        self.assertTrue(target.stat().st_mode & 0o111)

    def test_refuse_missing_binary_for_active_server(self):
        directory = self.staged()
        target = self.root / "missing-k3s"
        with self.assertRaises(ValueError):
            prepare_k3s(directory, target, active=True)
        self.assertFalse(target.exists())

    def test_refuse_wrong_existing_binary_without_overwriting(self):
        directory = self.staged()
        (directory / "k3s").chmod(0o700)
        target = self.root / "owned-k3s"
        original = b"different existing executable\n"
        target.write_bytes(original)
        target.chmod(0o700)
        for active in (False, True):
            with self.subTest(active=active), self.assertRaises(ValueError):
                prepare_k3s(directory, target, active=active)
            self.assertEqual(target.read_bytes(), original)

    def test_refuse_symlink_or_non_executable_existing_target(self):
        directory = self.staged()
        (directory / "k3s").chmod(0o700)
        actual = self.root / "actual-k3s"
        actual.write_bytes(self.payloads["k3s"])
        actual.chmod(0o700)
        link = self.root / "linked-k3s"
        link.symlink_to(actual)
        with self.assertRaises(ValueError):
            prepare_k3s(directory, link, active=False)

        not_executable = self.root / "not-executable-k3s"
        not_executable.write_bytes(self.payloads["k3s"])
        not_executable.chmod(0o600)
        with self.assertRaises(ValueError):
            prepare_k3s(directory, not_executable, active=True)

    def test_refuse_tampered_staged_binary_and_preserve_target(self):
        directory = self.staged()
        binary = directory / "k3s"
        binary.chmod(0o700)
        binary.write_bytes(b"tampered\n")
        target = self.root / "new-k3s"
        with self.assertRaises(ValueError):
            prepare_k3s(directory, target, active=False)
        self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
