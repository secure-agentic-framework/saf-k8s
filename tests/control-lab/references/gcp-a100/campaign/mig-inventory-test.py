"""Regression tests for the compute placement column reported by driver 580."""

from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "candidate"))
from mig_inventory import MigPrecondition, read_inventory


GPU_UUID = "GPU-10000000-0000-0000-0000-000000000000"
MIG_UUIDS = (
    "MIG-20000000-0000-0000-0000-000000000001",
    "MIG-20000000-0000-0000-0000-000000000002",
)
PROFILE = "NVIDIA A100-SXM4-40GB, 580.178.04, Enabled, Enabled"
GPU_INSTANCES = (
    "GPU instances:\n"
    "| 0 MIG 1g.5gb 19 11 4:1 |\n"
    "| 0 MIG 1g.5gb 19 13 6:1 |\n"
)
COMPUTE_INSTANCES = (
    "Compute instances:\n"
    "| 0 11 MIG 1g.5gb 0 0 0:1 |\n"
    "| 0 13 MIG 1g.5gb 0 0 0:1 |\n"
)


class CommandFixture:
    def __init__(self, compute_instances=COMPUTE_INSTANCES):
        self.compute_instances = compute_instances

    def __call__(self, *args, **kwargs):
        if args[1].startswith("--query-gpu="):
            stdout = PROFILE
        elif args[1:] == ("-L",):
            stdout = f"GPU 0: A100-SXM4-40GB (UUID: {GPU_UUID})\n"
            stdout += "".join(
                f"  MIG 1g.5gb Device {i}: (UUID: {uuid})\n"
                for i, uuid in enumerate(MIG_UUIDS)
            )
        elif "-lgi" in args:
            stdout = GPU_INSTANCES
        elif "-lci" in args:
            stdout = self.compute_instances
        else:
            raise AssertionError(f"Unexpected fixture command: {args!r}")
        return subprocess.CompletedProcess(args, 0, stdout, "")


class ObservedComputeInstanceColumnTest(unittest.TestCase):
    def test_accepts_full_compute_rows_with_placement_start_size(self):
        inventory = read_inventory(CommandFixture())
        self.assertEqual(len(inventory.devices), 2)
        self.assertEqual(inventory.instances, (("11", "0"), ("13", "0")))

    def test_rejects_unparsed_trailing_compute_columns(self):
        malformed = COMPUTE_INSTANCES.replace("0:1 |", "0:1 unexpected |", 1)
        with self.assertRaisesRegex(MigPrecondition, "compute instance"):
            read_inventory(CommandFixture(malformed))

    def test_rejects_malformed_placement_start_size(self):
        malformed = COMPUTE_INSTANCES.replace("0:1 |", "bad |", 1)
        with self.assertRaisesRegex(MigPrecondition, "compute instance"):
            read_inventory(CommandFixture(malformed))


if __name__ == "__main__":
    unittest.main()
