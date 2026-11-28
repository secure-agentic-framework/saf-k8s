"""Exercise the independent-boot evidence boundary using the saved reference."""

from copy import deepcopy
from datetime import timedelta
from hashlib import sha256
import json
from pathlib import Path
import runpy
import unittest

REFERENCE = Path(__file__).resolve().parents[1]
ADMISSION = runpy.run_path(str(REFERENCE / "candidate" / "prove-signed-admission.py"))
parse_time = ADMISSION["parse_time"]


def shifted(value, minutes):
    return (parse_time(value) + timedelta(minutes=minutes)).isoformat()


class IndependentBootTest(unittest.TestCase):
    def setUp(self):
        self.first = json.loads((REFERENCE / "bound-boot1.json").read_bytes())
        self.first_raw = (REFERENCE / "signed-modules-boot1.json").read_bytes()
        self.first_modules = json.loads(self.first_raw)
        self.host = self.first["host_ref_sha256"]
        self.later = deepcopy(self.first)
        self.later["boot_ref_sha256"] = "c" * 64
        self.later["provider_boot_counter"] += 1
        for key in ("guest_boot_utc", "provider_startup_utc"):
            self.later[key] = shifted(self.later[key], 40)
        for event in self.later["provider_events"].values():
            event["observed_utc"] = shifted(event["observed_utc"], 40)
        modules = deepcopy(self.first_modules)
        modules["boot_ref_sha256"] = self.later["boot_ref_sha256"]
        modules["captured_at_utc"] = shifted(self.first_modules["captured_at_utc"], 40)
        self.later_raw = json.dumps(modules, sort_keys=True).encode()
        self.later["signed_module_receipt_sha256"] = sha256(self.later_raw).hexdigest()

    def compare(self, current, *, host=None, first=None, first_modules=None, first_raw=None, current_raw=None):
        host = host or self.host
        current_raw = current_raw or self.later_raw
        ADMISSION["validate_same_boot"](
            current, json.loads(current_raw), current_raw, current["boot_ref_sha256"], host,
            parse_time(current["guest_boot_utc"]))
        return ADMISSION["require_independent_boot"](
            first or self.first, first_modules or self.first_modules, first_raw or self.first_raw, current, host)

    def test_proceed_with_distinct_ordered_boots(self):
        result = self.compare(self.later)
        self.assertTrue(result["independent_boot_verified"])
        self.assertEqual(result["current_provider_boot_counter"], 2)

    def test_reject_reused_first_boot(self):
        with self.assertRaisesRegex(SystemExit, "reuses the first boot"):
            self.compare(self.first, current_raw=self.first_raw)

    def test_reject_unchanged_provider_counter(self):
        self.later["provider_boot_counter"] = self.first["provider_boot_counter"]
        with self.assertRaisesRegex(SystemExit, "counter must advance"):
            self.compare(self.later)

    def test_reject_baseline_from_other_instance(self):
        first = {**self.first, "host_ref_sha256": "f" * 64}
        with self.assertRaisesRegex(SystemExit, "does not match this boot"):
            self.compare(self.later, first=first)

    def test_reject_baseline_module_digest_mismatch(self):
        with self.assertRaisesRegex(SystemExit, "does not match this boot"):
            self.compare(self.later, first_raw=self.first_raw + b"\n")

    def test_reject_out_of_order_boots(self):
        # Keep both records internally ordered while making the first capture
        # occur after the later provider startup.
        modules = {**self.first_modules, "captured_at_utc": shifted(self.first_modules["captured_at_utc"], 60)}
        raw = json.dumps(modules, sort_keys=True).encode()
        first = {**self.first, "signed_module_receipt_sha256": sha256(raw).hexdigest()}
        with self.assertRaisesRegex(SystemExit, "must precede the new startup"):
            self.compare(self.later, first=first, first_modules=modules, first_raw=raw)

    def test_reject_nonpassing_first_provider_evaluation(self):
        self.first["provider_events"]["earlyBootReportEvent"]["policy_passed"] = False
        with self.assertRaisesRegex(SystemExit, "passing early and late boot events"):
            self.compare(self.later)


if __name__ == "__main__":
    unittest.main()
