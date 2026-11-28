"""Host-only tests; these validate the finite oracle, not MP-SPDZ runtime evidence."""

import unittest
from itertools import product
from types import SimpleNamespace

import verify_witness as witness
from native_contract import (RESERVATION_DATA, duplicate_rejected, input_file_text,
                             reservation_manifest, reservation_matches, stable_receipt)


class QuantizedMedianOracleTests(unittest.TestCase):
    def test_all_u2_triples_calibrate(self):
        expected, _, _, _ = witness.exact_scalar_oracle()
        self.assertEqual(len(expected), 4 ** 3 * 2 ** 4)
        for values in product(range(4), repeat=3):
            self.assertEqual(witness.median3(values), sorted(values)[1])

    def test_numeric_median_is_not_bitwise_majority(self):
        # Integer median(1,2,0)=1; bitwise majority would incorrectly yield 0.
        self.assertEqual(witness.median3((1, 2, 0)), 1)

    def test_exact_scalar_privacy_and_interval_counts(self):
        _, adjacency, maximum, intervals = witness.exact_scalar_oracle()
        self.assertEqual(adjacency, 2304)
        self.assertEqual(maximum, 9)
        self.assertEqual(intervals, 72)
        self.assertEqual(maximum ** 4, 6561)

    def test_gradient_fixture_maps_to_eight_input_bits(self):
        self.assertEqual(witness.verify_synthetic_fixture(), 18)
        self.assertEqual(tuple(input_file_text(0).split()), ("0",) * 8)
        self.assertEqual(tuple(input_file_text(1).split()), ("1", "0", "0", "1", "1", "0", "0", "1"))
        self.assertEqual(tuple(input_file_text(2).split()), ("1",) * 8)

    def test_native_logs_require_one_shared_vector(self):
        calibration = witness.expected_calibration()
        lines = [
            "saf-quantized-calibration " + "".join(map(str, values)) + " "
            + "".join(map(str, coins)) + " " + format(output, "02b")
            for (values, coins), output in sorted(calibration.items())
        ]
        log = "\n".join(lines + ["saf-quantized-vector 01011001"])
        summary = witness.parse_logs((log, log, log))
        self.assertEqual(summary["vector_transcripts_observed"], 1)
        with self.assertRaises(ValueError):
            witness.parse_logs((log + "\nsaf-quantized-vector 00000000", log, log))

    def test_case_reservation_binds_exact_composed_budget(self):
        manifest = reservation_manifest()
        self.assertTrue(reservation_matches(manifest))
        changed = {**manifest, "data": {**manifest["data"], "epsilon": "ln(3)"}}
        self.assertFalse(reservation_matches(changed))
        self.assertEqual(RESERVATION_DATA["logical_rounds"], "2")
        self.assertEqual(RESERVATION_DATA["maximum_vector_transcripts"], "1")
        self.assertEqual(RESERVATION_DATA["maximum_participant_transcript_likelihood_ratio"], "6561")
        self.assertTrue(duplicate_rejected(SimpleNamespace(returncode=1, stderr="AlreadyExists")))
        self.assertFalse(duplicate_rejected(SimpleNamespace(returncode=1, stderr="connection refused")))
        rows = witness.expected_calibration()
        lines = [
            "saf-quantized-calibration " + "".join(map(str, values)) + " "
            + "".join(map(str, coins)) + " " + format(output, "02b")
            for (values, coins), output in sorted(rows.items())
        ]
        log = "\n".join(lines + ["saf-quantized-vector 01011001"])
        receipt = stable_receipt(witness.parse_logs((log, log, log)))
        self.assertFalse(receipt["production_enforcement_claimed"])
        self.assertFalse(receipt["random_vector_in_normalized_receipt"])


if __name__ == "__main__":
    unittest.main()
