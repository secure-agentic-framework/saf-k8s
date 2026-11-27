"""Pure local counterfactuals for the bounded route-read sequence oracle."""
import importlib.util
from pathlib import Path


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("route_delivery", HERE / "route_delivery.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
expected = sorted(module.EXPECTED_DELIVERIES)


def main():
    good = module.assess_delivery_reads(expected, [expected], True)
    assert good["read_sequence_complete"] and good["expected_deliveries_present"]
    assert not good["unexpected_records"] and not good["normal_target_notification_seen"]

    missing = module.assess_delivery_reads(expected[:1], [expected[:1]], True)
    assert missing["read_sequence_complete"] and not missing["expected_deliveries_present"]

    wrong = list(expected) + [("wrong-route", *expected[0][1:])]
    unexpected = module.assess_delivery_reads(wrong, [wrong], True)
    assert unexpected["unexpected_records"]

    normal = list(expected) + [("case-local-fixture", "firing", "Normal", "normal", "normal",
                                "warning", "fixture-accelerator-exporter:8080")]
    normal_case = module.assess_delivery_reads(normal, [normal], True)
    assert normal_case["normal_target_notification_seen"]
    assert normal_case["unexpected_records"]

    unreadable = module.assess_delivery_reads(expected, [None], False)
    assert not unreadable["read_sequence_complete"]
    assert not unreadable["expected_deliveries_present"]
    print("route sequence oracle counterfactuals: 5 passed")


if __name__ == "__main__":
    main()
