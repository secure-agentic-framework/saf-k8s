"""Offline evidence-shape supplement for SAF-K8S-0704-004.

The records are AWS-shaped static fixtures, not provider observations. This
adapter maps the selected EC2 instance's effective MetadataOptions into the
existing case classifier and refuses a mismatched or incomplete identity.
"""

import json
from pathlib import Path


REQUIRED_OPTIONS = {
    "HttpEndpoint", "HttpProtocolIpv6", "HttpPutResponseHopLimit",
    "HttpTokens", "InstanceMetadataTags", "State",
}
ALLOWED_ENDPOINT = {"enabled", "disabled"}
ALLOWED_IPV6 = {"enabled", "disabled"}
ALLOWED_TOKENS = {"required", "optional"}
ALLOWED_STATE = {"applied", "pending"}


def _all_instances(response):
    if not isinstance(response, dict):
        return []
    reservations = response.get("Reservations")
    if not isinstance(reservations, list):
        return []
    instances = []
    for reservation in reservations:
        if not isinstance(reservation, dict):
            continue
        rows = reservation.get("Instances")
        if isinstance(rows, list):
            instances.extend(row for row in rows if isinstance(row, dict))
    return instances


def _inspect(observation, intended_template, current_result):
    expected_id = observation.get("expected_instance_id")
    instances = _all_instances(observation.get("describe_instances"))
    matches = [row for row in instances if row.get("InstanceId") == expected_id]
    identity_match = bool(expected_id) and len(matches) == 1
    if not identity_match:
        return {"case": observation.get("case"), "expected_instance_id": expected_id,
                "returned_instance_ids": [row.get("InstanceId") for row in instances],
                "instance_identity_match": False,
                "launch_template_reference_match": False,
                "classification": "unverified", "effective_metadata_options": None,
                "template_effective_differences": []}

    instance = matches[0]
    expected_reference = {key: intended_template[key]
                          for key in ("LaunchTemplateId", "Version")}
    actual_reference = instance.get("LaunchTemplate")
    reference_match = (isinstance(actual_reference, dict)
                       and actual_reference.get("LaunchTemplateId") == expected_reference["LaunchTemplateId"]
                       and str(actual_reference.get("Version")) == str(expected_reference["Version"]))
    options = instance.get("MetadataOptions")
    fields_complete = isinstance(options, dict) and REQUIRED_OPTIONS.issubset(options)
    if fields_complete:
        hop_limit = options.get("HttpPutResponseHopLimit")
        fields_valid = (
            options.get("HttpEndpoint") in ALLOWED_ENDPOINT
            and options.get("HttpProtocolIpv6") in ALLOWED_IPV6
            and options.get("HttpTokens") in ALLOWED_TOKENS
            and options.get("State") in ALLOWED_STATE
            and options.get("InstanceMetadataTags") in ALLOWED_ENDPOINT
            and isinstance(hop_limit, int) and not isinstance(hop_limit, bool)
            and 1 <= hop_limit <= 64
        )
    else:
        fields_valid = False

    classification = "unverified"
    if fields_valid:
        classification = current_result({"live": {
            "HttpEndpoint": options["HttpEndpoint"],
            "HttpTokens": options["HttpTokens"],
            "State": options["State"],
        }})
    template_options = intended_template.get("LaunchTemplateData", {}).get("MetadataOptions", {})
    differences = sorted(key for key in REQUIRED_OPTIONS - {"State"}
                         if options.get(key) != template_options.get(key)) if fields_complete else []
    return {"case": observation.get("case"), "expected_instance_id": expected_id,
            "returned_instance_ids": [row.get("InstanceId") for row in instances],
            "instance_identity_match": identity_match,
            "launch_template_reference_match": reference_match,
            "classification": classification,
            "effective_metadata_options": options if fields_complete else None,
            "effective_fields_valid": fields_valid,
            "template_effective_differences": differences,
            "expected_disposition": observation.get("expected_disposition")}


def run(lab, case_dir, current_result):
    fixture_path = Path(case_dir) / "fixtures" / "ec2-effective-metadata.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    intended = fixture["intended_launch_template"]
    observations = [_inspect(row, intended, current_result)
                    for row in fixture["observations"]]
    expected = {
        "applied-matches-intent": (True, True, "session-required", []),
        "effective-differs-from-template": (True, True, "session-not-required", ["HttpTokens"]),
        "change-pending": (True, True, "unverified", []),
        "instance-identity-mismatch": (False, False, "unverified", []),
    }
    actual = {row["case"]: (
        row["instance_identity_match"], row["launch_template_reference_match"],
        row["classification"], row["template_effective_differences"])
        for row in observations}
    matched = actual == expected and len(observations) == len(expected)
    evidence = {
        "scope": "Offline AWS-shaped DescribeInstances fixture parsed by expected InstanceId; no provider API, metadata endpoint, credentials, or cloud resources contacted.",
        "api_version": fixture["ec2_api_version"],
        "source_apis": fixture["source_apis"],
        "intended_launch_template": intended,
        "observations": observations,
        "expected_dispositions": {name: values[2] for name, values in expected.items()},
        "result_match": matched,
        "hop_limit_recorded_as_observed_field_only": True,
        "universal_hop_limit_policy_asserted": False,
        "provider_evidence_claimed": False,
    }
    (lab.evidence / "effective-ec2-metadata-shape.raw.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lab.check("green",
              "The offline EC2 response gate matches the requested instance, distinguishes effective settings from template intent, and leaves pending or mismatched evidence unverified",
              matched,
              {"applied_effective_observation_matches": actual.get("applied-matches-intent") == expected["applied-matches-intent"],
               "effective_optional_state_overrides_required_template_intent": actual.get("effective-differs-from-template") == expected["effective-differs-from-template"],
               "pending_state_is_unverified": actual.get("change-pending") == expected["change-pending"],
               "wrong_instance_identity_is_unverified": actual.get("instance-identity-mismatch") == expected["instance-identity-mismatch"],
               "raw_evidence": "effective-ec2-metadata-shape.raw.json",
               "provider_settings_or_hop_limit_policy_claimed": False})
