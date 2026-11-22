"""Verify a narrow synthetic ServiceAccount-name filter before Pod stdout."""
import json
from pathlib import Path
import re

from fixtures import container, pod


HERE = Path(__file__).parent
REDACTED = "[synthetic service account identifier redacted]"
SCOPE = (
    "Two short non-root Pods in a disposable kind cluster process only the checked-in "
    "synthetic stdout lines. A case-local process filter redacts lines carrying one exact "
    "synthetic name and retains both other lines. The test reads only the two case Pods' "
    "stdout and disables credential automount. Production log aggregation, token protection, "
    "repository and image scanning, API sanitization, and external exposure remain separate."
)


def stdout(lab, name, command, env):
    lab.create(pod(name, [container("emit", command=["sh", "-ec", command], env=env)],
                   automountServiceAccountToken=False))
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded", f"pod/{name}",
                "--timeout=65s", timeout=75)
    return lab.kubectl("logs", name, "-c", "emit").stdout.splitlines()


def run(lab):
    fixture = json.loads((HERE / "fixtures.json").read_text())
    name = fixture["synthetic_service_account_identifier"]
    if not re.fullmatch(r"synthetic-sa-[a-z0-9-]+", name):
        lab.block("Expected an inert fixture identifier")
    expected = [fixture["matching_output"], fixture["nonmatching_output"],
                fixture["matching_output"].replace(name, f"{name}-unrelated")]
    env = [{"name": "OUTPUT", "value": "\n".join(expected)},
           {"name": "IDENTIFIER", "value": name}, {"name": "REDACTED", "value": REDACTED}]
    emit = r'''printf '%s\n' "$OUTPUT"'''
    red = stdout(lab, "saf-0402-003-raw", emit, env)
    lab.check("red", "The exact synthetic identifier reaches Pod stdout with the filter absent",
              red == expected, {"exact_fixture_round_trip": red == expected, "lines": len(red)})
    script = """ | awk -v name="$IDENTIFIER" -v replacement="$REDACTED" '
      BEGIN { pattern = "(^|[^[:alnum:]_.-])" name "($|[^[:alnum:]_.-])" }
      $0 ~ pattern { print replacement; next }
      { print }
    '"""
    green = stdout(lab, "saf-0402-003-filtered", emit + script, env)
    lab.check("green", "Only the exact configured identifier's line is redacted before stdout",
              green == [REDACTED, *expected[1:]],
              {"redacted_lines": green.count(REDACTED), "total_lines": len(green)})
    lab.check("positive", "An unrelated name and a longer shared-prefix name remain intact",
              green[1:] == expected[1:], {"unrelated_lines_intact": green[1:] == expected[1:]})
