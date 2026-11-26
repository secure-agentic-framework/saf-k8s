"""Verify a narrow synthetic ServiceAccount-name filter before Pod stdout."""
import json
from pathlib import Path
import re
import subprocess
import tempfile

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

    # Fixed, deliberately invalid marker: this is not a Kubernetes token or credential.
    bearer_marker = "synthetic-bearer-canary-not-a-credential"
    bearer_line = f"Authorization: Bearer {bearer_marker}"
    bearer_env = [{"name": "OUTPUT", "value": bearer_line},
                  {"name": "IDENTIFIER", "value": name},
                  {"name": "REDACTED", "value": REDACTED}]
    bearer_red = stdout(lab, "saf-0402-003-bearer-raw", emit, bearer_env)
    lab.check("red", "The inert bearer lookalike is visible in the unfiltered fixture path",
              bearer_red == [bearer_line], {"exact_inert_marker_seen": bearer_red == [bearer_line]})
    bearer_filter = r''' | sed -E 's/(Authorization:[[:space:]]*Bearer[[:space:]]+)[^[:space:]]+/\1[synthetic bearer redacted]/' '''
    bearer_green = stdout(lab, "saf-0402-003-bearer-filtered",
                          emit + bearer_filter + script, bearer_env)
    expected_bearer = "Authorization: Bearer [synthetic bearer redacted]"
    lab.check("green", "The bearer value lookalike is removed before case-Pod stdout",
              bearer_green == [expected_bearer] and bearer_marker not in "\n".join(bearer_green),
              {"redacted": bearer_green == [expected_bearer],
               "marker_absent": bearer_marker not in "\n".join(bearer_green)})

    # A separate disposable local repository checks inert canary detection in the
    # current tree and in history. Command output is captured and never recorded.
    def git(repo, *args):
        return subprocess.run(["git", "-C", str(repo), *args], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, check=False)

    with tempfile.TemporaryDirectory(prefix="saf-0402-003-git-") as temporary:
        repo = Path(temporary)
        marker_file = repo / "fixture-ci.log"
        marker_file.write_text(bearer_line + "\n", encoding="utf-8")
        setup = [git(repo, "init", "-q"),
                 git(repo, "config", "user.name", "SAF inert fixture"),
                 git(repo, "config", "user.email", "fixture@example.invalid"),
                 git(repo, "add", "fixture-ci.log"),
                 git(repo, "commit", "-q", "-m", "Add inert canary fixture")]
        if any(result.returncode != 0 for result in setup):
            lab.block("Disposable local Git fixture setup failed (details suppressed)")
        current_leak = git(repo, "grep", "-I", "-F", "-l", "-e", bearer_marker, "HEAD", "--")
        lab.check("red", "The local repository check detects the inert bearer marker in a committed fixture",
                  current_leak.returncode == 0 and current_leak.stdout.strip() == "HEAD:fixture-ci.log",
                  {"current_fixture_marker_detected": current_leak.returncode == 0})
        marker_file.unlink()
        removed = [git(repo, "add", "-A"),
                   git(repo, "commit", "-q", "-m", "Remove inert canary from current tree")]
        if any(result.returncode != 0 for result in removed):
            lab.block("Disposable local Git cleanup commit failed (details suppressed)")
        current_clean = git(repo, "grep", "-I", "-F", "-l", "-e", bearer_marker, "HEAD", "--")
        history_hit = git(repo, "log", "--all", "--format=%H", "-S" + bearer_marker, "--", ".")
        lab.check("positive", "Current-tree scan is clean while history scan still identifies the prior canary commit",
                  current_clean.returncode == 1 and not current_clean.stdout.strip()
                  and history_hit.returncode == 0 and bool(history_hit.stdout.strip()),
                  {"current_tree_clean": current_clean.returncode == 1 and not current_clean.stdout.strip(),
                   "historical_marker_detected": history_hit.returncode == 0 and bool(history_hit.stdout.strip())})
