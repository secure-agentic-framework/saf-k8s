"""Verify a narrow synthetic ServiceAccount-name filter before Pod stdout."""
import json
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import re
import subprocess
import tempfile
from threading import Thread

from fixtures import container, pod


HERE = Path(__file__).parent
REDACTED = "[synthetic service account identifier redacted]"
SCOPE = (
    "Four short non-root Pods in a disposable kind cluster process only the checked-in "
    "synthetic stdout lines. A case-local process filter redacts lines carrying one exact "
    "synthetic name and retains both other lines. The test reads only the two case Pods' "
    "stdout and disables credential automount. A separate loopback-only HTTP handler compares "
    "an inert error response with and without a fixed response sanitizer. Production log "
    "aggregation, token protection, repository and image scanning, deployed API behavior, "
    "and external exposure remain separate."
)


def response_redaction_probe(lab, marker):
    """Compare one fixed synthetic API error response; retain booleans only."""
    replacement = "[synthetic bearer redacted]"
    pattern = re.compile(r'(Authorization:\s*Bearer\s+)[^\s",}]+', re.IGNORECASE)
    baseline_body = (f'{{"error":"invalid Authorization: Bearer {marker}",'
                     '"request_id":"fixture-request-0402-003","state":"unchanged"}}')

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = baseline_body
            if self.path == "/filtered":
                body = pattern.sub(lambda match: match.group(1) + replacement, body)
            encoded = body.encode("utf-8")
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, _format, *_args):
            # Never copy request or response content to stdout/stderr.
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.timeout = 3
    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    baseline = filtered = None
    try:
        for path, slot in (("/baseline", "baseline"), ("/filtered", "filtered")):
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            try:
                connection.request("GET", path)
                response = connection.getresponse()
                value = (response.status, response.read().decode("utf-8"))
            finally:
                connection.close()
            if slot == "baseline":
                baseline = value
            else:
                filtered = value
    except Exception:
        lab.block("Loopback response comparison failed (details suppressed)")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    raw_status, raw_body = baseline
    filtered_status, filtered_body = filtered
    raw_control = raw_status == 400 and marker in raw_body
    filtered_control = (
        filtered_status == 400
        and marker not in filtered_body
        and replacement in filtered_body
        and '"request_id":"fixture-request-0402-003"' in filtered_body
        and '"state":"unchanged"' in filtered_body
    )
    lab.check(
        "green",
        "A loopback HTTP error response redacts the inert bearer marker and preserves safe fields",
        raw_control and filtered_control,
        {"baseline_exposed_in_memory": raw_control,
         "filtered_marker_absent": marker not in filtered_body,
         "safe_fields_preserved": ('"request_id":"fixture-request-0402-003"' in filtered_body
                                   and '"state":"unchanged"' in filtered_body),
         "response_body_retained": False},
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

    response_redaction_probe(lab, bearer_marker)
