"""Check withdrawal of an enrolled leaf on the live Flower Fleet route."""

import json
import selectors
import subprocess
from tempfile import TemporaryFile


ROSTER = "fixture-fleet-enrollment"
READY = {"event": "fleet-hold-ready", "tls": "TLSv1.3", "settings_observed": True}
CLOSED = {"event": "fleet-hold-closed", "outcome": "closed"}
RETIRED = "participant-c"


def read_json(client, *args):
    return json.loads(client.kubectl(*args, "-o", "json").stdout)


def gateway_identity(lab, name):
    item = read_json(lab, "get", "pod", name)
    return (item["metadata"]["uid"], {container["name"]: (container.get("containerID"), container["restartCount"])
                                    for container in item["status"]["containerStatuses"]})


def read_line(lab, process, selector, deadline):
    if not selector.select(deadline):
        lab.block("The Fleet connection probe did not reach the expected checkpoint")
    body = process.stdout.readline(2048)
    if not body.endswith(b"\n"):
        lab.block("The Fleet connection probe emitted an incomplete checkpoint")
    try:
        return json.loads(body)
    except (ValueError, UnicodeError):
        lab.block("The Fleet connection probe emitted an invalid checkpoint")


def retire(lab, peer, names, gateway, endpoint, port, allowlist):
    command = ["python", "-B", "/fleet/hold.py", endpoint, str(port)]
    runner = [
        "kubectl", "--kubeconfig", str(peer.kubeconfig), "--context", f"kind-{peer.cluster}",
        "--namespace", "saf-test", "exec", f"pod/{names[2]}", "-c", "relay", "--", *command,
    ]
    before = gateway_identity(lab, gateway)
    expected = {digest: member for digest, member in allowlist.items() if member != RETIRED}
    if len(allowlist) != 3 or set(expected.values()) != {"participant-a", "participant-b"}:
        lab.block("Expected the exact prior enrolled cohort before participant withdrawal")

    with TemporaryFile() as stderr, selectors.DefaultSelector() as selector:
        process = subprocess.Popen(runner, env=peer.env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=stderr)
        try:
            selector.register(process.stdout, selectors.EVENT_READ)
            ready = read_line(lab, process, selector, 20)
            if ready != READY:
                lab.block("The originally enrolled leaf could not open the live Fleet transport")
            current = read_json(lab, "get", "configmap", ROSTER)
            if json.loads(current["data"]["allow.json"]) != allowlist:
                lab.block("The roster changed before the approved retirement step")
            patch = [{
                "op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"],
            }, {"op": "replace", "path": "/data/allow.json", "value": json.dumps(expected, sort_keys=True)}]
            new = read_json(lab, "patch", "configmap", ROSTER, "--type=json", "-p", json.dumps(patch))
            if (new["metadata"]["resourceVersion"] == current["metadata"]["resourceVersion"]
                    or json.loads(new["data"]["allow.json"]) != expected):
                lab.block("The API did not record the requested exact roster update")
            lab.kubectl("annotate", "pod", gateway, "fixture.example/enrollment-refresh=retirement", "--overwrite")
            closed = read_line(lab, process, selector, 120)
            if closed != CLOSED or process.wait(timeout=5) != 0:
                lab.block("The existing Fleet connection did not observe a clean server-side closure")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            process.stdout.close()

    rejected = peer.kubectl("exec", f"pod/{names[2]}", "-c", "relay", "--", "python", "-B", "/fleet/relay.py",
                            "probe", endpoint, str(port), "retired", timeout=22)
    healthy = peer.kubectl("exec", f"pod/{names[1]}", "-c", "relay", "--", *command, "--once", timeout=22)
    log = lab.kubectl("logs", f"pod/{gateway}", "-c", "relay", "--tail=200").stdout
    events = [json.loads(line) for line in log.splitlines()]
    checks = {
        "enrolled_leaf_previously_reached_actual_fleet_http2": ready == READY,
        "only_retired_participant_removed_from_roster": set(expected.values()) == {"participant-a", "participant-b"},
        "gateway_observed_the_projected_roster": {"event": "roster-reloaded", "participants": sorted(expected.values())}
        in events,
        "existing_fleet_connection_closed": closed == CLOSED and
        {"event": "retired-fleet-session", "participant": RETIRED} in events,
        "same_ca_valid_leaf_could_not_reopen_fleet": json.loads(rejected.stdout) == {
            "mode": "retired", "outcome": "closed-without-admission"} and
        {"event": "retired-leaf-denied", "participant": RETIRED} in events,
        "unaffected_leaf_still_reaches_actual_fleet_http2": json.loads(healthy.stdout) == READY,
        "gateway_pod_and_containers_were_not_restarted": gateway_identity(lab, gateway) == before,
    }
    (lab.evidence / "flower-participant-retirement.json").write_text(
        json.dumps({"transport": "TLSv1.3", "retired_participant": RETIRED, "observations": checks},
                   sort_keys=True, indent=2) + "\n", encoding="utf-8")
    lab.check("cross-cluster-participant-retirement",
              "Withdrawing one enrolled leaf closes its existing Fleet connection and denies reconnection",
              all(checks.values()), checks)
