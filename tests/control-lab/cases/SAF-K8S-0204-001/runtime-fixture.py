"""Trace only a child process that touches an owned file and a loopback marker."""

import json
import os
import re
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener


MARKER = "saf-0204-001-public.txt"
HERE = Path(__file__).resolve()


def workload(filename, port):
    assert Path(filename).read_text() == MARKER
    with socket.create_connection(("127.0.0.1", port)) as peer:
        peer.settimeout(4)
        assert peer.recv(128).decode() == MARKER
    assert Path(filename).with_name("owned-out-of-scope.txt").read_text() == "ordinary fixture"
    subprocess.run(["/usr/bin/true"], check=True)


def observe(listener, directory, path, *, capture):
    command = [sys.executable, str(HERE), str(path), str(listener.getsockname()[1])]
    destination = directory / "fixture.trace"
    if capture:
        command = ["strace", "-f", "-ttt", "-s", "192", "-o", str(destination),
                   "-e", "trace=openat,connect,execve", *command]
    with subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as current:
        try:
            listener.settimeout(8)
            with listener.accept()[0] as peer:
                peer.sendall(MARKER.encode())
            _, details = current.communicate(timeout=8)
        except (OSError, subprocess.TimeoutExpired):
            current.kill()
            _, details = current.communicate()
            raise RuntimeError("Owned workload did not complete: " + details) from None
        if current.returncode:
            raise RuntimeError("Owned workload returned an error: " + details)
    if not capture:
        return not destination.exists()
    lines = destination.read_text().splitlines()
    selected = {
        "owned_file_open": lambda line: "openat(" in line and str(path) in line,
        "loopback_connection": lambda line: "connect(" in line and 'inet_addr("127.0.0.1")' in line
        and f"htons({listener.getsockname()[1]})" in line,
        "known_child_executed": lambda line: 'execve("/usr/bin/true"' in line,
    }
    result = {}
    for kind, matches in selected.items():
        candidates = [line for line in lines if matches(line) and re.search(r"= [0-9]+$", line)]
        line, = candidates
        stamp = re.search(r"\b[0-9]{10}\.[0-9]+\b", line)
        if stamp is None:
            raise RuntimeError("Selected event lacks a source timestamp")
        result[kind] = {"time_unix": stamp[0], "signal": kind}
    excluded = any("openat(" in line and "owned-out-of-scope.txt" in line
                   and re.search(r"= [0-9]+$", line) for line in lines)
    return list(result.values()), excluded


def deliver(events):
    outbound = {
        "pod_uid": os.environ["POD_UID"], "pod_name": os.environ["POD_NAME"],
        "namespace": os.environ["POD_NAMESPACE"], "node_name": os.environ["NODE_NAME"],
        "sensor": subprocess.check_output(["strace", "--version"], text=True).splitlines()[0],
        "events": events,
    }
    client = build_opener(ProxyHandler({}))
    target = Request("http://fixture-runtime-receiver:18082/events", data=json.dumps(outbound).encode(),
                     headers={"Content-Type": "application/json"})
    try:
        with client.open(target, timeout=6):
            first_status = 201
    except HTTPError as error:
        first_status = error.code
    with client.open(target, timeout=6) as response:
        return first_status, json.load(response), outbound


def main():
    with tempfile.TemporaryDirectory() as workspace, socket.socket() as listener:
        folder = Path(workspace)
        marker = folder / MARKER
        marker.write_text(MARKER)
        marker.with_name("owned-out-of-scope.txt").write_text("ordinary fixture")
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        baseline = observe(listener, folder, marker, capture=False)
        events, excluded = observe(listener, folder, marker, capture=True)
        first_status, ack, sender = deliver(events)
        print(json.dumps({"workload_without_capture_emits_no_record": baseline,
                          "out_of_scope_open_observed_locally": excluded,
                          "workload_with_capture_completed": True,
                          "initial_delivery_status": first_status, "ack": ack, "sender": sender}))


if __name__ == "__main__":
    if len(sys.argv) == 3:
        workload(sys.argv[1], int(sys.argv[2]))
    else:
        main()
