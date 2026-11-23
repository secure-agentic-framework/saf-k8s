"""Trace only a child process that touches an owned file and a loopback marker."""

import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


MARKER = "saf-0204-001-public.txt"
HERE = Path(__file__).resolve()


def workload(filename, port):
    assert Path(filename).read_text() == MARKER
    with socket.create_connection(("127.0.0.1", port), timeout=4) as peer:
        assert peer.recv(128).decode() == MARKER
    subprocess.run(["/usr/bin/true"], check=True)


def observe(listener, directory, path, *, capture):
    command = [sys.executable, str(HERE), str(path), str(listener.getsockname()[1])]
    destination = directory / "fixture.trace"
    if capture:
        command = ["strace", "-f", "-s", "192", "-o", str(destination),
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
    return {
        "workload_with_capture_completed": current.returncode == 0,
        "owned_file_open": any("openat(" in line and MARKER in line for line in lines),
        "loopback_connection": any("connect(" in line and 'inet_addr("127.0.0.1")' in line
                                   and f"htons({listener.getsockname()[1]})" in line for line in lines),
        "known_child_executed": any('execve("/usr/bin/true"' in line for line in lines),
    }


def main():
    with tempfile.TemporaryDirectory() as workspace, socket.socket() as listener:
        folder = Path(workspace)
        marker = folder / MARKER
        marker.write_text(MARKER)
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        baseline = observe(listener, folder, marker, capture=False)
        captured = observe(listener, folder, marker, capture=True)
        print(json.dumps({"workload_without_capture_emits_no_record": baseline, **captured}))


if __name__ == "__main__":
    if len(sys.argv) == 3:
        workload(sys.argv[1], int(sys.argv[2]))
    else:
        main()
