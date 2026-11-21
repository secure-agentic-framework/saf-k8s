"""Measure idle and active sessions on the pinned containerd CRI implementation."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import select
import socket
import subprocess
import tempfile
import time

from fixtures import container, pod

SCOPE = ("Containerd CRI idle timing for standard Kubernetes attach and port-forward; "
         "application-idle exec measured separately and routine exec access restricted via RBAC.")
IDLE = 5
WINDOW = IDLE + 4
OPERATIONS = ("exec", "attach", "port-forward")
ECHO = "while IFS= read -r line; do printf '%s\\n' \"$line\"; done"
MESSAGE = b"fixture-echo\n"
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"


def client(cluster, kubeconfig):
    return ["kubectl", "--kubeconfig", str(kubeconfig), "--context", f"kind-{cluster}",
            "--namespace", "saf-test"]


def fixtures(lab, args):
    resources = (
        pod("echo-shell", [container("probe", command=["sh", "-c", ECHO], stdin=True)]),
        pod("echo-tcp", [container("probe", command=[
            "sh", "-c", "while :; do nc -l -p 8080 -e /bin/cat; sleep 0.1; done",
        ])]),
    )
    lab.command(*args, "wait", "--for=create", "serviceaccount/default", "--timeout=20s")
    for resource in resources:
        lab.command(*args, "create", "-f", "-", payload=json.dumps(resource))
    lab.command(*args, "wait", "--for=condition=Ready", "pod/echo-shell", "pod/echo-tcp",
                "--timeout=95s", timeout=110)


@contextmanager
def connection_process(lab, args):
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=errors, bufsize=0, env=lab.env)
        try:
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            errors.seek(0)
            error = errors.read().decode(errors="replace").strip()
            if error:
                with (lab.evidence / "stream.log").open("a") as output:
                    output.write(f"{args[-1]}: {error}\n")
            process.stdin.close()
            process.stdout.close()


def pipe_line(pipe, seconds):
    deadline = time.monotonic() + seconds
    data = bytearray()
    while select.select([pipe], [], [], max(0, deadline - time.monotonic()))[0]:
        value = os.read(pipe.fileno(), 1)
        if not value or value == b"\n":
            return bytes(data)
        data += value
        if time.monotonic() >= deadline:
            break
    return None


def socket_echo(conn):
    conn.sendall(MESSAGE)
    result = bytearray()
    while len(result) < len(MESSAGE):
        chunk = conn.recv(len(MESSAGE) - len(result))
        if not chunk:
            break
        result += chunk
    return result == MESSAGE


def measure(echo, closed, active):
    if not echo():
        return {"established": False}
    healthy = True
    if active:
        deadline = time.monotonic() + WINDOW
        while time.monotonic() < deadline:
            time.sleep(0.75)
            if not echo():
                healthy = False
                break
    started = time.monotonic()
    did_close = closed(WINDOW)
    return {"established": True, "active_survived": healthy if active else None,
            "idle_closed": did_close, "idle_duration_s": round(time.monotonic() - started, 2)}


def observe(lab, args, operation, active=False):
    modes = {
        "exec": ("exec", "-i", "echo-shell", "--", "sh", "-c", ECHO),
        "attach": ("attach", "-i", "echo-shell"),
        "port-forward": ("port-forward", "--address=127.0.0.1", "pod/echo-tcp", ":8080"),
    }
    with connection_process(lab, [*args, *modes[operation]]) as process:
        if operation == "port-forward":
            line = pipe_line(process.stdout, 12) or b""
            match = re.fullmatch(rb"Forwarding from 127\.0\.0\.1:(\d+) -> 8080", line)
            if not match:
                return {"established": False, "listener": line.decode(errors="replace")}
            with socket.create_connection(("127.0.0.1", int(match[1])), timeout=3) as stream:
                def echo():
                    try:
                        return socket_echo(stream)
                    except OSError:
                        return False

                def closed(seconds):
                    stream.settimeout(seconds)
                    try:
                        return stream.recv(1) == b""
                    except socket.timeout:
                        return False
                    except ConnectionResetError:
                        return True

                return measure(echo, closed, active)

        def echo():
            try:
                process.stdin.write(MESSAGE)
                for _ in range(4):
                    response = pipe_line(process.stdout, 2)
                    if response == MESSAGE.rstrip():
                        return True
                    if response in (None, b""):
                        return False
            except BrokenPipeError:
                return False
            return False

        def closed(seconds):
            return pipe_line(process.stdout, seconds) == b""

        return measure(echo, closed, active)


def timeout_config(lab, cluster):
    node = f"{cluster}-control-plane"
    version = lab.command("docker", "exec", node, "containerd", "--version").stdout.strip()
    config = lab.command("docker", "exec", node, "containerd", "config", "dump").stdout
    value = re.search(r"stream_idle_timeout\s*=\s*['\"]([^'\"]+)", config)
    return {"version": version, "timeout": value[1] if value else None}


@contextmanager
def tuned_profile(lab):
    cluster = lab.cluster + "-tuned"
    if cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block(f"Additional analysis cluster already exists: {cluster}")
    with tempfile.TemporaryDirectory(prefix="saf-stream-runtime-") as temp:
        kubeconfig = Path(temp) / "kubeconfig"
        config = Path(temp) / "kind.yaml"
        config.write_text(
            "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\n"
            "containerdConfigPatches:\n- |\n"
            '    [plugins."io.containerd.grpc.v1.cri"]\n'
            f'      stream_idle_timeout = "{IDLE}s"\n'
        )
        try:
            lab.command("kind", "create", "cluster", "--name", cluster, "--image", NODE_IMAGE,
                        "--config", str(config), "--kubeconfig", str(kubeconfig),
                        "--wait", "90s", timeout=480)
            args = client(cluster, kubeconfig)
            lab.command(*args, "create", "namespace", "saf-test")
            yield cluster, args
        finally:
            lab.command("kind", "delete", "cluster", "--name", cluster,
                        "--kubeconfig", str(kubeconfig), timeout=90)


def routine_stream_restriction(lab, args, restricted):
    actor = [*args, "--as=saf-stream-routine-operator", "--as-group=system:authenticated"]
    rule = {"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}
    streams = {"apiGroups": [""], "verbs": ["get", "create"]}
    operations = {"exec": "pods/exec", "attach": "pods/attach", "port-forward": "pods/portforward"}
    remaining = [op for op in operations if op not in restricted]

    def configure_role(stream_names):
        role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                "metadata": {"name": "routine-stream-operator"},
                "rules": [rule, {**streams, "resources": stream_names}]}
        lab.command(*args, "apply", "-f", "-", payload=json.dumps(role))

    configure_role(list(operations.values()))
    binding = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
               "metadata": {"name": "routine-stream-operator"},
               "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "User",
                             "name": "saf-stream-routine-operator"}],
               "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role",
                           "name": "routine-stream-operator"}}
    lab.command(*args, "apply", "-f", "-", payload=json.dumps(binding))
    command = (*actor, "exec", "echo-shell", "--", "printf", "routine-fixture")
    original = lab.command(*command)
    lab.check("red", "Routine exec is available before the access restriction",
              original.stdout == "routine-fixture", original.stdout)
    configure_role([operations[op] for op in remaining])
    def denied_upgrade(result, resource):
        text = result.stderr
        return (result.returncode != 0 and resource in text
                and "saf-stream-routine-operator" in text
                and (" is forbidden:" in text or "(Forbidden)" in text))

    deadline = time.monotonic() + 10
    while True:
        result = lab.command(*command, allow_failure=True)
        denied = denied_upgrade(result, "pods/exec")
        if denied or time.monotonic() >= deadline:
            break
        time.sleep(0.25)
    lab.check("green", "Routine exec is denied by Kubernetes authorization",
              denied, result.stderr.strip())

    if "attach" in restricted:
        result = lab.command(*actor, "attach", "-i", "echo-shell", allow_failure=True)
        lab.check("green", "Routine attach is denied by Kubernetes authorization",
                  denied_upgrade(result, "pods/attach"), result.stderr.strip())

    for op in operations:
        for verb in ("get", "create"):
            subresource = operations[op].split("/", 1)[1]
            decision = lab.command(*actor, "auth", "can-i", verb, "pods",
                                   f"--subresource={subresource}", allow_failure=True)
            allowed = op in remaining
            lab.check("positive" if allowed else "green",
                      f"Routine authorization for {verb} pods/{subresource} is correctly scoped",
                      decision.stdout.strip() == ("yes" if allowed else "no")
                      and decision.returncode == (0 if allowed else 1),
                      decision.stdout.strip() or decision.stderr.strip())


def run_profile(lab, required, restricted):
    original = client(lab.cluster, lab.kubeconfig)
    fixtures(lab, original)
    baseline = {op: observe(lab, original, op) for op in OPERATIONS}
    default_config = timeout_config(lab, lab.cluster)
    lab.check("red", "Established default runtime streams stay open beyond the lab limit",
              all(r.get("established") and not r["idle_closed"] for r in baseline.values()),
              {"config": default_config, "observations": baseline})

    with tuned_profile(lab) as (cluster, args):
        config = timeout_config(lab, cluster)
        lab.check("positive", "The runtime's effective configured timeout matches the profile",
                  "2.3." in config["version"] and config["timeout"] == f"{IDLE}s", config)
        fixtures(lab, args)
        observed = {op: observe(lab, args, op, active=True) for op in OPERATIONS}
        validated = [op for op, row in observed.items()
                     if row.get("established") and row["active_survived"] and row["idle_closed"]
                     and IDLE - 1 <= row["idle_duration_s"] < WINDOW]
        lab.check("green", "The timeout closes each allowed idle path after active traffic stops",
                  required <= set(validated),
                  {"verified_operations": validated, "observations": observed})
        lab.check("positive", "Paths requiring authorization restrictions were individually measured",
                  all(observed[op].get("established") for op in restricted),
                  {op: observed[op] for op in restricted})
        routine_stream_restriction(lab, args, restricted)


def run(lab):
    run_profile(lab, {"attach", "port-forward"}, ("exec",))
