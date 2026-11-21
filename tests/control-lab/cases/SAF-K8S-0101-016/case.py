"""Prove local audit-file delivery and persistence across an API server restart."""
from contextlib import contextmanager
import json
from pathlib import Path
import re
import tempfile
import time

from lab import NODE_IMAGE


CASE_DIR = Path(__file__).resolve().parent
AUDIT_NODE_DIR = "/var/log/kubernetes/audit"
AUDIT_FILE = f"{AUDIT_NODE_DIR}/audit.log"
NAMESPACE = "saf-test"
MARKERS = {
    "pre": "saf-audit-durable-before-restart",
    "post": "saf-audit-durable-after-restart",
}
SCOPE = (
    "One case-owned local kind Kubernetes v1.36.1 control-plane. Synthetic Metadata-only "
    "ConfigMap patch events are first generated with no audit output path, then with the "
    "file backend writing to an explicitly host-mounted audit file. The case verifies exact "
    "request metadata, retains a pre-restart event, stops the owned API server container for "
    "kubelet to recreate, and verifies both retained and post-restart delivery. This tests "
    "local file visibility and restart survival only; it does not test power-loss durability, "
    "remote archival, tamper resistance, provider-managed control planes, or webhook delivery."
)


def patch_resource(name):
    return {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": name, "namespace": NAMESPACE}, "data": {"probe": "synthetic"}}


def client(lab, cluster, kubeconfig, *arguments, allow_failure=False):
    return lab.command("kubectl", "--kubeconfig", str(kubeconfig),
                       "--context", f"kind-{cluster}", "-n", NAMESPACE,
                       "--request-timeout=5s", *arguments, timeout=10,
                       allow_failure=allow_failure)


def request(lab, cluster, kubeconfig, name):
    lab.command("kubectl", "--kubeconfig", str(kubeconfig),
                "--context", f"kind-{cluster}", "-n", NAMESPACE,
                "--request-timeout=10s", "create", "-f", "-",
                payload=json.dumps(patch_resource(name)), timeout=15)
    client(lab, cluster, kubeconfig, "patch", f"configmap/{name}", "--type=merge",
           "-p", '{"data":{"probe":"updated"}}')


def event_metadata(directory, marker):
    path = directory / "audit.log"
    if not path.is_file():
        return None
    try:
        with path.open() as stream:
            for line in stream:
                event = json.loads(line)
                uri = event.get("requestURI", "").split("?", 1)[0]
                if (event.get("level") == "Metadata"
                        and event.get("stage") == "ResponseComplete" and event.get("verb") == "patch"
                        and uri.endswith(f"/configmaps/{marker}")
                        and event.get("responseStatus", {}).get("code") == 200):
                    return {"stage": event["stage"], "verb": event["verb"],
                            "namespace": event.get("objectRef", {}).get("namespace"),
                            "resource": event.get("objectRef", {}).get("resource"),
                            "name": event.get("objectRef", {}).get("name"),
                            "response_code": event["responseStatus"]["code"]}
    except (OSError, json.JSONDecodeError):
        return None
    return None


def wait_for_event(directory, marker, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        observed = event_metadata(directory, marker)
        if observed:
            return observed
        time.sleep(0.25)
    return event_metadata(directory, marker)


def api_container(lab, node):
    result = lab.command("docker", "exec", node, "crictl", "ps", "--state", "Running",
                         "--name", "^kube-apiserver$", "--quiet",
                         allow_failure=True, timeout=10)
    ids = result.stdout.splitlines()
    if result.returncode == 0 and len(ids) == 1 and re.fullmatch("[a-f0-9]+", ids[0]):
        return ids[0]
    return None


def restart_api_server(lab, cluster, kubeconfig):
    node = f"{cluster}-control-plane"
    previous = api_container(lab, node)
    if not previous:
        lab.block("Could not identify the owned API server container before restart")
    lab.command("docker", "exec", node, "crictl", "stop", previous, timeout=45)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        running = api_container(lab, node)
        if running and running != previous:
            ready = client(lab, cluster, kubeconfig, "get", "--raw=/readyz", allow_failure=True)
            if ready.returncode == 0 and ready.stdout.strip() == "ok":
                return
        time.sleep(1)
    lab.block("Owned API server did not become ready with a different container ID")


@contextmanager
def audit_cluster(lab):
    cluster = f"{lab.cluster}-audit"
    if cluster in lab.command("kind", "get", "clusters").stdout.splitlines():
        lab.block("Audit comparison cluster name is already in use")
    with tempfile.TemporaryDirectory(prefix="saf-audit-file-") as temporary:
        working_dir = Path(temporary).resolve()
        audit_dir = working_dir / "audit"
        audit_dir.mkdir()
        kubeconfig = working_dir / "kubeconfig"
        profile = working_dir / "kind.yaml"
        template = (CASE_DIR / "kind-profile.yaml.in").read_text()
        profile.write_text(template.replace("@AUDIT_POLICY@", json.dumps(str(CASE_DIR / "audit-policy.yaml")))
                           .replace("@AUDIT_DIRECTORY@", json.dumps(str(audit_dir))))
        try:
            lab.command("kind", "create", "cluster", "--name", cluster, "--image", NODE_IMAGE,
                        "--config", str(profile), "--kubeconfig", str(kubeconfig),
                        "--wait", "90s", timeout=480)
            client(lab, cluster, kubeconfig, "create", "namespace", NAMESPACE)
            yield cluster, kubeconfig, audit_dir
        finally:
            lab.command("kind", "delete", "cluster", "--name", cluster,
                        "--kubeconfig", str(kubeconfig), timeout=90)


def run(lab):
    request(lab, lab.cluster, lab.kubeconfig, MARKERS["pre"])
    absent = lab.command("docker", "exec", f"{lab.cluster}-control-plane",
                         "test", "!", "-e", AUDIT_FILE, allow_failure=True)
    lab.check("red", "Disabled baseline has no audit file after a successful request",
              absent.returncode == 0,
              {"request_completed": True, "audit_file_absent": absent.returncode == 0})

    with audit_cluster(lab) as (cluster, kubeconfig, audit_dir):
        before = MARKERS["pre"]
        request(lab, cluster, kubeconfig, before)
        first = wait_for_event(audit_dir, before)
        lab.check("green", "The file backend delivers a searchable Metadata-only patch event",
                  first == {"stage": "ResponseComplete", "verb": "patch", "namespace": NAMESPACE,
                            "resource": "configmaps", "name": before, "response_code": 200}, first)

        restart_api_server(lab, cluster, kubeconfig)
        retained = event_metadata(audit_dir, before)
        lab.check("green", "The earlier audit event remains searchable after API server restart",
                  retained == first, {"pre_event_retained": retained == first,
                                     "api_server_container_recreated_and_ready": True})

        after = MARKERS["post"]
        request(lab, cluster, kubeconfig, after)
        event = wait_for_event(audit_dir, after)
        lab.check("positive", "A new request is successfully delivered to the mounted file after restart",
                  event == {"stage": "ResponseComplete", "verb": "patch", "namespace": NAMESPACE,
                            "resource": "configmaps", "name": after, "response_code": 200}, event)
