"""Test namespace-local image pull Secret delivery and a private fixture pull."""
import base64
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid
from collections import Counter
from http.client import HTTPConnection
from urllib.parse import unquote

from fixtures import container, pod

HERE = Path(__file__).resolve().parent
ACCOUNT = "fixture-pull-account"
SECRET = "fixture-empty-pull-config"
SCOPE = (
    "One disposable namespace, an empty dockerconfigjson Secret and normal ServiceAccount "
    "admission. Reference injection and an ordinary public-image workload are verified. "
    "A pinned owned registry separately checks wrong-credential refusal and a correct "
    "same-namespace Secret pulling one exact inert digest. External Secret managers, CI "
    "delivery, rotation and production authorization need separate evidence."
)


def classify(surface, form):
    if form == "direct-value" and surface in {"Pod workload", "Dockerfile", "CI environment"}:
        return "prohibited-value"
    if surface == "Pod imagePullSecrets reference" and form == "name-only-reference":
        return "allowed-reference"
    return "unclassified"


def evaluate_examples(lab):
    samples = json.loads((HERE / "embedding-cases.json").read_text())
    observed = {sample["surface"]: classify(sample["surface"], sample["form"])
                for sample in samples}
    expected = {
        "Pod workload": "prohibited-value",
        "Dockerfile": "prohibited-value",
        "CI environment": "prohibited-value",
        "Pod imagePullSecrets reference": "allowed-reference",
    }
    lab.check("red", "The policy example flags embedded-value forms in each named surface",
              observed == expected, observed)


def create_empty_pull_secret(lab):
    resource = {
        "apiVersion": "v1", "kind": "Secret", "metadata": {"name": SECRET},
        "type": "kubernetes.io/dockerconfigjson",
        "stringData": {".dockerconfigjson": json.dumps({"auths": {}})},
    }
    command = [
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "--namespace", "saf-test", "--request-timeout=20s",
        "create", "-f", "-", "-o", "name",
    ]
    result = subprocess.run(command, input=json.dumps(resource), text=True,
                            capture_output=True, env=lab.env, timeout=30)
    lab.check("positive", "The API admits the namespace-local empty pull configuration",
              result.returncode == 0 and result.stdout.strip() == f"secret/{SECRET}",
              {"secret_admitted": result.returncode == 0})


REGISTRY_IMAGE = (
    "docker.io/library/registry:3.0.0@sha256:"
    "6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
)
SKOPEO_IMAGE = (
    "quay.io/skopeo/stable:v1.20.0@sha256:"
    "47853bb9fb24202af9110531ebd6e43c5f97701254ca290596640290d17942f4"
)


def _quiet(args, *, env, input_text=None, timeout=45, allow_failure=False):
    """Keep credential-adjacent subprocess output out of evidence and command logs."""
    try:
        result = subprocess.run(args, input=input_text, text=True, capture_output=True,
                                env=env, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"{Path(args[0]).name} could not complete") from error
    if result.returncode and not allow_failure:
        raise RuntimeError(f"{Path(args[0]).name} returned a failure")
    return result


def _private_image_pod(name, image, secret):
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": "saf-test"},
        "spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "imagePullSecrets": [{"name": secret}],
            "containers": [{
                "name": "fixture", "image": image, "imagePullPolicy": "Always",
                "command": ["sh", "-ec", "printf private-pull-ok"],
                "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                              "limits": {"cpu": "100m", "memory": "32Mi"}},
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                    "runAsNonRoot": True, "runAsUser": 65534,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
            }],
        },
    }


def _registry_records(raw):
    """Read the pinned registry's combined HTTP access log, without retaining it."""
    records = []
    for line in raw.splitlines():
        entry = re.match(
            r'^\S+ \S+ \S+ \[[^]]+\] "(HEAD|GET) (/v2/\S*) HTTP/[\d.]+" (\d{3}) (?:\d+|-)(?: |$)',
            line,
        )
        if entry:
            method, uri, status = entry.groups()
            records.append((method, unquote(uri.split("?", 1)[0]), int(status)))
    return records


def _record_delta(before, after):
    remaining = Counter(before)
    delta = []
    for record in after:
        if remaining[record]:
            remaining[record] -= 1
        else:
            delta.append(record)
    return delta


def _wait_registry(host_port):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        connection = HTTPConnection("127.0.0.1", host_port, timeout=2)
        try:
            connection.request("GET", "/v2/")
            if connection.getresponse().status == 401:
                return
        except OSError:
            pass
        finally:
            connection.close()
        time.sleep(0.3)
    raise RuntimeError("owned registry did not issue its expected authentication challenge")


def _get_pod_quiet(lab, name):
    result = _quiet([
        "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
        "--namespace", "saf-test", "--request-timeout=10s", "get", "pod", name, "-o", "json",
    ], env=lab.env, timeout=15, allow_failure=True)
    if result.returncode:
        return None
    return json.loads(result.stdout)


def _wait_private_pod(lab, name, *, denied=False, timeout=60):
    deadline = time.monotonic() + timeout
    last = None
    expected = {"ErrImagePull", "ImagePullBackOff"}
    while time.monotonic() < deadline:
        last = _get_pod_quiet(lab, name)
        if last:
            status = last.get("status", {})
            containers = status.get("containerStatuses", [])
            waiting = {c.get("state", {}).get("waiting", {}).get("reason") for c in containers}
            if denied and waiting & expected:
                return last
            if not denied and (status.get("phase") in {"Succeeded", "Failed"}):
                return last
        time.sleep(1)
    return last


def _node_has_digest(lab, node, digest):
    result = _quiet(["docker", "exec", node, "crictl", "images", "-o", "json"],
                    env=lab.env, timeout=20)
    try:
        inventory = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("CRI image inventory was not JSON") from error
    for image in inventory.get("images", []):
        if digest in image.get("repoDigests", []) or digest in image.get("repoTags", []):
            return True
        if any(isinstance(value, str) and value.endswith("@" + digest)
               for value in image.get("repoDigests", [])):
            return True
    return False


def _node_has_private_reference(lab, node, image, digest):
    result = _quiet(["docker", "exec", node, "crictl", "inspecti", image],
                    env=lab.env, timeout=20, allow_failure=True)
    if result.returncode:
        return False
    try:
        status = json.loads(result.stdout).get("status", {})
    except json.JSONDecodeError as error:
        raise RuntimeError("CRI image inspection was not JSON") from error
    return image in status.get("repoDigests", []) and image.endswith("@" + digest)


def _create_pull_secret(lab, name, path):
    result = lab.kubectl(
        "create", "secret", "generic", name, "--type=kubernetes.io/dockerconfigjson",
        "--from-file=.dockerconfigjson=" + str(path), timeout=25,
    )
    return result.returncode == 0 and result.stdout.strip() == f"secret/{name} created"


def run_private_pull_checks(lab):
    """Prove wrong credentials fail and correct Secret credentials pull exact digest."""
    registry = f"saf-private-{lab.cluster}"
    node = f"{lab.cluster}-control-plane"
    network = f"{lab.cluster}-pull-net"
    tmp = Path(tempfile.mkdtemp(prefix="saf-0601-022-pull-"))
    os.chmod(tmp, 0o700)
    network_created = registry_started = False
    cleanup_failed = False
    try:
        if lab.command("docker", "container", "inspect", registry,
                       allow_failure=True).returncode == 0:
            lab.block("Generated private-pull container name already exists")
        for image in (REGISTRY_IMAGE, SKOPEO_IMAGE, "docker.io/library/busybox:1.37.0@sha256:"
                      "a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"):
            lab.command("docker", "image", "inspect", "--format", "{{.Id}}", image)

        if lab.command("docker", "network", "inspect", network, allow_failure=True).returncode == 0:
            lab.block("Generated private-pull Docker network already exists")
        network_created = True
        lab.command("docker", "network", "create", network)
        lab.command("docker", "network", "connect", network, node)

        username = "saf-pull-" + secrets.token_hex(6)
        password = secrets.token_urlsafe(32)
        wrong_password = secrets.token_urlsafe(32)
        auth_result = _quiet(["htpasswd", "-B", "-n", "-i", username], env=lab.env,
                             input_text=password + "\n", timeout=15)
        htpasswd = tmp / "htpasswd"
        htpasswd.write_text(auth_result.stdout, encoding="utf-8")
        htpasswd.chmod(0o600)

        alias = "saf-pull-reg-" + uuid.uuid4().hex[:10]
        registry_started = True
        lab.command(
            "docker", "run", "--detach", "--rm", "--name", registry,
            "--network", network, "--network-alias", alias,
            "--publish", "127.0.0.1::5000",
            "--env", "REGISTRY_LOG_ACCESSLOG_DISABLED=false",
            "--env", "REGISTRY_AUTH=htpasswd",
            "--env", "REGISTRY_AUTH_HTPASSWD_REALM=saf-0601-022",
            "--env", "REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd",
            "--volume", f"{htpasswd}:/auth/htpasswd:ro", REGISTRY_IMAGE,
        )
        port_rows = lab.command("docker", "port", registry, "5000/tcp").stdout.strip().splitlines()
        if len(port_rows) != 1:
            lab.block("owned registry has an unexpected published endpoint")
        match = re.fullmatch(r"127\.0\.0\.1:(\d+)", port_rows[0])
        if not match:
            lab.block("owned registry did not bind exclusively to IPv4 loopback")
        _wait_registry(int(match.group(1)))

        hosts_dir = tmp / "certs.d" / f"{alias}:5000"
        hosts_dir.mkdir(parents=True)
        hosts = hosts_dir / "hosts.toml"
        hosts.write_text(f'[host."http://{alias}:5000"]\ncapabilities = ["pull", "resolve"]\n',
                         encoding="utf-8")
        settings = f"/etc/containerd/certs.d/{alias}:5000"
        lab.command("docker", "exec", "--user", "0", node, "mkdir", "-p", settings)
        lab.command("docker", "cp", str(hosts), f"{node}:{settings}/hosts.toml")

        seed = tmp / "seed"
        seed.mkdir(mode=0o700)
        auth = base64.b64encode(f"{username}:{password}".encode()).decode()
        authfile = seed / "auth.json"
        authfile.write_text(json.dumps({"auths": {f"{alias}:5000": {"auth": auth}}}),
                            encoding="utf-8")
        authfile.chmod(0o600)
        archive = seed / "fixture.tar"
        busybox = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"
        _quiet(["docker", "image", "save", "--output", str(archive), busybox],
               env=lab.env, timeout=60)
        repo = "saf-fixture/0601-022/busybox"
        digest_file = seed / "digest"
        _quiet([
            "docker", "run", "--rm", "--network", network, "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--volume", f"{seed}:/fixture", SKOPEO_IMAGE,
            "copy", "--format", "oci", "--authfile", "/fixture/auth.json", "--dest-tls-verify=false",
            "--digestfile", "/fixture/digest", "docker-archive:/fixture/fixture.tar",
            f"docker://{alias}:5000/{repo}:owned",
        ], env=lab.env, timeout=120)
        digest = digest_file.read_text(encoding="utf-8").strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            lab.block("owned image push did not return an immutable digest")
        image = f"{alias}:5000/{repo}@{digest}"

        wrong_config = {"auths": {f"{alias}:5000": {
            "username": username, "password": wrong_password,
            "auth": base64.b64encode(f"{username}:{wrong_password}".encode()).decode(),
        }}}
        good_config = {"auths": {f"{alias}:5000": {
            "username": username, "password": password,
            "auth": base64.b64encode(f"{username}:{password}".encode()).decode(),
        }}}
        wrong_file, good_file = tmp / "wrong-config.json", tmp / "good-config.json"
        wrong_file.write_text(json.dumps(wrong_config), encoding="utf-8")
        good_file.write_text(json.dumps(good_config), encoding="utf-8")
        wrong_file.chmod(0o600)
        good_file.chmod(0o600)
        del password, wrong_password, auth, authfile, wrong_config, good_config
        wrong_secret, good_secret = "fixture-wrong-private-pull", "fixture-good-private-pull"
        if not _create_pull_secret(lab, wrong_secret, wrong_file):
            lab.block("wrong-credential fixture Secret was not admitted")
        if not _create_pull_secret(lab, good_secret, good_file):
            lab.block("correct-credential fixture Secret was not admitted")

        if _node_has_digest(lab, node, digest):
            lab.block("Unique private fixture digest unexpectedly exists in the node cache")

        def registry_log():
            return _quiet(["docker", "logs", registry], env=lab.env, timeout=15).stdout

        before_denied = _registry_records(registry_log())
        denied_name = "private-pull-wrong-credential"
        lab.create(_private_image_pod(denied_name, image, wrong_secret))
        denied_pod = _wait_private_pod(lab, denied_name, denied=True, timeout=60) or {}
        statuses = denied_pod.get("status", {}).get("containerStatuses", [])
        waiting = {item.get("state", {}).get("waiting", {}).get("reason") for item in statuses}
        started = any(item.get("containerID") or item.get("state", {}).get("running")
                      or item.get("state", {}).get("terminated") for item in statuses)
        denied_log = _registry_records(registry_log())
        denied_delta = _record_delta(before_denied, denied_log)
        manifest_path = f"/v2/{repo}/manifests/{digest}"
        registry_denial = any(method in {"HEAD", "GET"} and uri in {"/v2/", manifest_path} and status == 401
                              for method, uri, status in denied_delta)
        credential_error = any(
            image in message and re.search(r"(?i)\b401\b|unauthorized|authentication required", message)
            for item in statuses for message in [item.get("state", {}).get("waiting", {}).get("message", "")]
        )
        digest_cached = _node_has_digest(lab, node, digest)
        denial_observed = bool(waiting & {"ErrImagePull", "ImagePullBackOff"})
        lab.check("red", "The wrong same-namespace pull credential is refused by the owned registry",
                  denial_observed and not started and registry_denial and credential_error and not digest_cached,
                  {"pod_refused": denial_observed, "no_container_started": not started,
                   "owned_registry_401_observed": registry_denial, "exact_image_credential_error": credential_error,
                   "digest_not_cached": not digest_cached})

        lab.kubectl("delete", "pod", denied_name, "--wait=true", "--timeout=45s")
        before_allowed = _registry_records(registry_log())
        allowed_name = "private-pull-correct-credential"
        lab.create(_private_image_pod(allowed_name, image, good_secret))
        allowed_pod = _wait_private_pod(lab, allowed_name, timeout=90) or {}
        allowed_status = (allowed_pod.get("status", {}).get("containerStatuses") or [{}])[0]
        phase = allowed_pod.get("status", {}).get("phase")
        output = _quiet([
            "kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
            "--namespace", "saf-test", "--request-timeout=15s", "logs", allowed_name,
        ], env=lab.env, timeout=20, allow_failure=True)
        log_delta = _record_delta(before_allowed, _registry_records(registry_log()))
        manifest_200 = any(method == "GET" and uri == manifest_path and status == 200
                           for method, uri, status in log_delta)
        # CRI imageID may be the config digest; require the exact registry repoDigest.
        exact_repo_digest = _node_has_private_reference(lab, node, image, digest)
        good_pull = (phase == "Succeeded" and output.returncode == 0
                     and output.stdout.strip() == "private-pull-ok"
                     and manifest_200 and exact_repo_digest and not allowed_status.get("error"))
        lab.check("positive", "The correct same-namespace Secret authorizes an exact private-image pull",
                  good_pull,
                  {"pod_succeeded": phase == "Succeeded", "command_succeeded": output.returncode == 0
                   and output.stdout.strip() == "private-pull-ok", "manifest_request_authorized": manifest_200,
                   "exact_digest_observed": exact_repo_digest})
    except RuntimeError as error:
        lab.block(str(error))
    finally:
        cleanups = []
        if registry_started:
            cleanups.append(("container", ["docker", "rm", "-f", registry],
                             ["docker", "container", "inspect", registry]))
        if network_created:
            # The owned Kind node stays live until the enclosing runner cleans up.
            try:
                _quiet(["docker", "network", "disconnect", network, node], env=lab.env,
                       timeout=20, allow_failure=True)
            except RuntimeError:
                cleanup_failed = True
            cleanups.append(("network", ["docker", "network", "rm", network],
                             ["docker", "network", "inspect", network]))
        for _kind, remove, inspect in cleanups:
            try:
                _quiet(remove, env=lab.env, timeout=20, allow_failure=True)
                remaining = _quiet(inspect, env=lab.env, timeout=20, allow_failure=True)
                cleanup_failed = cleanup_failed or remaining.returncode == 0
            except RuntimeError:
                cleanup_failed = True
        shutil.rmtree(tmp, ignore_errors=True)
        if cleanup_failed:
            lab.block("Owned private-pull registry or network cleanup did not complete")


def run(lab):
    evaluate_examples(lab)
    lab.kubectl("create", "serviceaccount", ACCOUNT)
    body = pod("fixture-pull-reference", [container("public-probe", command=["true"])],
               serviceAccountName=ACCOUNT, automountServiceAccountToken=False)
    baseline = lab.create(body, dry_run=True)["spec"]
    lab.check("red", "The Pod has no injected pull reference before linking the ServiceAccount",
              not baseline.get("imagePullSecrets"), {"pull_references": baseline.get("imagePullSecrets", [])})

    create_empty_pull_secret(lab)
    patch = json.dumps({"imagePullSecrets": [{"name": SECRET}]})
    lab.kubectl("patch", "serviceaccount", ACCOUNT, "--type=merge", "-p", patch)
    deadline = time.monotonic() + 20
    expected = [{"name": SECRET}]
    observed = []
    while time.monotonic() < deadline:
        observed = lab.create(body, dry_run=True)["spec"].get("imagePullSecrets", [])
        if observed == expected:
            break
        time.sleep(0.5)
    lab.check("green", "Kubernetes admission injects the exact same-namespace Secret name",
              observed == expected, {"pull_references": observed})

    admitted = lab.create(body)
    lab.kubectl("wait", "pod/fixture-pull-reference", "--for=jsonpath={.status.phase}=Succeeded",
                "--timeout=75s", timeout=85)
    references = admitted["spec"].get("imagePullSecrets", [])
    lab.check("positive", "The live public-image Pod carries only the expected name reference",
              references == expected, {"pull_references": references, "workload_succeeded": True})
    run_private_pull_checks(lab)
