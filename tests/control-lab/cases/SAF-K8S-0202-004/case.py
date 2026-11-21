"""Check namespace Pod Security Admission blocks runtime socket hostPath mounts."""
import json
from pathlib import Path
import time

from fixtures import BUSYBOX_IMAGE, container, pod

SCOPE = (
    "Local kind with the repository's pinned Kubernetes 1.36.1 node image. "
    "Checks namespace Pod Security Admission Baseline rejection of Pod hostPath "
    "volumes using inert, nonexistent socket and runtime-parent fixtures, plus "
    "admission and readiness of a benign Pod without hostPath, and a pinned "
    "daemonless Kaniko build with a synthetic build context and no runtime socket."
)
NAMESPACE = "saf-test"
LABEL = "pod-security.kubernetes.io/enforce"
VERSION_LABEL = "pod-security.kubernetes.io/enforce-version"


def compliant_workload():
    return pod("compliant-no-hostpath", [{
        "name": "probe", "image": BUSYBOX_IMAGE,
        "command": ["sh", "-c", "sleep 3600"],
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
            "runAsNonRoot": True,
            "runAsUser": 65534,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
    }])


KANIKO = ("ghcr.io/osscontainertools/kaniko:v1.28.5@sha256:"
          "738807f0e31daf07743f89260a95956dcc6ee4f62553f4f6344c990cabab8675")
PYTHON = ("docker.io/library/python:3.13.2-alpine@sha256:"
          "323a717dc4a010fee21e3f1aac738ee10bb485de4e7593ce242b36ee48d6b352")
INSPECT_BUILD = '''
import json
from pathlib import Path
import time
import re
import tarfile

with tarfile.open("/build-out/image.tar") as archive:
    manifest = json.load(archive.extractfile("manifest.json"))
    layers = manifest[0]["Layers"]
    assert len(layers) == 1
    with tarfile.open(fileobj=archive.extractfile(layers[0]), mode="r:*") as layer:
        content = layer.extractfile("fixture.txt").read().decode()
        assert content == "socket-free build fixture"
digest = Path("/build-out/digest").read_text().strip()
assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
assert not any(Path(path).is_socket() for path in (
    "/var/run/docker.sock", "/run/containerd/containerd.sock", "/var/run/crio/crio.sock",
))
print("Verified image payload and digest: " + digest)
'''


def build_without_socket(lab):
    lab.create({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "saf-daemonless-build-context"},
        "data": {"Dockerfile": "FROM scratch\nCOPY fixture.txt /fixture.txt\n",
                 "fixture.txt": "socket-free build fixture"},
    })
    security = {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                "runAsUser": 0, "runAsGroup": 65534,
                "seccompProfile": {"type": "RuntimeDefault"}}
    output = {"name": "out", "mountPath": "/build-out"}
    build = {"name": "build", "image": KANIKO, "command": ["/kaniko/executor"],
             "args": ["--context=dir:///build-input", "--dockerfile=/build-input/Dockerfile",
                      "--destination=example.invalid/saf/control:local", "--no-push",
                      "--no-push-cache", "--cache=false", "--tar-path=/build-out/image.tar",
                      "--digest-file=/build-out/digest"],
             "volumeMounts": [{"name": "input", "mountPath": "/build-input", "readOnly": True}, output],
             "securityContext": security}
    inspect = {"name": "inspect", "image": PYTHON, "command": ["python", "-c", INSPECT_BUILD],
               "volumeMounts": [{**output, "readOnly": True}], "securityContext": security}
    stage = container(
        "stage", command=["sh", "-c", "cp -L /source/Dockerfile /source/fixture.txt /staged"],
        securityContext=security,
        volumeMounts=[{"name": "source", "mountPath": "/source", "readOnly": True},
                      {"name": "input", "mountPath": "/staged"}],
    )
    resource = pod("daemonless-ci-build", [inspect], initContainers=[stage, build],
                   automountServiceAccountToken=False, securityContext={"fsGroup": 65534},
                   volumes=[{"name": "source", "configMap": {"name": "saf-daemonless-build-context"}},
                            {"name": "input", "emptyDir": {}}, {"name": "out", "emptyDir": {}}])
    rendered = lab.create(resource)
    host_paths = [volume["name"] for volume in rendered["spec"]["volumes"] if "hostPath" in volume]
    deadline = time.monotonic() + 120
    while True:
        current = json.loads(lab.kubectl("get", "pod/daemonless-ci-build", "-o", "json").stdout)
        phase = current["status"].get("phase")
        if phase in ("Failed", "Succeeded") or time.monotonic() >= deadline:
            break
        time.sleep(1)
    if phase != "Succeeded":
        for name in ("stage", "build", "inspect"):
            lab.kubectl("logs", "daemonless-ci-build", "-c", name, allow_failure=True)
        lab.block("The synthetic daemonless build did not reach Succeeded")
    proof = lab.kubectl("logs", "daemonless-ci-build", "-c", "inspect").stdout.strip()
    lab.check("positive", "Daemonless CI build without hostPath produces a verifiable image archive",
              not host_paths and proof.startswith("Verified image payload and digest: sha256:"), proof)


def run(lab):
    case_dir = Path(__file__).parent
    fixtures = json.loads((case_dir / "fixtures.json").read_text())
    # Prove both admission challenges reach the API before enforcement. Server
    # dry-run keeps the deliberately violating Pods from ever being created.
    for fixture in fixtures:
        before = lab.create(fixture, dry_run=True, allow_failure=True)
        lab.check("red", f"{fixture['metadata']['name']} is admitted before PSA enforcement",
                  before.returncode == 0, before.stderr.strip() or "server dry-run admitted")

    lab.kubectl("label", "namespace", NAMESPACE,
                f"{LABEL}=baseline", f"{VERSION_LABEL}=v1.36", "--overwrite")
    for fixture in fixtures:
        rejected = lab.create(fixture, dry_run=True, allow_failure=True)
        denied = (rejected.returncode != 0 and "(Forbidden)" in rejected.stderr
                  and "violates PodSecurity" in rejected.stderr
                  and "hostPath volumes" in rejected.stderr)
        lab.check("green", f"{fixture['metadata']['name']} is denied by PSA Baseline",
                  denied, rejected.stderr.strip() or "unexpected admission success")

    benign = compliant_workload()
    admitted = lab.create(benign, dry_run=True, allow_failure=True)
    lab.check("positive", "A benign no-hostPath Pod passes server admission dry-run",
              admitted.returncode == 0, admitted.stderr.strip() or "server dry-run admitted")
    lab.create(benign)
    lab.kubectl("wait", "--for=condition=Ready", "pod/compliant-no-hostpath",
                "--timeout=95s", timeout=105)
    lab.check("positive", "The benign no-hostPath Pod reaches Ready",
              True, "Pod/compliant-no-hostpath Ready")

    build_without_socket(lab)
