"""Verify native filesystem authorization for a public backup fixture."""

import json

SCOPE = "Actual Linux file access checks from isolated fixture identities in a disposable Kubernetes Pod."
IMAGE = "docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
POD = "fixture-backup-repository"
ROLES = {"writer": (1001, 2000), "restore": (1002, 2000), "unrelated": (1003, 3000)}
SETUP = """
from pathlib import Path
for name, mode, file_mode in (('baseline', 0o777, 0o666), ('reviewed', 0o750, 0o640)):
    directory = Path('/repo') / name
    directory.mkdir()
    path = directory / 'fixture-marker'
    path.write_text('fixture backup marker')
    path.chmod(file_mode)
    directory.chmod(mode)
"""
PROBE = """
import json
import sys
from pathlib import Path
direction, action = sys.argv[1:]
directory = Path('/repo') / direction
path = directory / 'fixture-marker'
try:
    if action == 'read':
        assert path.read_text() == 'fixture backup marker'
    elif action == 'list':
        assert path.name in {entry.name for entry in directory.iterdir()}
    elif action == 'write':
        with path.open('r+') as output:
            output.write('fixture backup marker')
    elif action == 'create':
        with (directory / 'fixture-new').open('x') as output:
            output.write('new fixture backup')
    elif action == 'delete':
        path.unlink()
    else:
        raise ValueError(action)
except PermissionError:
    print(json.dumps({'decision': 'denied'}))
else:
    print(json.dumps({'decision': 'allowed'}))
"""


def container(name, command, *, uid, gid):
    return {"name": name, "image": IMAGE, "command": command,
            "volumeMounts": [{"name": "repository", "mountPath": "/repo"}],
            "securityContext": {"runAsUser": uid, "runAsGroup": gid, "runAsNonRoot": True,
                                "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "5m", "memory": "12Mi"},
                          "limits": {"cpu": "100m", "memory": "48Mi"}}}


def observe(lab, role, directory, action):
    response = lab.kubectl("exec", "pod/" + POD, "-c", role, "--", "python", "-c", PROBE, directory, action)
    return json.loads(response.stdout)["decision"]


def run(lab):
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    writer_uid, writer_gid = ROLES["writer"]
    init = container("bootstrap", ["python", "-c", SETUP], uid=writer_uid, gid=writer_gid)
    probes = [container(role, ["python", "-c", "import time; time.sleep(180)"], uid=uid, gid=gid)
              for role, (uid, gid) in ROLES.items()]
    lab.create({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": POD}, "spec": {
        "restartPolicy": "Never", "automountServiceAccountToken": False,
        "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}, "supplementalGroupsPolicy": "Strict"},
        "initContainers": [init], "containers": probes, "volumes": [{"name": "repository", "emptyDir": {}}],
    }})
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + POD, "--timeout=75s", timeout=84)
    baseline = {"unrelated_read": observe(lab, "unrelated", "baseline", "read"),
                "restore_write": observe(lab, "restore", "baseline", "write")}
    lab.check("red", "The broadly permissioned baseline admits unrelated reads and restore-account writes",
              set(baseline.values()) == {"allowed"}, baseline)
    restricted = {"unrelated_read": observe(lab, "unrelated", "reviewed", "read"),
                  "unrelated_list": observe(lab, "unrelated", "reviewed", "list"),
                  "restore_write": observe(lab, "restore", "reviewed", "write"),
                  "restore_delete": observe(lab, "restore", "reviewed", "delete")}
    lab.check("green", "Native permissions deny unrelated reads and listings and keep restoration read-only",
              set(restricted.values()) == {"denied"}, restricted)
    intended = {"writer_create": observe(lab, "writer", "reviewed", "create"),
                "writer_write": observe(lab, "writer", "reviewed", "write"),
                "restore_read": observe(lab, "restore", "reviewed", "read")}
    lab.check("positive", "Only the intended local backup and restore paths remain usable",
              set(intended.values()) == {"allowed"}, intended)
    (lab.evidence / "backup-repository-permissions.json").write_text(json.dumps({
        "baseline": baseline, "reviewed": restricted, "intended": intended, "etcd_snapshot_used": False,
    }, indent=2) + "\n")
