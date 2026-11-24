"""Collect and verify an owned incident fixture through an authorized read path."""

import base64
from datetime import datetime, timezone
import hashlib
import json
import time

from fixtures import container, pod, ready

SCOPE = "Capture an owned volatile file and bounded process state, verify a signed custody handoff, and observe workload continuity."
NAME = "fixture-incident-workload"
OTHER = "fixture-unrelated-workload"
COLLECTOR = "fixture-incident-collector"
CUSTODIAN = "fixture-evidence-custodian"
BUNDLE = "fixture-signed-evidence"
STATE = "/state/owned-public.txt"
MARKER = "Fixture incident evidence only"
NAMESPACE = "saf-test"


def create_workload(lab, name):
    lab.create(pod(
        name, [container("target",
            command=["sh", "-ec", 'printf "%s\\n" "$1" > /state/owned-public.txt; exec sleep 180', "sh", MARKER],
            volumeMounts=[{"name": "state", "mountPath": "/state"}],
            securityContext={"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                             "capabilities": {"drop": ["ALL"]}},
            resources={"requests": {"cpu": "5m", "memory": "8Mi"}, "limits": {"cpu": "50m", "memory": "24Mi"}},
        )],
        automountServiceAccountToken=False,
        securityContext={"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534,
                         "seccompProfile": {"type": "RuntimeDefault"}},
        volumes=[{"name": "state", "emptyDir": {}}],
    ))


def workload_state(lab, name):
    row = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
    unit, = row["status"]["containerStatuses"]
    return {"uid": row["metadata"]["uid"], "node": row["spec"]["nodeName"],
            "container_id": unit["containerID"], "restart_count": unit["restartCount"]}


def collect(lab, name):
    return lab.kubectl(f"--as={COLLECTOR}", "exec", f"pod/{name}", "--", "cat", STATE, allow_failure=True)


def grant(lab):
    base = {"apiVersion": "rbac.authorization.k8s.io/v1", "metadata": {"name": COLLECTOR}}
    lab.create({**base, "kind": "Role",
                "rules": [{"apiGroups": [""], "resources": ["pods"],
                           "resourceNames": [NAME], "verbs": ["get"]},
                          {"apiGroups": [""], "resources": ["pods/exec"],
                           "resourceNames": [NAME], "verbs": ["get", "create"]}]})
    lab.create({**base, "kind": "RoleBinding",
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": COLLECTOR},
                "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": COLLECTOR}]})


def denied(result):
    return result.returncode != 0 and "forbidden" in result.stderr.lower()


def process_summary(lab):
    return lab.kubectl(f"--as={COLLECTOR}", "exec", f"pod/{NAME}", "--",
                       "awk", "/^(Name|Pid|Uid):[ \t]/", "/proc/1/status").stdout


def handoff(lab, files, source):
    keys = lab.kubeconfig.parent / "fixture-handoff"
    keys.mkdir(mode=0o700)
    key, public = keys / "issuer.key", keys / "issuer.pub"
    manifest, signature = keys / "manifest.json", keys / "manifest.sig"
    checksums = {name: hashlib.sha256(value).hexdigest() for name, value in files.items()}
    metadata = {"collector": COLLECTOR, "custodian": CUSTODIAN, "source": source, "files": checksums}
    manifest.write_text(json.dumps(metadata, sort_keys=True))
    lab.command("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key))
    lab.command("openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public))
    lab.command("openssl", "dgst", "-sha256", "-sign", str(key), "-out", str(signature), str(manifest))
    data = {name: value.decode() for name, value in files.items()}
    data.update({"manifest.json": manifest.read_text(), "signature.txt": base64.b64encode(signature.read_bytes()).decode()})
    stored = lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": BUNDLE},
                         "immutable": True, "data": data})
    anonymous = lab.kubectl(f"--as={CUSTODIAN}", "get", "configmap", BUNDLE, "-o", "name", allow_failure=True)
    rbac = {"apiVersion": "rbac.authorization.k8s.io/v1", "metadata": {"name": CUSTODIAN}}
    lab.create({**rbac, "kind": "Role", "rules": [
        {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [BUNDLE], "verbs": ["get"]},
    ]})
    lab.create({**rbac, "kind": "RoleBinding",
                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": CUSTODIAN},
                "subjects": [{"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": CUSTODIAN}]})
    receipt = json.loads(lab.kubectl(f"--as={CUSTODIAN}", "get", "configmap", BUNDLE, "-o", "json").stdout)
    verified_manifest, verified_signature = keys / "received.json", keys / "received.sig"
    verified_manifest.write_text(receipt["data"]["manifest.json"])
    verified_signature.write_bytes(base64.b64decode(receipt["data"]["signature.txt"], validate=True))
    verification = ("openssl", "dgst", "-sha256", "-verify", str(public), "-signature", str(verified_signature))
    authentic = lab.command(*verification, str(verified_manifest), allow_failure=True).returncode == 0
    recorded = json.loads(verified_manifest.read_text())
    copied = {name: hashlib.sha256(receipt["data"][name].encode()).hexdigest() for name in files}
    reproduced = stored["metadata"]["uid"] == receipt["metadata"]["uid"] and recorded == metadata and copied == checksums
    lab.check("positive", "The separately authorized custodian reads and verifies the exact signed manifest and specimen bytes",
              denied(anonymous) and authentic and reproduced,
              {"unassigned_custodian_denied": denied(anonymous), "signed_handoff_verified": authentic and reproduced})

    altered = keys / "altered.json"
    altered.write_text(json.dumps({**recorded, "collector": "modified-fixture-collector"}, sort_keys=True))
    bad_signature = lab.command(*verification, str(altered), allow_failure=True).returncode != 0
    patch = json.dumps({"data": {next(iter(files)): "modified public evidence"}})
    read_only = lab.kubectl(f"--as={CUSTODIAN}", "patch", "configmap", BUNDLE, "--type=merge", "-p", patch, allow_failure=True)
    immutable = lab.kubectl("patch", "configmap", BUNDLE, "--type=merge", "-p", patch, allow_failure=True)
    unchanged = json.loads(lab.kubectl("get", "configmap", BUNDLE, "-o", "json").stdout)["data"] == receipt["data"]
    locked = immutable.returncode != 0 and "immutable" in immutable.stderr.lower() and unchanged
    lab.check("green", "The receiver rejects a modified manifest and both RBAC and API immutability preserve the stored fixture data",
              bad_signature and denied(read_only) and locked,
              {"modified_manifest_rejected": bad_signature, "custodian_write_denied": denied(read_only),
               "stored_data_unchanged": locked})
    return {"manifest": recorded, "verified_signature": authentic, "modified_manifest_rejected": bad_signature,
            "signed_manifest": receipt["data"]["manifest.json"], "signature": receipt["data"]["signature.txt"],
            "verification_key": public.read_text(),
            "receipt_uid": receipt["metadata"]["uid"], "receiver": CUSTODIAN,
            "captured_file_digests_match": reproduced, "immutable_data_retained": locked}


def run(lab):
    lab.kubectl("label", "namespace", NAMESPACE, "pod-security.kubernetes.io/enforce=restricted")
    for name in (NAME, OTHER):
        create_workload(lab, name)
        ready(lab, name)
    before = workload_state(lab, NAME)
    began = datetime.now(timezone.utc).isoformat()
    restricted = denied(collect(lab, NAME))
    lab.check("red", "The unassigned fixture collector is forbidden from collecting owned state",
              restricted, {"unassigned_collector_denied": restricted})
    grant(lab)
    deadline = time.monotonic() + 12
    allowed = collect(lab, NAME)
    while allowed.returncode and time.monotonic() < deadline:
        time.sleep(0.4)
        allowed = collect(lab, NAME)
    outside = denied(collect(lab, OTHER))
    expected = (MARKER + "\n").encode()
    capture = allowed.stdout.encode()
    digest = hashlib.sha256(capture).hexdigest()
    verified = allowed.returncode == 0 and digest == hashlib.sha256(expected).hexdigest()
    lab.check("green", "The assigned collector verifies the exact evidence bytes and is denied on an unrelated fixture",
              verified and outside, {"exact_capture_verified": verified, "unrelated_workload_denied": outside})
    state = process_summary(lab).encode()
    fields = dict(line.split(":", 1) for line in state.decode().splitlines())
    expected_process = (fields["Name"].strip() == "sleep" and fields["Pid"].strip() == "1"
                        and fields["Uid"].split() == ["65534"] * 4)
    lab.check("positive", "The scoped collection records the owned workload's actual PID, name and UID",
              expected_process, {"limited_process_state_matches_fixture": expected_process})
    after = workload_state(lab, NAME)
    collected = datetime.now(timezone.utc).isoformat()
    again = collect(lab, NAME)
    continuous = before == after and before["restart_count"] == 0 and again.returncode == 0 and again.stdout.encode() == capture
    lab.check("positive", "The target remains the same running container and returns the same owned marker",
              continuous, {"same_running_container_and_marker": continuous})
    files = {"captured-public-marker.txt": capture, "captured-process-summary.txt": state}
    source = {"cluster": lab.cluster, "namespace": NAMESPACE, "object": NAME, "path": STATE,
              "capture_started": began, "capture_completed": collected, "workload": before}
    transfer = handoff(lab, files, source)
    for name, value in files.items():
        (lab.evidence / name).write_bytes(value)
    (lab.evidence / "forensic-custody-observations.json").write_text(json.dumps({
        "source": source, "workload_identity_after": after, "custody_handoff": transfer,
    }, indent=2) + "\n")
