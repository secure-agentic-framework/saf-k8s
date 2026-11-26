"""Verify capability admission, signed guest BPF identity, unattached load inventory, and a scoped guest attachment lifecycle."""

import base64
import hashlib
import json
from pathlib import Path
import tempfile

from fixtures import container, pod

SCOPE = "Verify capability admission, signed guest BPF identity, unattached load inventory, and a scoped guest attachment lifecycle."
HERE = Path(__file__).resolve().parent
SOURCE = hashlib.sha256((HERE / "Dockerfile").read_bytes()
                       + (HERE / "marker.c").read_bytes()
                       + (HERE / "attach_marker.c").read_bytes()).hexdigest()
TOOLS = "saf-lab-bpf-integrity:source-" + SOURCE[:24]
LABEL = "org.saf.fixture.bpf-source"
NAME = "fixture-bpf-integrity"


def image(lab):
    checked = lab.command("docker", "image", "inspect", TOOLS, allow_failure=True)
    if checked.returncode:
        lab.command("docker", "build", "-q", "-t", TOOLS, "--label", f"{LABEL}={SOURCE}",
                    "-f", str(HERE / "Dockerfile"), str(HERE), timeout=420)
        checked = lab.command("docker", "image", "inspect", TOOLS)
    record, = json.loads(checked.stdout)
    if record["Config"]["Labels"].get(LABEL) != SOURCE:
        lab.block("The local guest fixture image does not match the tested build recipe")
    return record["Id"]


def independent_marker_trust(lab, image_id):
    """Sign only the exact harmless marker extracted from the verified local image.

    The ephemeral private key is host-side temporary state. Only the public key,
    detached signature and expected digest are returned for a read-only ConfigMap.
    """
    with tempfile.TemporaryDirectory(prefix="saf-0205-005-marker-") as scratch:
        scratch = Path(scratch)
        scratch.chmod(0o700)
        marker = scratch / "marker.o"
        attachment = scratch / "attach_marker.o"
        key = scratch / "ephemeral-signing-key.pem"
        public = scratch / "ephemeral-signing-key.pub"
        signature = scratch / "marker.sig"
        attachment_signature = scratch / "attach_marker.sig"
        export = f"{lab.cluster}-marker-export"
        lab.command("docker", "create", "--name", export, image_id)
        try:
            lab.command("docker", "cp", f"{export}:/fixture/marker.o", str(marker))
            lab.command("docker", "cp", f"{export}:/fixture/attach_marker.o", str(attachment))
        finally:
            lab.command("docker", "rm", "-f", export, allow_failure=True)
        lab.command("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
                    "ec_paramgen_curve:P-256", "-out", str(key))
        lab.command("openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public))
        lab.command("openssl", "dgst", "-sha256", "-sign", str(key), "-out", str(signature), str(marker))
        lab.command("openssl", "dgst", "-sha256", "-sign", str(key),
                    "-out", str(attachment_signature), str(attachment))
        marker_bytes = marker.read_bytes()
        attachment_bytes = attachment.read_bytes()
        public_bytes = public.read_text()
        signature_b64 = base64.b64encode(signature.read_bytes()).decode("ascii")
        attachment_signature_b64 = base64.b64encode(attachment_signature.read_bytes()).decode("ascii")
        digest = hashlib.sha256(marker_bytes).hexdigest()
        attachment_digest = hashlib.sha256(attachment_bytes).hexdigest()
    return ({"anchor.pem": public_bytes, "marker.sig.b64": signature_b64,
             "approved.sha256": digest, "attach.sig.b64": attachment_signature_b64,
             "attach.sha256": attachment_digest}, digest, attachment_digest,
            hashlib.sha256(public_bytes.encode()).hexdigest())


def capability_request(capability, placement):
    context = {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"], "add": [capability]},
               "runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}}
    marker = container("marker", securityContext=context)
    if placement == "init":
        ordinary = dict(context, capabilities={"drop": ["ALL"]})
        return pod("fixture-capability-check", [container("worker", securityContext=ordinary)],
                   initContainers=[marker], automountServiceAccountToken=False)
    return pod("fixture-capability-check", [marker], automountServiceAccountToken=False)


def run(lab):
    shapes = [(cap, placement) for cap in ("BPF", "SYS_ADMIN") for placement in ("ordinary", "init")]
    baseline = {placement + "_" + cap: lab.create(capability_request(cap, placement), dry_run=True,
                                                  allow_failure=True).returncode == 0
                for cap, placement in shapes}
    lab.check("red", "Unrestricted admission accepts the inert capability requests as dry-runs",
              all(baseline.values()), {"baseline_dry_run_accepted": baseline})
    lab.kubectl("label", "namespace", "saf-test", "pod-security.kubernetes.io/enforce=restricted")
    denied = {}
    admission_response = {}
    for cap, placement in shapes:
        request = lab.create(capability_request(cap, placement), dry_run=True, allow_failure=True)
        key = placement + "_" + cap
        admission_response[key] = request.stderr.strip()
        denied[key] = request.returncode != 0 and "capabilities.add" in request.stderr and cap in request.stderr
    expected_image = image(lab)
    trust_data, expected_marker_digest, expected_attachment_digest, trust_anchor_digest = independent_marker_trust(
        lab, expected_image)
    lab.command("kind", "load", "docker-image", TOOLS, "--name", lab.cluster, timeout=210)
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME},
                "immutable": True, "data": {"boot.sh": (HERE / "integrity-fixture.sh").read_text()}})
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": NAME + "-trust"},
                "immutable": True, "data": trust_data})
    unit = {"name": "guest", "image": TOOLS, "imagePullPolicy": "Never",
            "command": ["sh", "/test/boot.sh"],
            "volumeMounts": [{"name": "fixture", "mountPath": "/test", "readOnly": True},
                             {"name": "trust", "mountPath": "/trust", "readOnly": True},
                             {"name": "temporary", "mountPath": "/tmp"}],
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "200m", "memory": "160Mi"},
                          "limits": {"cpu": "1800m", "memory": "768Mi"}}}
    lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": NAME},
                "spec": {"backoffLimit": 0, "template": {"spec": {
                    "restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [unit], "volumes": [
                        {"name": "fixture", "configMap": {"name": NAME}},
                        {"name": "trust", "configMap": {"name": NAME + "-trust"}},
                        {"name": "temporary", "emptyDir": {}}],
                }}}})
    completion = lab.kubectl("wait", "--for=condition=Complete", "job/" + NAME,
                             "--timeout=135s", timeout=145, allow_failure=True)
    logs = lab.kubectl("logs", "job/" + NAME, allow_failure=True)
    if completion.returncode or logs.returncode:
        lab.block("The isolated BPF fixture did not complete; inspect its owned Job result")
    results = set(logs.stdout.splitlines())
    refused = ("modified_object_rejected_before_load" in results
               and "approved_object_signature_verified" in results)
    lab.check("green", "Restricted admission refuses both capability requests and the fixture verifier rejects changed bytes",
              all(denied.values()) and refused, {"governed_capabilities_denied": denied, "changed_artifact_rejected": refused})
    report = dict(line.split(": ", 1) for line in logs.stdout.splitlines() if line.startswith("SAF-"))
    restricted = (int(report["SAF-WORKLOAD-UID"]) == 65534 and int(report["SAF-WORKLOAD-CAPABILITIES"], 16) == 0)
    lab.check("positive", "The ordinary live Job runs as its non-root UID with no effective capabilities",
              restricted, {"non_root_zero_capabilities": restricted})
    matched_digest = (report["SAF-GUEST-DIGEST"] == report["SAF-APPROVED-DIGEST"]
                      == expected_marker_digest
                      and report["SAF-APPROVED-TRUST-ANCHOR"] == trust_anchor_digest
                      and report["SAF-APPROVED-DIGEST"] != report["SAF-ALTERED-DIGEST"])
    lab.check("green", "The guest verifies the same approved object digest after altered bytes were rejected",
              matched_digest, {"identical_approved_bytes": matched_digest})
    attachment = json.loads(report["SAF-BPF-ATTACHMENT"])
    attached_count = attachment.get("counter_after_attached_read")
    hook_invoked = type(attached_count) is int and attached_count > 0
    count_stable_after_detach = attachment.get("counter_after_detached_read") == attached_count
    attachment_passed = (
        "approved_attachment_signature_verified" in results
        and attachment.get("signature_verified") is True
        and attachment.get("approved_sha256") == expected_attachment_digest
        and attachment.get("program_type") == "cgroup_sysctl"
        and attachment.get("cgroup_path") == "/sys/fs/cgroup/saf-0205-005"
        and attachment.get("attached_program_matches") is True
        and attachment.get("counter_before") == 0
        and hook_invoked
        and attachment.get("detached_program_absent") is True
        and count_stable_after_detach
        and attachment.get("cgroup_removed") is True)
    lab.check("positive", "The separately signed guest program attaches to one owned cgroup, observes one benign sysctl read, then detaches",
              attachment_passed, {
                  "approved_attachment_sha256": expected_attachment_digest,
                  "guest_scope_exact": attachment.get("cgroup_path") == "/sys/fs/cgroup/saf-0205-005",
                  "attached_program_matches": attachment.get("attached_program_matches") is True,
                  "zero_before_attach": attachment.get("counter_before") == 0,
                  "hook_invoked_in_owned_cgroup": hook_invoked,
                  "detached_program_absent": attachment.get("detached_program_absent") is True,
                  "count_stable_after_detach": count_stable_after_detach,
                  "owned_cgroup_removed": attachment.get("cgroup_removed") is True})
    before, loaded, active, after = (json.loads(report["SAF-BPF-" + stage])
                                      for stage in ("BEFORE", "LOADED", "ACTIVE", "AFTER"))
    program, = loaded if isinstance(loaded, list) else [loaded]
    supports_load = ("approved_object_verifies" in results and report["SAF-BPF-LOAD"] == "succeeded"
                     and program["type"] == "socket_filter" and program["name"] == "saf_marker"
                     and int(report["SAF-GUEST-LOADER-UID"]) == 0 and bool(program["tag"]))
    tracked = not any(item.get("name") == "saf_marker" for item in before + after) and any(
        item["id"] == program["id"] and item["tag"] == program["tag"] for item in active)
    lab.check("positive", "An accepted unattached guest load has an inventory ID and disappears after unpinning",
              supports_load and tracked, {"accepted_load_reconciled_with_inventory": supports_load and tracked})
    refused_load = json.loads(report["SAF-BPF-REFUSED-LOAD"])
    if refused_load.get("result") == "blocked":
        lab.block("The guest cannot exercise the refused-load comparator: "
                  + str(refused_load.get("reason", "unknown guest prerequisite")))
    identity_verified = (refused_load.get("identity_uid_gid_verified") is True
                         and refused_load.get("uid") == 65534 and refused_load.get("gid") == 65534)
    refusal_stage_is_load = refused_load.get("rejection_stage") in {"object_program_load", "libbpf_prog_load_probe"}
    refused_load_passed = (
        refused_load.get("result") == "load_eprem"
        and identity_verified
        and refused_load.get("cap_eff_zero") is True
        and refused_load.get("setting") == "2"
        and refused_load.get("approved_sha256") == expected_marker_digest
        and refused_load.get("identity_and_digest_verified") is True
        and refused_load.get("writable_pin_parent_verified") is True
        and refused_load.get("load_attempted") is True
        and refused_load.get("load_stage_eprem") is True and refusal_stage_is_load
        and refused_load.get("pin_absent") is True)
    lab.check("green", "A no-capability guest cannot load the approved signed marker because its BPF load syscall is refused",
              refused_load_passed, {
                  "non_root_identity": identity_verified,
                  "zero_effective_caps": refused_load.get("cap_eff_zero") is True,
                  "unprivileged_bpf_disabled_two": refused_load.get("setting") == "2",
                  "same_approved_marker_digest": refused_load.get("approved_sha256") == expected_marker_digest,
                  "writable_pin_parent_preflight": refused_load.get("writable_pin_parent_verified") is True,
                  "bpf_load_stage_eprem": refused_load.get("load_attempted") is True and refused_load.get("load_stage_eprem") is True,
                  "refusal_at_load_or_library_load_probe": refusal_stage_is_load,
                  "no_pin_created": refused_load.get("pin_absent") is True})
    observations = {"unrestricted_dry_run": baseline, "restricted_dry_run_denied": denied,
                    "admission_response": admission_response, "changed_artifact_rejected": refused,
                    "workload_process": {"uid": int(report["SAF-WORKLOAD-UID"]),
                                         "cap_eff": report["SAF-WORKLOAD-CAPABILITIES"]},
                    "guest": {"kernel": report["SAF-GUEST-KERNEL"], "loader_uid": int(report["SAF-GUEST-LOADER-UID"]),
                              "unprivileged_bpf_setting": report["SAF-UNPRIVILEGED-BPF"]},
                    "artifact": {"approved_sha256": report["SAF-APPROVED-DIGEST"],
                                 "changed_sha256": report["SAF-ALTERED-DIGEST"],
                                 "guest_sha256": report["SAF-GUEST-DIGEST"],
                                 "anchor_sha256": trust_anchor_digest,
                                 "attachment_sha256": report["SAF-ATTACH-APPROVED-DIGEST"],
                                 "host_expected_marker_sha256": expected_marker_digest,
                                 "independent_signature_verified": "approved_object_signature_verified" in results},
                    "load_and_inventory": {"loader_result": report["SAF-BPF-LOAD"], "program": program,
                                           "before": before, "active": active, "after_unpin": after},
                    "attachment": attachment,
                    "refused_load": refused_load}
    rows = json.loads(lab.kubectl("get", "pods", "-l", f"job-name={NAME}", "-o", "json").stdout)["items"]
    worker, = rows
    status, = worker["status"]["containerStatuses"]
    (lab.evidence / "bpf-integrity-observations.json").write_text(json.dumps({
        "build_image": expected_image, "running_image": status["imageID"],
        **observations,
    }, indent=2) + "\n")
