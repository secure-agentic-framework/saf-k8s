"""Check runtime inventory policy using synthetic release evidence."""
from datetime import date, timedelta
import importlib.util
import json
from pathlib import Path
import re

from fixtures import BUSYBOX_IMAGE, pod
from lab import NODE_IMAGE


HERE = Path(__file__).resolve().parent
SCOPE = (
    "Reads Kubernetes v1.36 Node.status.nodeInfo.containerRuntimeVersion from every "
    "node created by this run and verifies the Docker node containers use the lab's "
    "digest-pinned kind image and checks the packaged containerd and runc versions. "
    "Retains synthetic applicability and SLA tests. Verifies a pinned signed containerd "
    "release tag and independently reviewed dated compatibility records. A dedicated worker "
    "runs the same non-root workload before and after a digest-verified daemon patch and "
    "again after restoring the original daemon. The adopter guide covers additional components "
    "and workload and provider applicability."
)


def load_json(name):
    return json.loads((HERE / name).read_text())


def version_tuple(value):
    match = re.fullmatch(r"(?:containerd://)?(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise ValueError(f"Expected a stable containerd semantic version, got {value!r}")
    return tuple(int(part) for part in match.groups())


def evaluate(policy, record, release, advisory):
    as_of = date.fromisoformat(policy["fixture_as_of"])
    supported_until = date.fromisoformat(record["vendor_support_until"])
    support_policy = policy["vendor_support_policy"]
    support_ok = (
        record["runtime"] == policy["runtime"]
        and record["vendor_support_status"] in support_policy["accepted_statuses"]
        and (not support_policy["require_as_of_on_or_before_support_until"]
             or as_of <= supported_until)
    )

    advisory_ok = (
        advisory["synthetic"] is True and release["synthetic"] is True
        and advisory["advisory_id"] == record["applicable_advisory_id"]
        and advisory["source_ref"] in policy["allowed_fixture_sources"]
        and advisory["affected_runtime"] == policy["runtime"]
        and release["runtime"] == policy["runtime"]
        and advisory["affected_versions"] == f'< {release["fixed_version"]}'
    )
    fixed = version_tuple(release["fixed_version"])
    installed = version_tuple(record["installed_version"])
    disclosed = date.fromisoformat(advisory["disclosed_on"])
    due = disclosed + timedelta(days=policy["security_patch_sla_days"])
    published = date.fromisoformat(release["published_on"])
    patched_at = (date.fromisoformat(record["patched_on"])
                  if record["patched_on"] else None)
    patch_ok = (
        advisory_ok
        and installed >= fixed
        and patched_at is not None
        and published <= patched_at <= min(due, as_of)
    )
    return {
        "vendor_support": support_ok,
        "patch_sla": patch_ok,
        "advisory_provenance": advisory_ok,
        "overall": support_ok and patch_ok and advisory_ok,
        "sla_due": due.isoformat(),
        "reasons": [
            name for name, passed in (
                ("vendor_support", support_ok),
                ("patch_sla", patch_ok),
                ("advisory_provenance", advisory_ok),
            ) if not passed
        ],
    }


def verify_fixture_records(lab):
    policy = load_json("fixture-policy.json")
    release = load_json("synthetic-release.json")
    advisory = load_json("synthetic-advisory.json")
    approved, outdated = load_json("synthetic-inventory.json")["records"]
    red = evaluate(policy, outdated, release, advisory)
    green = evaluate(policy, approved, release, advisory)
    lab.check(
        "red",
        "An overdue synthetic runtime inventory fails while support and advisory provenance remain independently valid",
        not red["overall"] and red["reasons"] == ["patch_sla"]
        and red["vendor_support"] and red["advisory_provenance"],
        {"result": red, "record": outdated["record_id"]},
    )
    lab.check(
        "green",
        "A synthetic inventory at the fixed release, patched inside its SLA, passes",
        green["overall"] and green["reasons"] == []
        and green["vendor_support"] and green["patch_sla"]
        and green["advisory_provenance"],
        {"result": green, "record": approved["record_id"]},
    )
    late = evaluate(policy, {**approved, "patched_on": "2026-11-17"}, release, advisory)
    expired = evaluate(policy, {**approved, "vendor_support_until": "2026-11-20"}, release, advisory)
    unknown = evaluate(policy, approved, release, {**advisory, "source_ref": "fixture://unknown"})
    lab.check(
        "green", "A fixed binary still fails the fixture policy when timing, support or provenance fails",
        late["reasons"] == ["patch_sla"] and expired["reasons"] == ["vendor_support"]
        and unknown["reasons"] == ["patch_sla", "advisory_provenance"],
        {"late": late["reasons"], "expired_support": expired["reasons"],
         "unknown_source": unknown["reasons"]},
    )


def verify_node_runtime_reporting(lab):
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    if not nodes:
        lab.block("The new kind cluster reported no nodes")
    observed = []
    for item in nodes:
        name = item["metadata"]["name"]
        runtime = item["status"]["nodeInfo"]["containerRuntimeVersion"]
        try:
            version_tuple(runtime)
        except ValueError as error:
            lab.block(f"Node {name} reported an unrecognized runtime: {error}")
        image = lab.command(
            "docker", "inspect", "--format", "{{.Config.Image}}", name
        ).stdout.strip()
        if not name.startswith(lab.cluster + "-") or image != NODE_IMAGE:
            lab.block("The observed node is not part of the pinned kind fixture")
        package = lab.command("docker", "exec", name, "containerd", "--version").stdout
        binary = re.search(r"\bv?(\d+\.\d+\.\d+)\b", package)
        runc = lab.command("docker", "exec", name, "runc", "--version").stdout
        runc_version = re.search(r"^runc version (\S+)", runc)
        observed.append({"node": name.removeprefix(lab.cluster + "-"),
                         "container_runtime_version": runtime, "node_image": image,
                         "runc_version": runc_version.group(1) if runc_version else None,
                         "cri_matches_containerd": bool(binary and runtime == "containerd://" + binary.group(1))})
    lab.check(
        "positive",
        "Every node reports the packaged containerd version and has an inventoried runc version",
        all(row["cri_matches_containerd"] and row["runc_version"] for row in observed),
        {"pinned_image": NODE_IMAGE, "nodes": observed},
    )
    return {item["metadata"]["name"] for item in nodes}


def schedule_compatible_fixture(lab, inventoried_nodes):
    name = "saf-runtime-compatible"
    workload = pod(name, [{
        "name": "check",
        "image": BUSYBOX_IMAGE,
        "imagePullPolicy": "IfNotPresent",
        "command": ["sh", "-c", "test \"$(id -u)\" = 65534 && printf 'fixture-ok\\n'"],
        "resources": {"requests": {"cpu": "10m", "memory": "8Mi"},
                      "limits": {"cpu": "50m", "memory": "16Mi"}},
        "securityContext": {"allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                            "runAsNonRoot": True, "runAsUser": 65534,
                            "seccompProfile": {"type": "RuntimeDefault"}},
    }], tolerations=[
        {"key": "node-role.kubernetes.io/control-plane", "operator": "Exists",
         "effect": "NoSchedule"},
        {"key": "node-role.kubernetes.io/master", "operator": "Exists",
         "effect": "NoSchedule"},
    ], nodeSelector={"kubernetes.io/hostname": f"{lab.cluster}-control-plane"})
    lab.create(workload)
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Succeeded",
                f"pod/{name}", "--timeout=95s", timeout=105)
    pod_state = json.loads(lab.kubectl("get", f"pod/{name}", "-o", "json").stdout)
    output = lab.kubectl("logs", name, "-c", "check").stdout.strip()
    node = pod_state["spec"].get("nodeName", "")
    lab.check(
        "positive",
        "A tiny non-root BusyBox fixture schedules on a reported node and completes",
        pod_state["status"]["phase"] == "Succeeded" and node in inventoried_nodes
        and output == "fixture-ok",
        {"phase": pod_state["status"]["phase"], "scheduled_node": node.removeprefix(lab.cluster + "-"),
         "output": output, "image": BUSYBOX_IMAGE},
    )



def sibling_module(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_release(lab):
    checker = sibling_module("verify_official_release")
    key = HERE / "containerd-maintainer-public.asc"
    tag = HERE / "official-containerd-v2.3.7.tag"
    payload, signature, _, _ = checker.parse_tag(tag.read_bytes())
    try:
        checker.verify_signature(key, payload + b"modified", signature)
    except checker.VerificationError as error:
        rejected_modified_tag = str(error) == "tag signature verification failed"
    else:
        rejected_modified_tag = False
    lab.check("red", "The pinned maintainer signature rejects changed release metadata",
              rejected_modified_tag, {"changed_signature_payload_rejected": rejected_modified_tag})

    verified = checker.verify(tag, key, HERE / "official-policy-facts.json", HERE / "live-observation.json")
    snapshot = verified["comparison"]
    historical, = snapshot["nodes"]
    canonical = (verified["result"] == "verified"
                 and verified["tag"] == "v2.3.7"
                 and snapshot["sla_days"] is None
                 and historical["in_support_on_observation_date"]
                 and historical["meets_kubernetes_recommendation"]
                 and historical["older_than_reviewed_release"]
                 and historical["advisory_applicability"] == "not_assessed_from_version_alone")
    lab.check("green", "The exact upstream tag verifies and the reviewed support snapshot distinguishes "
              "branch support, patch age and advisory applicability",
              canonical, {"tag": verified["tag"], "signer": verified["signer_fingerprint"],
                          "support_branch": historical["support_line"], "within_support": True,
                          "older_than_reviewed_release": True, "advisory_applicability_assessed": False})
    return verified


def run(lab):
    verify_fixture_records(lab)
    try:
        verified = verify_release(lab)
    except (OSError, ValueError) as error:
        lab.block(f"Official release verification prerequisite failed: {error}")
    schedule_compatible_fixture(lab, verify_node_runtime_reporting(lab))
    sibling_module("runtime_canary").verify_runtime_canary(lab)
    (lab.evidence / "verified-runtime-release.json").write_text(json.dumps(verified, indent=2) + "\n")
