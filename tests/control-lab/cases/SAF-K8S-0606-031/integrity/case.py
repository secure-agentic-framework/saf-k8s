"""Check Argo CD upstream provenance and a controlled configuration update."""
from hashlib import sha256
import json
from pathlib import Path
import platform
import re
import time

HERE = Path(__file__).resolve().parent
NS = "argocd"
MAP = "argocd-cm"
POLICY = "saf-argocd-cm-scoped-update"
MAINTAINER = "system:serviceaccount:argocd:saf-config-maintainer"
KEY = "timeout.reconciliation"
SOURCE = "github.com/argoproj/argo-cd"
VERSION = "v3.6.1"
DIGEST = "sha256:296e3d74f449b2ce45265613fcb68c18ed7366488360c8ea32f5f2a93d2e5c54"
IMAGE = f"quay.io/argoproj/argocd@{DIGEST}"
IDENTITY = f"https://{SOURCE}/.github/workflows/image-reuse.yaml@refs/tags/{VERSION}"
COSIGN = ("ghcr.io/sigstore/cosign/cosign:v3.1.4@sha256:"
          "0f06154836d2de34f887a5c273506d52ca43edaa1d9e53e6510fa78a48f69c2d")
SLSA_VERSION = "v2.7.1"
SLSA_CHECKSUMS = {
    "darwin-amd64": "4baf25415727821f847a38bccedc86c3e5b17cbfc2eb534cd554feb6c856d6f1",
    "darwin-arm64": "39abfcf5f1d690c3e889ce3d2d6a8b87711424d83368511868d414e8f8bcb05c",
    "linux-amd64": "946dbec729094195e88ef78e1734324a27869f03e2c6bd2f61cbc06bd5350339",
    "linux-arm64": "5d3b2349ede7bfec19e7a21569f18b9f7410145ad12e9584b175370669e14061",
}
COMPONENTS = ("argocd-application-controller", "argocd-repo-server", "argocd-server")


def slsa(lab):
    arch = {"aarch64": "arm64", "x86_64": "amd64"}.get(platform.machine(), platform.machine())
    system = f"{platform.system().lower()}-{arch}"
    if system not in SLSA_CHECKSUMS:
        lab.block(f"No checksum-pinned SLSA verifier for {system}")
    name = f"slsa-verifier-{system}"
    url = f"https://github.com/slsa-framework/slsa-verifier/releases/download/{SLSA_VERSION}/{name}"
    path = lab.kubeconfig.with_name(name)
    lab.command("curl", "-fsSL", "--max-time", "60", url, "-o", str(path), timeout=70)
    if sha256(path.read_bytes()).hexdigest() != SLSA_CHECKSUMS[system]:
        lab.block("SLSA verifier checksum did not match its release")
    path.chmod(0o700)
    result = lab.command(str(path), "verify-image", IMAGE, "--source-uri", SOURCE,
                         "--source-tag", VERSION, "--print-provenance", timeout=90)
    return json.loads(result.stdout)


def cosign(lab, identity):
    return lab.command("docker", "--context", lab.context, "run", "--rm", "--cap-drop", "ALL",
                       "--security-opt", "no-new-privileges", COSIGN, "verify",
                       "--certificate-identity", identity,
                       "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
                       "--certificate-github-workflow-repository", "argoproj/argo-cd", IMAGE,
                       allow_failure=True, timeout=100)


def verify_release(lab):
    approved = cosign(lab, IDENTITY)
    if approved.returncode != 0:
        lab.block("Argo CD's approved release signature could not be verified")
    claims = json.loads(approved.stdout)
    checked_signatures = [row for row in claims
               if row["critical"]["image"]["docker-manifest-digest"] == DIGEST]
    wrong = cosign(lab, IDENTITY.replace("/image-reuse.yaml@", "/fixture-unapproved.yaml@"))
    reason = (wrong.stderr + wrong.stdout).lower()
    lab.check("red", "The exact release image fails verification with an unrelated workflow identity",
              wrong.returncode != 0 and ("subject" in reason or "identity" in reason),
              {"identity_rejected": wrong.returncode != 0, "same_image_digest": DIGEST})
    provenance = slsa(lab)
    predicate = provenance.get("predicate", {})
    resolved = predicate.get("invocation", {}).get("configSource", {})
    lab.check("positive", "Cosign authenticates the pinned image and the SLSA verifier binds it to the source tag",
              bool(checked_signatures) and any(row["digest"].get("sha256") == DIGEST.split(":", 1)[1]
                                for row in provenance["subject"])
              and provenance["predicateType"] in {"https://slsa.dev/provenance/v0.2", "https://slsa.dev/provenance/v1"},
              {"image_digest": DIGEST, "source": SOURCE, "tag": VERSION,
               "verified_builder": predicate.get("builder", {}).get("id"),
               "build_source_digest": resolved.get("digest", {})})
    return {"cosign": checked_signatures, "slsa": provenance}


def node_runtime(lab, node, *args):
    return lab.command("docker", "--context", lab.context, "exec", node,
                       "ctr", "--namespace", "k8s.io", *args, timeout=40).stdout


def verified_content(lab, node, digest):
    content = node_runtime(lab, node, "content", "get", digest)
    if f"sha256:{sha256(content.encode()).hexdigest()}" != digest:
        lab.block(f"Runtime content did not match its OCI digest: {digest}")
    return json.loads(content)


def parent_for_layers(diff_ids):
    chain = diff_ids[0]
    for diff_id in diff_ids[1:]:
        chain = "sha256:" + sha256(f"{chain} {diff_id}".encode()).hexdigest()
    return chain


def snapshot_evidence(lab, node, container_id, child):
    child_manifest = verified_content(lab, node, child)
    config_digest = child_manifest["config"]["digest"]
    image_config = verified_content(lab, node, config_digest)
    chain = parent_for_layers(image_config["rootfs"]["diff_ids"])
    running = json.loads(node_runtime(lab, node, "containers", "info", container_id))
    active = json.loads(node_runtime(lab, node, "snapshots", "--snapshotter", running["Snapshotter"],
                                    "info", running["SnapshotKey"]))
    parent = active.get("Parent")
    matched = (running.get("ID") == container_id and running.get("Image", "").endswith(f"@{DIGEST}")
               and active.get("Kind") == "Active" and parent == chain)
    return {"runtime_snapshot_parent": parent, "verified_platform_chain_id": chain,
            "verified_platform_config": config_digest, "rootfs_matches": matched}


def check_runtime(lab):
    result = lab.command("docker", "--context", lab.context, "buildx", "imagetools",
                         "inspect", "--raw", IMAGE, timeout=55)
    if "sha256:" + sha256(result.stdout.encode()).hexdigest() != DIGEST:
        lab.block("The public OCI index did not match the verified digest")
    index = json.loads(result.stdout)
    pods = json.loads(lab.kubectl("-n", NS, "get", "pods", "-o", "json").stdout)["items"]
    nodes = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    platforms = {node["metadata"]["name"]: (node["status"]["nodeInfo"]["operatingSystem"],
                                           node["status"]["nodeInfo"]["architecture"]) for node in nodes}
    evidence = []
    checked = set()
    mismatches = []
    for pod in pods:
        component = pod["metadata"].get("labels", {}).get("app.kubernetes.io/name")
        if component not in COMPONENTS:
            continue
        os_name, arch = platforms[pod["spec"]["nodeName"]]
        descriptors = [row["digest"] for row in index["manifests"]
                       if (row.get("platform", {}).get("os"), row.get("platform", {}).get("architecture")) == (os_name, arch)]
        declared = {c["name"]: c["image"] for c in pod["spec"]["containers"]}
        statuses = [c for c in pod["status"].get("containerStatuses", [])
                    if declared[c["name"]].startswith("quay.io/argoproj/argocd:")]
        if not statuses:
            mismatches.append(component)
        for container in statuses:
            digest = re.search(r"sha256:[0-9a-f]{64}$", container.get("imageID", ""))
            actual = digest.group() if digest else None
            expected = descriptors[0] if len(descriptors) == 1 else None
            container_id = container.get("containerID", "").removeprefix("containerd://")
            snapshot = (snapshot_evidence(lab, pod["spec"]["nodeName"], container_id, expected)
                        if expected and re.fullmatch(r"[a-f0-9]{64}", container_id) else {})
            clean = (container.get("ready") and expected and actual in {DIGEST, expected}
                     and declared[container["name"]].endswith(f"@{DIGEST}")
                     and snapshot.get("rootfs_matches") is True)
            if clean:
                checked.add(component)
            else:
                mismatches.append(component)
            evidence.append({"component": component, "container": container["name"],
                             "platform": f"{os_name}/{arch}", "declared_image": declared[container["name"]],
                             "runtime_digest": actual, "verified_child_digest": expected, **snapshot})
    evidence.sort(key=lambda row: (row["component"], row["container"]))
    lab.check("positive", "The running Argo CD controllers use root filesystems from the verified platform-specific child image",
              set(COMPONENTS) == checked and not mismatches,
              {"runtime_images": evidence, "mismatched_components": sorted(mismatches)})
    return evidence


def config(lab):
    return json.loads(lab.kubectl("-n", NS, "get", "configmap", MAP, "-o", "json").stdout)


def config_integrity(lab):
    seed = json.dumps({"data": {KEY: "120s", "application.resourceTrackingMethod": "annotation"}})
    lab.kubectl("-n", NS, "patch", "configmap", MAP, "--type=merge", "--patch", seed)
    before = config(lab)
    manifest = HERE / "controller-config-policy.yaml"
    bindings = lab.kubeconfig.with_name("saf-argocd-config-rbac.yaml")
    rules = manifest.read_text().split("\n---\n")
    bindings.write_text("\n---\n".join(rules[2:]))
    lab.kubectl("-n", NS, "apply", "-f", str(bindings))
    # A JSON replacement uses update permission, so no patch permission is needed.
    arguments = ("-n", NS, "--as", MAINTAINER, "replace", "-f", "-", "-o", "json")
    unwanted = {**before, "data": {**before["data"], KEY: "600s"}}
    drift = lab.kubectl(*arguments, "--dry-run=server", payload=json.dumps(unwanted), allow_failure=True)
    lab.check("red", "The scoped maintainer can submit an out-of-contract change before admission is enabled",
              drift.returncode == 0 and json.loads(drift.stdout)["data"][KEY] == "600s",
              {"out_of_contract_dry_run_admitted": drift.returncode == 0})

    lab.kubectl("-n", NS, "apply", "-f", str(manifest))
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        denied = lab.kubectl(*arguments, "--dry-run=server", payload=json.dumps(unwanted), allow_failure=True)
        if denied.returncode and POLICY in denied.stderr:
            break
        time.sleep(1)
    lab.check("green", "The installed policy rejects the same fixture drift with its exact constraint reason",
              denied.returncode != 0 and POLICY in denied.stderr
              and "only timeout.reconciliation may be set to the fixture value 180s" in denied.stderr
              and config(lab)["data"] == before["data"],
              {"policy_named": POLICY in denied.stderr, "stored_config_unchanged": config(lab)["data"] == before["data"]})
    current = config(lab)
    change = {**current, "data": {**current["data"], KEY: "180s"}}
    permitted = lab.kubectl(*arguments, payload=json.dumps(change), allow_failure=True)
    after = config(lab)
    protected = ("uid", "labels", "annotations", "ownerReferences", "finalizers")
    same_metadata = all(after["metadata"].get(key) == before["metadata"].get(key) for key in protected)
    policy = json.loads(lab.kubectl("get", "validatingadmissionpolicy", POLICY, "-o", "json").stdout)
    warnings = policy.get("status", {}).get("typeChecking", {}).get("expressionWarnings", [])
    lab.check("positive", "The maintainer persists only the approved value with the policy active",
              permitted.returncode == 0 and same_metadata and after["data"] == change["data"]
              and after.get("immutable") == before.get("immutable")
              and after.get("binaryData") == before.get("binaryData") and not warnings,
              {"maintainer": MAINTAINER, "approved_value": after["data"].get(KEY),
               "other_data_unchanged": after["data"] == change["data"], "scope_unchanged": same_metadata,
               "type_warnings": warnings})
    return {"before": before, "after": after, "policy": policy}


def run(lab):
    provenance = verify_release(lab)
    runtime = check_runtime(lab)
    protection = config_integrity(lab)
    (lab.evidence / "argocd-controller-integrity.json").write_text(json.dumps(
        {"provenance": provenance, "runtime": runtime, "configuration": protection}, indent=2) + "\n")
