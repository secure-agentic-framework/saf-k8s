"""Exercise a native admission release gate against bounded synthetic inventory."""
import importlib.util
import hashlib
import json
from pathlib import Path
import re
import shlex
import tarfile
import tempfile
import time

from fixtures import BUSYBOX_IMAGE, container, pod


HERE = Path(__file__).resolve().parent
PUBLISHED_CASES = HERE.parent
SCOPE = (
    "One disposable Kind cluster and its default saf-test namespace. A Kubernetes-native "
    "ValidatingAdmissionPolicy gates server-side Pod dry-runs on an exact pinned inert image "
    "and an exact, bounded offline synthetic inference package inventory. The inventory "
    "uses the published OCI fixture's canonical JSON and digest helper and the published "
    "inference fixture's serving contract. It demonstrates declared-inventory release gating; "
    "the positive path runs the pinned fixture and checks its exact API metadata. "
    "A separate fixture comparison builds two inert local OCI targets from the exact pinned base, "
    "observes marker files inside their real filesystem layers, and records local config/layer digests, "
    "per-Pod-node CRI config/diff-ID joins, and Kubernetes runtime image IDs. This proves only the fixture's "
    "build-stage marker distinction; "
    "actual production image composition, hardware, CUDA/driver compatibility, qualification, provenance, "
    "registry promotion, and deployed gate adoption remain unverified."
)

NS = "saf-test"
POLICY = "fixture-inference-minimal-image"
PARAMETERS = "fixture-inference-minimal-image-approved"
DENIAL = "inference image is not the exact approved runtime-only composition"
INVENTORY_ANNOTATION = "saf-k8s.example/package-inventory"
INVENTORY_SHA_ANNOTATION = "saf-k8s.example/package-inventory-sha256"
CASE_LABEL = "saf-k8s.example/case"
IMAGE_SOURCE_LABEL = "saf-k8s.example/image-source-sha256"
IMAGE_TARGET_LABEL = "saf-k8s.example/image-target"
IMAGE_JOB_PREFIX = "fixture-image-content"


def read_exported_config(lab, reference):
    with tempfile.TemporaryDirectory(prefix="saf-oci-config-") as directory:
        exported = Path(directory) / "image.tar"
        lab.command("docker", "image", "save", "-o", str(exported), reference, timeout=60)
        with tarfile.open(exported) as archive:
            manifest_rows = json.load(archive.extractfile("manifest.json"))
            if len(manifest_rows) != 1:
                lab.block("The case image export did not resolve one platform config")
            member = archive.getmember(manifest_rows[0]["Config"])
            if not member.isfile() or member.size > 1048576:
                lab.block("The exported image config is missing or exceeds the fixture bound")
            config_bytes = archive.extractfile(member).read()
    return "sha256:" + hashlib.sha256(config_bytes).hexdigest(), json.loads(config_bytes)


def build_image_pair(lab):
    dockerfile = HERE / "Dockerfile"
    runtime_marker = HERE / "runtime-marker.txt"
    build_marker = HERE / "build-only-marker.txt"
    source_hash = hashlib.sha256(b"\0".join(
        path.read_bytes() for path in (dockerfile, runtime_marker, build_marker)
    )).hexdigest()
    dockerfile_text = dockerfile.read_text()
    if f"FROM {BUSYBOX_IMAGE} AS runtime-base" not in dockerfile_text:
        lab.block("The image content fixture no longer uses the exact pinned base image")
    expected_markers = {
        "runtime": hashlib.sha256(runtime_marker.read_bytes()).hexdigest(),
        "build": hashlib.sha256(build_marker.read_bytes()).hexdigest(),
    }
    specs = {
        "with-build-marker": "image-with-build-marker",
        "runtime-only": "image-runtime-only",
    }
    records = {}
    for variant, target in specs.items():
        image = f"docker.io/library/saf-0601-015:{source_hash[:16]}-{variant}"
        inspected = lab.command("docker", "image", "inspect", image, allow_failure=True)
        expected_labels = {IMAGE_SOURCE_LABEL: source_hash, IMAGE_TARGET_LABEL: target}
        if inspected.returncode:
            lab.command("docker", "build", "--network=none", "-t", image,
                        "--label", f"{IMAGE_SOURCE_LABEL}={source_hash}",
                        "--label", f"{IMAGE_TARGET_LABEL}={target}",
                        "--target", target, "-f", str(dockerfile), str(HERE), timeout=420)
            inspected = lab.command("docker", "image", "inspect", image)
        record, = json.loads(inspected.stdout)
        config = record.get("Config", {})
        image_id = record.get("Id", "")
        labels = config.get("Labels") or {}
        if labels.get(IMAGE_SOURCE_LABEL) != source_hash or labels.get(IMAGE_TARGET_LABEL) != target:
            lab.block("A local image tag is not bound to this exact fixture source and target")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            lab.block("The image engine did not return a digest-qualified descriptor")
        layers = record.get("RootFS", {}).get("Layers", [])
        if not layers or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", item) for item in layers):
            lab.block("The image engine did not return canonical root filesystem layer digests")
        config_digest, exported_config = read_exported_config(lab, image)
        if exported_config.get("rootfs", {}).get("diff_ids") != layers:
            lab.block("The image export config diff IDs differ from the inspected local image layers")
        exported_labels = exported_config.get("config", {}).get("Labels") or {}
        if any(exported_labels.get(name) != value for name, value in expected_labels.items()):
            lab.block("The exported image config labels do not identify the exact fixture target")
        records[variant] = {"reference": image, "target": target, "config_digest": config_digest,
                            "docker_image_id": image_id, "rootfs_layer_digests": layers,
                            "source_sha256": source_hash, "expected_labels": expected_labels}
    if records["with-build-marker"]["config_digest"] == records["runtime-only"]["config_digest"]:
        lab.block("The two image targets unexpectedly resolved to the same image config digest")
    for record in records.values():
        lab.command("kind", "load", "docker-image", record["reference"], "--name", lab.cluster,
                    timeout=210)
    return {"source_sha256": source_hash, "expected_marker_sha256": expected_markers,
            "images": records}


def observe_image_job(lab, name, image_record, expect_build_marker, marker_hashes):
    runtime_hash = marker_hashes["runtime"]
    build_hash = marker_hashes["build"]
    script = (
        "set -eu; "
        "runtime=$(/bin/busybox sha256sum /fixture/runtime-marker | /bin/busybox cut -d ' ' -f 1); "
        f"test \"$runtime\" = {shlex.quote(runtime_hash)}; "
        "if test -f /fixture/build-only-marker; then "
        "build_present=true; "
        "build=$(/bin/busybox sha256sum /fixture/build-only-marker | /bin/busybox cut -d ' ' -f 1); "
        f"test \"$build\" = {shlex.quote(build_hash)}; "
        "else build_present=false; build=; fi; "
        f"test \"$build_present\" = {str(expect_build_marker).lower()}; "
        "printf '{\"runtime_sha256\":\"%s\",\"build_marker_present\":%s,\"build_sha256\":\"%s\"}\\n' \"$runtime\" \"$build_present\" \"$build\""
    )
    pod_spec = pod(name, [container("inspect", image=image_record["reference"],
        imagePullPolicy="Never", command=["/bin/busybox", "sh", "-c", script])],
        automountServiceAccountToken=False)
    pod_spec["spec"].update({
        "restartPolicy": "Never",
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                            "seccompProfile": {"type": "RuntimeDefault"}},
    })
    pod_spec["spec"]["containers"][0].update({
        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                             "capabilities": {"drop": ["ALL"]}},
        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                      "limits": {"cpu": "50m", "memory": "32Mi"}},
    })
    lab.create({"apiVersion": "batch/v1", "kind": "Job",
                "metadata": {"name": name},
                "spec": {"backoffLimit": 0, "template": {"metadata": {"labels": {"app": name}},
                    "spec": pod_spec["spec"]}}})
    deadline = time.monotonic() + 100
    conditions = set()
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", f"job/{name}", "-o", "json").stdout)
        conditions = {row["type"] for row in job.get("status", {}).get("conditions", [])
                      if row.get("status") == "True"}
        if conditions & {"Complete", "Failed", "FailureTarget"}:
            break
        time.sleep(1)
    if "Complete" not in conditions:
        lab.kubectl("logs", f"job/{name}", "--tail=4", allow_failure=True)
        lab.block(f"The owned OCI marker Job {name} did not complete successfully")
    pod_obj = json.loads(lab.kubectl("get", "pods", "-l", f"app={name}", "-o", "json").stdout)
    items = pod_obj.get("items", [])
    if len(items) != 1:
        lab.block("Image content job did not produce exactly one owned Pod")
    observed_pod = items[0]
    logs = lab.kubectl("logs", f"pod/{observed_pod['metadata']['name']}").stdout.strip()
    result = json.loads(logs)
    status = observed_pod.get("status", {}).get("containerStatuses", [{}])[0]
    if result.get("runtime_sha256") != marker_hashes["runtime"] or \
       result.get("build_marker_present") is not expect_build_marker or \
       (expect_build_marker and result.get("build_sha256") != marker_hashes["build"]) or \
       (not expect_build_marker and result.get("build_sha256") != ""):
        lab.block("The running image content did not match the expected inert marker comparison")
    if not status.get("imageID") or not status.get("ready", False):
        # Completed Jobs may not report ready after termination; imageID is the runtime binding.
        if not status.get("imageID"):
            lab.block("Kubernetes did not report the actual runtime image identifier")
    return {"job": name, "job_uid": json.loads(lab.kubectl("get", "job", name, "-o", "json").stdout)["metadata"]["uid"],
            "pod_uid": observed_pod["metadata"]["uid"], "requested_image": image_record["reference"],
            "node_name": observed_pod.get("spec", {}).get("nodeName"),
            "local_config_digest": image_record["config_digest"],
            "runtime_image_id": status["imageID"], "runtime_marker_sha256": result["runtime_sha256"],
            "build_marker_present": result["build_marker_present"],
            "build_marker_sha256": result["build_sha256"]}


def inspect_cri_image(lab, observation, image_record):
    node = observation.get("node_name", "")
    if not node or not node.startswith(lab.cluster + "-"):
        lab.block("The image-content Pod was not scheduled to an owned Kind node")
    result = lab.command("docker", "exec", node, "crictl", "inspecti",
                         image_record["reference"], timeout=25)
    try:
        inspected = json.loads(result.stdout)
        status = inspected["status"]
        image_spec = inspected["info"]["imageSpec"]
        if isinstance(image_spec, str):
            image_spec = json.loads(image_spec)
        diff_ids = image_spec["rootfs"]["diff_ids"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        lab.block(f"CRI image inspection did not expose the required config/diff IDs ({type(error).__name__})")
    repo_tags = status.get("repoTags", [])
    cri_id = status.get("id", "")
    if image_record["reference"] not in repo_tags:
        lab.block("The selected Kind node CRI did not resolve the exact case-owned image reference")
    if cri_id != image_record["config_digest"]:
        lab.block("The CRI image config ID differs from the local image config digest")
    if diff_ids != image_record["rootfs_layer_digests"]:
        lab.block("The CRI rootfs diff IDs differ from the locally inspected image layers")
    return {"node": node, "requested_reference": image_record["reference"],
            "repo_tags": repo_tags, "cri_config_id": cri_id,
            "local_config_id": image_record["config_digest"],
            "cri_rootfs_diff_ids": diff_ids,
            "local_rootfs_diff_ids": image_record["rootfs_layer_digests"],
            "config_id_match": cri_id == image_record["config_digest"],
            "diff_ids_match": diff_ids == image_record["rootfs_layer_digests"]}


def published_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load published helper {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def admission(lab, name, inventory_json, inventory_sha, *, dry_run=True, image=BUSYBOX_IMAGE):
    request = pod(name, [container("inference", image=image,
                                   imagePullPolicy="IfNotPresent")],
                  automountServiceAccountToken=False)
    request["metadata"]["labels"] = {CASE_LABEL: "SAF-K8S-0601-015"}
    request["metadata"]["annotations"] = {
        INVENTORY_ANNOTATION: inventory_json,
        INVENTORY_SHA_ANNOTATION: inventory_sha,
    }
    optional = ("--dry-run=server",) if dry_run else ()
    result = lab.kubectl("create", *optional, "-f", "-", "-o", "json",
                         payload=json.dumps(request, sort_keys=True), allow_failure=True)
    observed = {"name": name, "accepted": result.returncode == 0,
                "returncode": result.returncode,
                "stdout": result.stdout.strip(), "stderr": result.stderr.strip()}
    if result.returncode == 0:
        try:
            parsed = json.loads(result.stdout)
            observed["admitted_image"] = parsed["spec"]["containers"][0]["image"]
            if not dry_run:
                observed["created_uid"] = parsed["metadata"]["uid"]
        except (json.JSONDecodeError, KeyError, IndexError):
            lab.block("The API server returned an unrecognized successful dry-run response")
    return observed


def run(lab):
    package_helper = published_module(
        PUBLISHED_CASES / "SAF-K8S-0601-008" / "image_fixture.py",
        "saf_0601_015_package_scope_helper",
    )
    inference_helper = published_module(
        PUBLISHED_CASES / "SAF-K8S-0908-001" / "inference_fixture.py",
        "saf_0601_015_inference_scope_helper",
    )

    runtime_packages = [
        {"name": "cuda-cublas", "version": "12.8.4", "role": "gpu-runtime"},
        {"name": "cuda-cudart", "version": "12.8.90", "role": "gpu-runtime"},
        {"name": "glibc", "version": "2.35", "role": "native-runtime"},
        {"name": "libstdcxx", "version": "12.3.0", "role": "native-runtime"},
        {"name": package_helper.PACKAGE, "version": "1.0.1", "role": "inference-library"},
    ]
    runtime_packages.sort(key=lambda row: row["name"])
    runtime_inventory = {
        "schema": "saf.synthetic.inference-package-inventory.v1",
        "image": BUSYBOX_IMAGE,
        "serving_contract": {"audience": inference_helper.AUDIENCE,
                             "fixture_result": inference_helper.RESULT},
        "packages": runtime_packages,
    }
    build_packages = runtime_packages + [
        {"name": "gcc", "version": "14.2.0", "role": "compiler"},
        {"name": "gdb", "version": "15.2", "role": "debugger"},
        {"name": "make", "version": "4.4.1", "role": "build-tool"},
        {"name": "apk-tools", "version": "2.14.4", "role": "package-manager"},
    ]
    build_packages.sort(key=lambda row: row["name"])
    build_inventory = {**runtime_inventory, "packages": build_packages}

    runtime_bytes = package_helper.encode(runtime_inventory)
    build_bytes = package_helper.encode(build_inventory)
    runtime_json, build_json = runtime_bytes.decode(), build_bytes.decode()
    runtime_sha = package_helper.digest(runtime_bytes).removeprefix("sha256:")
    build_sha = package_helper.digest(build_bytes).removeprefix("sha256:")
    if len(runtime_packages) != 5 or len(build_packages) != 9 or runtime_sha == build_sha:
        lab.block("The bounded fixture inventories were not constructed as expected")

    denied_name = "fixture-inference-with-build-tools"
    unguarded = admission(lab, denied_name, build_json, build_sha)
    lab.check("red", "An unguarded API server accepts a declared build-tool inventory",
              unguarded["accepted"] and unguarded.get("admitted_image") == BUSYBOX_IMAGE,
              {"accepted": unguarded["accepted"], "image": unguarded.get("admitted_image"),
               "inventory_package_count": len(build_packages)})

    lab.create({"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": PARAMETERS, "labels": {CASE_LABEL: "SAF-K8S-0601-015"}},
                "immutable": True,
                "data": {"approved-image": BUSYBOX_IMAGE,
                         "approved-inventory-json": runtime_json,
                         "approved-inventory-sha256": runtime_sha}})
    validation_expression = (
        "params != null && has(params.data) && "
        "has(object.metadata.annotations) && "
        f'object.metadata.annotations["{INVENTORY_ANNOTATION}"] == '
        'params.data["approved-inventory-json"] && '
        f'object.metadata.annotations["{INVENTORY_SHA_ANNOTATION}"] == '
        'params.data["approved-inventory-sha256"] && '
        'object.spec.containers.size() == 1 && object.spec.containers.all(c, '
        'c.image == params.data["approved-image"] && c.imagePullPolicy == "IfNotPresent") && '
        '(!has(object.spec.initContainers) || object.spec.initContainers.size() == 0)'
    )
    policy_spec = {
        "failurePolicy": "Fail",
        "paramKind": {"apiVersion": "v1", "kind": "ConfigMap"},
        "matchConstraints": {"objectSelector": {"matchLabels": {CASE_LABEL: "SAF-K8S-0601-015"}},
                             "resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"],
                                                    "operations": ["CREATE"], "resources": ["pods"]}]},
        "matchConditions": [{"name": "owned-test-namespace",
                              "expression": f'request.namespace == "{NS}"'}],
        "validations": [{"expression": validation_expression, "message": DENIAL}],
    }
    lab.create({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicy",
        "metadata": {"name": POLICY, "labels": {CASE_LABEL: "SAF-K8S-0601-015"}},
        "spec": policy_spec,
    })
    binding_spec = {"policyName": POLICY, "validationActions": ["Deny"],
                    "paramRef": {"name": PARAMETERS, "namespace": NS,
                                 "parameterNotFoundAction": "Deny"}}
    lab.create({
        "apiVersion": "admissionregistration.k8s.io/v1",
        "kind": "ValidatingAdmissionPolicyBinding",
        "metadata": {"name": POLICY, "labels": {CASE_LABEL: "SAF-K8S-0601-015"}},
        "spec": binding_spec,
    })

    deadline = time.monotonic() + 25
    while True:
        leaky = admission(lab, denied_name, build_json, build_sha)
        if DENIAL in leaky["stderr"] or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    wrong_sha = admission(lab, "fixture-inference-forged-inventory", build_json, runtime_sha)
    wrong_image = admission(lab, "fixture-inference-wrong-image", runtime_json, runtime_sha,
                            image="fixture.invalid/unreviewed-image:latest")
    active_policy = json.loads(lab.kubectl("get", "validatingadmissionpolicy", POLICY, "-o", "json").stdout)
    active_binding = json.loads(lab.kubectl("get", "validatingadmissionpolicybinding", POLICY, "-o", "json").stdout)

    green = {
        "build_compiler_package_manager_debugger_denied": (
            not leaky["accepted"] and DENIAL in leaky["stderr"]
        ),
        "denial_is_for_exact_unapproved_inventory": build_sha != runtime_sha,
        "approved_hash_cannot_label_a_different_inventory": DENIAL in wrong_sha["stderr"] and not wrong_sha["accepted"],
        "approved_inventory_cannot_label_a_different_image": DENIAL in wrong_image["stderr"] and not wrong_image["accepted"],
        "approved_image_is_exact_digest_pinned_busybox": bool(re.fullmatch(
            r"docker\.io/library/busybox:1\.37\.0@sha256:[0-9a-f]{64}", BUSYBOX_IMAGE
        )),
        "policy_and_binding_persist_exact_fail_closed_gate":
            all(active_policy["spec"].get(k) == policy_spec[k]
                for k in ("failurePolicy", "paramKind", "validations", "matchConditions")) and
            active_binding["spec"].get("validationActions") == ["Deny"] and
            active_binding["spec"].get("paramRef") == binding_spec["paramRef"],
    }
    lab.check("green", "The native release gate denies the inventory containing build dependencies",
              all(green.values()), green)

    name = "fixture-inference-runtime-only"
    clean = admission(lab, name, runtime_json, runtime_sha, dry_run=False)
    if not clean["accepted"]:
        lab.block("Exact reviewed inference fixture was not admitted: " + clean["stderr"])
    lab.kubectl("wait", "--for=condition=Ready", f"pod/{name}", "--timeout=100s", timeout=110)
    live = json.loads(lab.kubectl("get", "pod", name, "-o", "json").stdout)
    positive = {
        "runtime_inventory_admitted": clean["accepted"]
        and clean.get("admitted_image") == BUSYBOX_IMAGE
        and live["metadata"]["uid"] == clean["created_uid"]
        and live["metadata"]["annotations"][INVENTORY_SHA_ANNOTATION] == runtime_sha
        and bool(live["status"]["containerStatuses"][0]["imageID"])
        and live["status"]["containerStatuses"][0]["ready"],
        "required_inference_and_native_runtime_packages_retained": (
            {row["role"] for row in runtime_packages}
            == {"gpu-runtime", "native-runtime", "inference-library"}
        ),
        "cuda_runtime_packages_retained_for_gpu_profile": (
            {row["name"] for row in runtime_packages if row["role"] == "gpu-runtime"}
            == {"cuda-cublas", "cuda-cudart"}
        ),
        "no_compiler_package_manager_build_tool_or_debugger_in_approved_inventory": (
            not {"compiler", "package-manager", "build-tool", "debugger"}
            & {row["role"] for row in runtime_packages}
        ),
    }
    lab.check("positive", "The exact runtime-only GPU inference inventory remains admissible",
              all(positive.values()), {"checks": positive,
                                      "admitted_image": clean.get("admitted_image")})

    raw = {
        "control": "SAF-K8S-0601-015",
        "namespace": NS,
        "image": BUSYBOX_IMAGE,
        "serving_contract": {"audience": inference_helper.AUDIENCE,
                             "fixture_result": inference_helper.RESULT},
        "inventory_helper": "SAF-K8S-0601-008/image_fixture.py",
        "baseline_without_gate": unguarded,
        "policy": {"name": POLICY, "parameter": PARAMETERS,
                   "failurePolicy": "Fail", "validationAction": "Deny",
                   "approved_inventory_sha256": runtime_sha,
                   "spec": policy_spec, "binding_spec": binding_spec},
        "synthetic_inventories": {
            "runtime_only": {"sha256": runtime_sha, "package_count": len(runtime_packages),
                              "document": runtime_inventory},
            "with_build_dependencies": {"sha256": build_sha,
                                        "package_count": len(build_packages),
                                        "document": build_inventory},
        },
        "under_gate": {"build_dependencies": leaky, "runtime_only": clean,
                       "wrong_sha": wrong_sha, "wrong_image": wrong_image},
        "policy_uid": active_policy["metadata"]["uid"],
        "actual_runtime": {"pod_uid": live["metadata"]["uid"],
                           "image_id": live["status"]["containerStatuses"][0]["imageID"]},
        "red": unguarded["accepted"], "green": green, "positive": positive,
    }
    normalized = {
        "control": "SAF-K8S-0601-015",
        "image": BUSYBOX_IMAGE,
        "namespace": NS,
        "inventory_helper": "SAF-K8S-0601-008/image_fixture.py",
        "runtime_inventory_sha256": runtime_sha,
        "leaky_inventory_sha256": build_sha,
        "runtime_package_count": len(runtime_packages),
        "leaky_package_count": len(build_packages),
        "red_unguarded_admitted": unguarded["accepted"],
        "green_leaky_denied": green["build_compiler_package_manager_debugger_denied"],
        "positive_runtime_only_admitted": positive["runtime_inventory_admitted"],
        "hardware_tested": False,
        "production_image_qualified": False,
        "inventory_provenance_verified": False,
    }
    for filename, value in (("inference-image-composition-raw.json", raw),
                            ("inference-image-composition-normalized.json", normalized)):
        (lab.evidence / filename).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")

    # Supplemental real-image content witness. Kept after the original three checks.
    pair = build_image_pair(lab)
    leaky_observation = observe_image_job(
        lab, IMAGE_JOB_PREFIX + "-build-stage", pair["images"]["with-build-marker"], True,
        pair["expected_marker_sha256"])
    approved_observation = observe_image_job(
        lab, IMAGE_JOB_PREFIX + "-runtime-only", pair["images"]["runtime-only"], False,
        pair["expected_marker_sha256"])
    leaky_cri = inspect_cri_image(lab, leaky_observation, pair["images"]["with-build-marker"])
    approved_cri = inspect_cri_image(lab, approved_observation, pair["images"]["runtime-only"])
    content_checks = {
        "distinct_local_image_config_digests": (
            pair["images"]["with-build-marker"]["config_digest"] !=
            pair["images"]["runtime-only"]["config_digest"]
        ),
        "build_stage_image_contains_exact_synthetic_build_marker": (
            leaky_observation["build_marker_present"] and
            leaky_observation["build_marker_sha256"] == pair["expected_marker_sha256"]["build"]
        ),
        "runtime_only_image_contains_no_build_marker": (
            not approved_observation["build_marker_present"] and
            approved_observation["build_marker_sha256"] == ""
        ),
        "both_images_run_the_same_exact_runtime_marker": (
            leaky_observation["runtime_marker_sha256"] ==
            approved_observation["runtime_marker_sha256"] ==
            pair["expected_marker_sha256"]["runtime"]
        ),
        "runtime_image_ids_observed_for_both_owned_jobs": (
            bool(leaky_observation["runtime_image_id"]) and
            bool(approved_observation["runtime_image_id"])
        ),
        "approved_runtime_only_job_uses_its_built_image_reference": (
            approved_observation["requested_image"] == pair["images"]["runtime-only"]["reference"]
        ),
        "each_pod_node_cri_resolves_the_requested_case_image_tag": (
            leaky_cri["requested_reference"] in leaky_cri["repo_tags"] and
            approved_cri["requested_reference"] in approved_cri["repo_tags"]
        ),
        "cri_config_ids_equal_docker_image_config_ids": (
            leaky_cri["config_id_match"] and approved_cri["config_id_match"]
        ),
        "cri_rootfs_diff_ids_equal_docker_rootfs_layers": (
            leaky_cri["diff_ids_match"] and approved_cri["diff_ids_match"]
        ),
        "pod_runtime_image_ids_are_digest_qualified": (
            bool(re.search(r"sha256:[0-9a-f]{64}$", leaky_observation["runtime_image_id"])) and
            bool(re.search(r"sha256:[0-9a-f]{64}$", approved_observation["runtime_image_id"]))
        ),
    }
    lab.check("positive", "Owned OCI targets show the approved runtime-only filesystem content",
              all(content_checks.values()), content_checks)
    (lab.evidence / "observed-image-content.json").write_text(json.dumps({
        "control": "SAF-K8S-0601-015",
        "scope": "synthetic local OCI content comparison only; no production image or hardware claim",
        "source_sha256": pair["source_sha256"],
        "expected_marker_sha256": pair["expected_marker_sha256"],
        "images": pair["images"],
        "observations": {"with_build_marker": leaky_observation,
                         "runtime_only": approved_observation},
        "cri_inspections": {"with_build_marker": leaky_cri, "runtime_only": approved_cri},
        "raw_predicates": content_checks,
        "normalized": {
            "distinct_config_digests": content_checks["distinct_local_image_config_digests"],
            "build_marker_content_observed": content_checks["build_stage_image_contains_exact_synthetic_build_marker"],
            "runtime_only_marker_absence_observed": content_checks["runtime_only_image_contains_no_build_marker"],
            "runtime_marker_equal": content_checks["both_images_run_the_same_exact_runtime_marker"],
            "pod_runtime_ids_present": content_checks["runtime_image_ids_observed_for_both_owned_jobs"],
            "cri_tag_config_and_diff_id_join": all((
                content_checks["each_pod_node_cri_resolves_the_requested_case_image_tag"],
                content_checks["cri_config_ids_equal_docker_image_config_ids"],
                content_checks["cri_rootfs_diff_ids_equal_docker_rootfs_layers"],
                content_checks["pod_runtime_image_ids_are_digest_qualified"],
            )),
        },
    }, sort_keys=True, indent=2) + "\n")

    # Additive real Go toolchain witness; the four existing checks above remain unchanged.
    real_witness = published_module(HERE / "real_toolchain_witness.py", "saf_0601_015_real_toolchain")
    real_witness.run(lab, BUSYBOX_IMAGE, NS)
