"""Exercise a native admission release gate against bounded synthetic inventory."""
import importlib.util
import json
from pathlib import Path
import re
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
    "Actual image composition, hardware, CUDA/driver compatibility, production image qualification, "
    "attestation provenance, registry promotion, and deployed gate adoption remain unverified."
)

NS = "saf-test"
POLICY = "fixture-inference-minimal-image"
PARAMETERS = "fixture-inference-minimal-image-approved"
DENIAL = "inference image is not the exact approved runtime-only composition"
INVENTORY_ANNOTATION = "saf-k8s.example/package-inventory"
INVENTORY_SHA_ANNOTATION = "saf-k8s.example/package-inventory-sha256"
CASE_LABEL = "saf-k8s.example/case"


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
