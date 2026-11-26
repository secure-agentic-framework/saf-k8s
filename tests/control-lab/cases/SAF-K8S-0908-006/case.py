"""Scratch wrapper preserving the published four checks and adding one Flower round."""

import importlib.util
from hashlib import sha256
import json
from pathlib import Path

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent
BASE_CASE = HERE / "base_case.py"
PIN_FILE = HERE / "image-pins.json"
LINK = "fixture-flower-superlink"
NODE_A = "fixture-flower-supernode-a"
NODE_B = "fixture-flower-supernode-b"
NODE_C = "fixture-flower-supernode-c"
LINK_SERVICE = "fixture-flower-superlink"
APP_CONFIG = "fixture-flower-app"
FLOWER_HOME_CONFIG = "fixture-flower-home"
LABEL = "saf-k8s-fixture-flower-secagg"
SCOPE = (
    "Preserve the four published Kubernetes identity, authorization, replay and release checks. "
    "Add one actual Flower 1.29.0 SecAggPlusWorkflow round over three fixed synthetic vectors "
    "in four owned Pods; this checks library execution, not deployment privacy or protocol security."
)


def load_base():
    spec = importlib.util.spec_from_file_location("saf_0908_006_published", BASE_CASE)
    if spec is None or spec.loader is None:
        raise RuntimeError("Published SAF-K8S-0908-006 case could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pin_images(lab):
    pins = json.loads(PIN_FILE.read_text())
    architecture = lab.command("docker", "info", "--format", "{{.Architecture}}", timeout=20).stdout.strip()
    platform = {"aarch64": "linux/arm64", "arm64": "linux/arm64",
                "x86_64": "linux/amd64", "amd64": "linux/amd64"}.get(architecture)
    if platform is None:
        lab.block("No official Flower 1.29.0 manifest is pinned for this Docker architecture")

    references = {}
    for name in ("superlink", "supernode"):
        entry = pins["images"][name]
        if platform not in entry["platform_manifests"]:
            lab.block("The selected Flower image has no manifest for the Docker architecture")
        reference = f'{entry["repository"]}@{entry["platform_manifests"][platform]}'
        digest_suffix = entry["index_sha256"][:12]
        local = f"saf-k8s-fixture/flwr-{name}:{platform.rsplit('/', 1)[-1]}-{digest_suffix}"
        lab.command("docker", "pull", reference, timeout=900)
        pinned_id = lab.command("docker", "image", "inspect", "--format", "{{.Id}}",
                                reference, timeout=20).stdout.strip()
        pulled_arch = lab.command("docker", "image", "inspect", "--format", "{{.Architecture}}",
                                  reference, timeout=20).stdout.strip()
        expected_arch = platform.split("/", 1)[1]
        if pulled_arch != expected_arch:
            lab.block("The pulled Flower image platform differs from the pinned OCI descriptor")
        lab.command("docker", "image", "tag", reference, local, timeout=20)
        local_id = lab.command("docker", "image", "inspect", "--format", "{{.Id}}",
                               local, timeout=20).stdout.strip()
        if not pinned_id or pinned_id != local_id:
            lab.block("A local Flower alias does not match the pinned official image")
        lab.command("kind", "load", "docker-image", local, "--name", lab.cluster, timeout=120)
        references[name] = {
            "image": local,
            "source_index_sha256": entry["index_sha256"],
            "platform": platform,
            "platform_manifest": entry["platform_manifests"][platform],
        }
    return references


def create(lab, kind, name, api="v1", **fields):
    return lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})


def create_flower_pod(lab, name, image, command, args, *, result_volume=False, env=None):
    mounts = [{"name": "app", "mountPath": "/flowerapp", "readOnly": True}]
    volumes = [{"name": "app", "configMap": {
        "name": APP_CONFIG,
        "items": [{"key": key, "path": key} for key in (
            "pyproject.toml", "client_app.py", "server_app.py")],
    }}]
    if name == LINK:
        mounts.extend([{"name": "flower-home", "mountPath": "/flower-home"},
                       {"name": "flower-config", "mountPath": "/flower-home/config.toml",
                        "subPath": "config.toml", "readOnly": True}])
        volumes.append({"name": "flower-home", "emptyDir": {}})
        volumes.append({"name": "flower-config", "configMap": {
            "name": FLOWER_HOME_CONFIG,
            "items": [{"key": "config.toml", "path": "config.toml"}],
        }})
    if result_volume:
        mounts.append({"name": "results", "mountPath": "/flower-results"})
        volumes.append({"name": "results", "emptyDir": {}})
    unit = container(
        "flower", image=image, imagePullPolicy="Never", command=command, args=args,
        env=[{"name": key, "value": value} for key, value in (env or {}).items()],
        volumeMounts=mounts,
        securityContext={"allowPrivilegeEscalation": False,
                         "capabilities": {"drop": ["ALL"]},
                         "runAsNonRoot": True,
                         "seccompProfile": {"type": "RuntimeDefault"}},
    )
    request = pod(name, [unit], automountServiceAccountToken=False, volumes=volumes,
                  securityContext={"runAsUser": 49999, "runAsGroup": 49999, "fsGroup": 49999})
    request["metadata"]["labels"] = {
        "fixture": LABEL,
        "flower-role": "superlink" if name == LINK else "supernode",
    }
    lab.create(request)


def start_flower(lab, images):
    create(lab, "ConfigMap", APP_CONFIG, immutable=True, data={
        "pyproject.toml": (HERE / "pyproject.toml").read_text(),
        "client_app.py": (HERE / "client_app.py").read_text(),
        "server_app.py": (HERE / "server_app.py").read_text(),
    })
    create(lab, "ConfigMap", FLOWER_HOME_CONFIG, immutable=True, data={
        "config.toml": "[superlink.fixture]\naddress = \"127.0.0.1:9093\"\ninsecure = true\n",
    })
    create_flower_pod(lab, LINK, images["superlink"]["image"], ["flower-superlink"], [
        "--insecure", "--isolation", "subprocess",
        "--control-api-address", "127.0.0.1:9093",
    ], result_volume=True,
       env={"SAF_FLOWER_RESULT_PATH": "/flower-results/result.json",
            "FLWR_HOME": "/flower-home"})
    create(lab, "Service", LINK_SERVICE, spec={
        "selector": {"flower-role": "superlink"},
        "ports": [{"name": "fleet", "port": 9092, "targetPort": 9092}],
    })
    for name, partition in ((NODE_A, "0"), (NODE_B, "1"), (NODE_C, "2")):
        create_flower_pod(lab, name, images["supernode"]["image"], ["flower-supernode"], [
            "--insecure", "--superlink", f"{LINK_SERVICE}:9092",
            "--node-config", f"partition-id={partition}",
            "--clientappio-api-address", "127.0.0.1:9094",
            "--isolation", "subprocess",
        ])
    for name in (LINK, NODE_A, NODE_B, NODE_C):
        ready(lab, name)

    # The 1.29 subprocess mode uses the parent environment. Check the two
    # direct Python imports required by the fixed app without retaining package
    # inventory or version output in the receipt.
    deps_ready = {}
    for name in (LINK, NODE_A, NODE_B, NODE_C):
        check = lab.kubectl(
            "exec", "pod/" + name, "--", "python", "-c",
            "import flwr, numpy; assert flwr.__version__ == '1.29.0'; print('deps-ok')",
            timeout=15, allow_failure=True,
        )
        deps_ready[name] = check.returncode == 0 and check.stdout.strip() == "deps-ok"

    # The in-pod CLI addresses only this case-owned SuperLink Control API through
    # loopback. No host port, external endpoint, kubeconfig, or API token is used.
    if not all(deps_ready.values()):
        lab.block("Flower 1.29.0 and NumPy must be available in all pinned runtime images")
    result = lab.kubectl("exec", "pod/" + LINK, "--", "sh", "-ec",
                         'work=$(mktemp -d); trap \'rm -rf "$work"\' EXIT; '
                         'cp /flowerapp/pyproject.toml /flowerapp/client_app.py '
                         '/flowerapp/server_app.py "$work/"; cd "$work"; flwr run . fixture --stream',
                         timeout=220, allow_failure=True)
    readback = lab.kubectl("exec", "pod/" + LINK, "--", "cat",
                           "/flower-results/result.json", timeout=20, allow_failure=True)
    try:
        report = json.loads(readback.stdout) if readback.returncode == 0 else {}
    except json.JSONDecodeError:
        report = {}
    aggregate = report.get("aggregate", [])
    expected = [3.5, 1.25]
    matches = len(aggregate) == 2 and all(abs(float(actual) - wanted) <= 0.001
                                          for actual, wanted in zip(aggregate, expected))
    allowed_result_keys = {
        "workflow", "round", "participant_result_count", "failure_count", "aggregate",
    }
    only_aggregate_receipt = set(report) == allowed_result_keys
    pods = json.loads(lab.kubectl("get", "pods", "-l", f"fixture={LABEL}", "-o", "json").stdout)
    exact_topology = {item["metadata"]["name"] for item in pods.get("items", [])} == {
        LINK, NODE_A, NODE_B, NODE_C
    }
    observed = {
        "flower_cli_completed": result.returncode == 0,
        "pinned_flower_and_numpy_available_in_all_subprocess_parents": all(deps_ready.values()),
        "case_owned_four_pod_topology": exact_topology,
        "protocol": report.get("workflow") == "SecAggPlusWorkflow",
        "one_round_three_client_results_no_failures": report.get("round") == 1
        and report.get("participant_result_count") == 3 and report.get("failure_count") == 0,
        "aggregate_matches_fixed_vector_mean": matches,
        "receipt_contains_aggregate_only_schema": only_aggregate_receipt,
    }
    if not all(observed.values()):
        for name in (LINK, NODE_A, NODE_B, NODE_C):
            lab.kubectl("logs", "pod/" + name, "--tail=60", timeout=20, allow_failure=True)
    lab.check("supplement", "Pinned Flower SecAgg+ completes one fixed-vector round",
              all(observed.values()), observed)
    (lab.evidence / "flower-secagg-plus-observations.json").write_text(json.dumps({
        "images": {key: {name: value[name] for name in (
            "source_index_sha256", "platform", "platform_manifest")}
                    for key, value in images.items()},
        "protocol_settings": {
            "num_shares": 1.0, "reconstruction_threshold": 1.0,
            "clipping_range": 8.0, "quantization_range": 65536,
            "modulus_range": 1073741824, "max_weight": 1.0,
            "timeout_seconds": 45, "rounds": 1, "participants": 3,
        },
        "observed": observed,
        "aggregate": aggregate if matches else [],
    }, sort_keys=True, indent=2) + "\n")

    # Delete only these exact resources. The disposable cluster remains the final
    # cleanup boundary if the fixture stops before this point.
    lab.kubectl("delete", "pod", LINK, NODE_A, NODE_B, NODE_C, "--wait=true", timeout=35)
    lab.kubectl("delete", "service", LINK_SERVICE, "--ignore-not-found=true", timeout=25)
    lab.kubectl("delete", "configmap", APP_CONFIG, "--ignore-not-found=true", timeout=25)
    lab.kubectl("delete", "configmap", FLOWER_HOME_CONFIG,
                 "--ignore-not-found=true", timeout=25)
    return readback.stdout if all(observed.values()) else None


def verify_approved_release(lab, base, raw):
    report_name, approval_name = "fixture-flower-closed-aggregate", "fixture-flower-release-approval"
    operation = ("release", "release-flower")
    digest = sha256(raw.encode()).hexdigest()
    create(lab, "ConfigMap", report_name, immutable=True, data={"report.json": raw})
    base.grant(lab, "fixture-flower-aggregate-release-reader", "release", [
        base.rule([report_name, approval_name], ["get"])
    ])
    unapproved = base.execute(lab, *operation)
    forbidden = base.execute(lab, "east", "observe", report_name)
    masked = base.execute(lab, "release", "observe", base.vector_share("east", "alpha"))
    unapproved_identity = base.execute(lab, "east", "release-flower")
    record = {"decision": "approved", "cohort-size": "3", "receipt-sha256": digest}
    create(lab, "ConfigMap", approval_name, immutable=True,
           data={**record, "receipt-sha256": "0" * 64})
    wrong_digest = base.execute(lab, *operation)
    lab.kubectl("delete", "configmap", approval_name, "--wait=true")
    create(lab, "ConfigMap", approval_name, immutable=True, data=record)
    approved = base.execute(lab, *operation)
    observed = {
        "release_refused_without_approval": unapproved == {"decision": "held", "reason": "approval-absent"},
        "wrong_digest_refused": wrong_digest == {"decision": "held", "reason": "approval-mismatch"},
        "unapproved_identity_refused": unapproved_identity == {"decision": "held", "reason": "identity"},
        "unapproved_service_account_cannot_read_aggregate": forbidden == {"status": 403},
        "release_identity_cannot_read_individual_share": masked == {"status": 403},
        "approved_exact_result_has_only_aggregate": approved == {
            "decision": "released", "contributors": 3, "aggregate": json.loads(raw)["aggregate"]},
    }
    lab.check("supplement", "Independent workload identity releases only the approved Flower aggregate",
              all(observed.values()), observed)


def run(lab):
    base = load_base()
    base.run(lab)
    raw = start_flower(lab, pin_images(lab))
    if raw is not None:
        verify_approved_release(lab, base, raw)
