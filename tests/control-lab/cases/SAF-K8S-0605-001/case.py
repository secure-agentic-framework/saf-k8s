"""Exercise Gatekeeper GPU-request and RuntimeClass admission in a Kind fixture."""
from hashlib import sha256
import json
import platform
import runpy
import shutil
import tarfile
from pathlib import Path
import time
from urllib.request import urlopen

from fixtures import container, pod

HERE = Path(__file__).resolve().parent
VERSION = "v3.23.1"
INSTALL = "https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.23.1/deploy/gatekeeper.yaml"
INSTALL_SHA = "3c178abe6de4dcdcd2810c2945468a0d7a15ccf0036e324b73308643e94d6f72"
DIGESTS = {
    "amd64": "989b6950e220290f5439a8a338526f330fed2d3f086a11410df733ebbbca8b31",
    "arm64": "8578c23032d996ac5b6475c7bf6bf48c99ecef6ec34889c5177436b07d91eb51",
}
GATOR_ARCHIVES = {
    ("darwin", "amd64"): "4318b3ce4bc115ed861ff4a1df26ad1ddf3ae0c7907f20caac85affd400af39e",
    ("darwin", "arm64"): "dc96df4a0bad0427b36d2b10473801528ca5bdb00f2addb34d17bb7d706ed99b",
    ("linux", "amd64"): "c268d7b809c9fe59a110ab0bf7c296ab00b0b6c894c209cd15e94194590291bb",
    ("linux", "arm64"): "2d4bd0e28e708c2893a66fdca652f1d775b23fc5a3c07571fd314ba06d19ff2b",
}
NAMESPACE = "saf-0605-001-ai"
COMPARISON = "saf-0605-001-comparison"
CONSTRAINT = "saf-gpu-admission"
RESOURCE = "safgpuadmission.constraints.gatekeeper.sh"
GPU = "nvidia.com/gpu"
CAP_DENIAL = "GPU requests 3 exceed fixture maximum 2"
RUNTIME_DENIAL = "GPU Pods require RuntimeClass saf-gpu"
SCOPE = (
    "Kubernetes v1.36.1 and digest-pinned Gatekeeper v3.23.1. A Rego ConstraintTemplate "
    "and namespace-selected constraint check aggregate regular-container requests for nvidia.com/gpu "
    "and require an approved RuntimeClass for those Pods. A real denied CREATE, actual "
    "approved persistence, audit of an existing violation, and a namespace comparison "
    "are observed. Fixture classes use runc and synthetic GPU resources. The extension checks init and sidecar accounting and TrainJob declarations. The same cluster runs the signed-image admission comparison."
)


def gator_verify(lab, cases):
    systems = platform.system().lower(), platform.machine().lower()
    operating_system, hardware = systems
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(hardware, hardware)
    digest = GATOR_ARCHIVES.get((operating_system, arch))
    if not digest:
        lab.block(f"No pinned Gator release for {operating_system}/{arch}")
    filename = f"gator-{VERSION}-{operating_system}-{arch}.tar.gz"
    origin = f"https://github.com/open-policy-agent/gatekeeper/releases/download/{VERSION}/{filename}"
    directory = lab.kubeconfig.parent / "gator"
    directory.mkdir()
    local_archive = directory / filename
    lab.command("curl", "-fsSL", origin, "-o", str(local_archive), timeout=90)
    if sha256(local_archive.read_bytes()).hexdigest() != digest:
        lab.block("Gator archive bytes differ from the verified release digest")
    binary = directory / "gator"
    with tarfile.open(local_archive, "r:gz") as archive:
        matches = [member for member in archive.getmembers()
                   if member.isfile() and Path(member.name).name == "gator"]
        if len(matches) != 1:
            lab.block("Could not identify the pinned Gator executable")
        binary.write_bytes(archive.extractfile(matches[0]).read())
    binary.chmod(0o700)
    for filename in ("constraint-template.yaml", "constraint.yaml"):
        shutil.copyfile(HERE / filename, directory / filename)
    suite_cases = []
    for name, definition, message in cases:
        fixture_path = directory / f"{name}.yaml"
        fixture_path.write_text(json.dumps(definition))
        assertion = {"violations": 0} if message is None else {"violations": 1, "message": message}
        suite_cases.append({"name": name, "object": fixture_path.name, "assertions": [assertion]})
    suite = {"apiVersion": "test.gatekeeper.sh/v1alpha1", "kind": "Suite", "tests": [{
        "name": "gpu-requests-and-runtime", "template": "constraint-template.yaml",
        "constraint": "constraint.yaml", "cases": suite_cases,
    }]}
    suite_file = directory / "suite.yaml"
    suite_file.write_text(json.dumps(suite))
    result = lab.command(str(binary), "verify", "--verbose", str(suite_file), timeout=50, allow_failure=True)
    combined = result.stdout + result.stderr
    (lab.evidence / "gator-verification.txt").write_text(combined)
    expected = [name for name, _, _ in cases]
    checked = [name for name in expected if name in combined]
    lab.check("positive", "The pinned Gator suite passes its exact offline checks before policy deployment",
              result.returncode == 0 and expected == checked,
              {"release": VERSION, "suite_cases": checked, "exit_code": result.returncode})


    return binary


def install_gatekeeper(lab):
    with urlopen(INSTALL, timeout=30) as response:
        source = response.read(1024 * 1024)
    if sha256(source).hexdigest() != INSTALL_SHA:
        lab.block("Upstream Gatekeeper manifest does not match the checked release bytes")
    node = f"node/{lab.cluster}-control-plane"
    arch = lab.kubectl("get", node, "-o", "jsonpath={.status.nodeInfo.architecture}").stdout.strip()
    if arch not in DIGESTS:
        lab.block(f"No verified Gatekeeper runtime digest for {arch}")
    reference = f"docker.io/openpolicyagent/gatekeeper:{VERSION}@sha256:{DIGESTS[arch]}"
    staged = f"saf-gatekeeper-fixture:{lab.cluster}"
    present = lab.command("docker", "image", "inspect", reference, "--format", "{{.Id}}", allow_failure=True)
    if present.returncode:
        lab.command("docker", "pull", reference, timeout=180)
    lab.command("docker", "tag", reference, staged)
    try:
        lab.command("kind", "load", "docker-image", "--name", lab.cluster, staged, timeout=120)
    finally:
        lab.command("docker", "image", "rm", staged)
    text = source.decode()
    raw_image = f"image: openpolicyagent/gatekeeper:{VERSION}"
    if text.count(raw_image) != 2 or text.count("- --operation=audit") != 1 or text.count("replicas: 3") != 1:
        lab.block("Upstream Gatekeeper manifest layout differs from the reviewed release")
    text = text.replace(raw_image + "\n        imagePullPolicy: Always",
                        f"image: {staged}\n        imagePullPolicy: Never")
    text = text.replace("- --operation=audit", "- --operation=audit\n        - --audit-interval=8")
    text = text.replace("replicas: 3", "replicas: 1")
    lab.kubectl("-n", "gatekeeper-system", "apply", "-f", "-", payload=text, timeout=85)
    # Gatekeeper can create its initial mount before the rotator publishes the certificate.
    deadline = time.monotonic() + 70
    while time.monotonic() < deadline:
        cert = lab.kubectl("-n", "gatekeeper-system", "get", "secret", "gatekeeper-webhook-server-cert",
                           "-o", 'go-template={{with .data}}{{if index . "tls.crt"}}ready{{end}}{{end}}',
                           allow_failure=True)
        if cert.returncode == 0 and cert.stdout.strip() == "ready":
            break
        time.sleep(1)
    else:
        lab.block("Gatekeeper did not provision its webhook certificate")
    lab.kubectl("-n", "gatekeeper-system", "rollout", "restart", "deployment/gatekeeper-controller-manager")
    for deployment in ("gatekeeper-controller-manager", "gatekeeper-audit"):
        lab.kubectl("-n", "gatekeeper-system", "rollout", "status",
                    f"deployment/{deployment}", "--timeout=105s", timeout=115)
    deployments = json.loads(lab.kubectl("-n", "gatekeeper-system", "get", "deployments", "-o", "json").stdout)
    stable = {
        "release": VERSION,
        "installer_sha256": INSTALL_SHA,
        "repository": "docker.io/openpolicyagent/gatekeeper",
        "deployments": sorted(item["metadata"]["name"] for item in deployments["items"]),
        "all_use_digest_staged_copy": all(
            c["image"] == staged for item in deployments["items"]
            for c in item["spec"]["template"]["spec"]["containers"]),
    }
    (lab.evidence / "gatekeeper-version.json").write_text(json.dumps(stable | {"reference": reference}, indent=2) + "\n")
    lab.check("positive", "The actual Gatekeeper admission and audit deployments use the digest-staged release",
              stable["all_use_digest_staged_copy"]
              and stable["deployments"] == ["gatekeeper-audit", "gatekeeper-controller-manager"], stable)


def runtime_class(lab, name):
    lab.create({"apiVersion": "node.k8s.io/v1", "kind": "RuntimeClass",
                "metadata": {"name": name}, "handler": "runc"})


def fixture(name, counts, runtime="saf-gpu", namespace=NAMESPACE):
    containers = []
    for number, value in enumerate(counts):
        extended = {GPU: str(value)} if value else {}
        containers.append(container(f"fixture-{number}", resources={"requests": extended, "limits": extended}))
    definition = pod(name, containers, automountServiceAccountToken=False)
    definition["metadata"]["namespace"] = namespace
    if runtime:
        definition["spec"]["runtimeClassName"] = runtime
    return definition


def submit(lab, definition, dry_run=False):
    namespace = definition["metadata"]["namespace"]
    args = ["-n", namespace, "create", "-f", "-", "-o", "json"]
    if dry_run:
        args.append("--dry-run=server")
    return lab.kubectl(*args, payload=json.dumps(definition), allow_failure=True)


def expect_denied(result, message):
    return result.returncode == 1 and CONSTRAINT in result.stderr and message in result.stderr


def record_api(lab, label, result):
    (lab.evidence / f"{label}-api.json").write_text(json.dumps({
        "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
    }, indent=2) + "\n")


def run(lab):
    for ns in (NAMESPACE, COMPARISON):
        lab.kubectl("create", "namespace", ns)
    for name in ("saf-gpu", "saf-ordinary"):
        runtime_class(lab, name)
    budget = fixture("probe-budget", (1, 2))
    wrong_runtime = fixture("probe-runtime", (1,), "saf-ordinary")
    absent_runtime = fixture("probe-missing-runtime", (1,), None)
    for label, definition in (("baseline-budget", budget), ("baseline-runtime", wrong_runtime)):
        before = submit(lab, definition, dry_run=True)
        record_api(lab, label, before)
        lab.check("red", "The API admits the baseline declaration before the Gatekeeper constraint",
                  before.returncode == 0, {"probe": label, "returncode": before.returncode})
    existing = submit(lab, fixture("existing-excess", (1, 2)))
    if existing.returncode:
        lab.block("The pre-policy violation fixture did not persist")

    gator = gator_verify(lab, (
        ("checks-aggregate-budget", budget, CAP_DENIAL),
        ("checks-wrong-runtime", wrong_runtime, RUNTIME_DENIAL),
        ("checks-missing-runtime", absent_runtime, RUNTIME_DENIAL),
        ("checks-approved", fixture("probe-approved", (1, 1)), None),
        ("checks-cpu-only", fixture("cpu-only", (0,), "saf-ordinary"), None),
        ("checks-other-namespace", fixture("scope-comparison", (1, 2), "saf-ordinary", COMPARISON), None),
    ))
    install_gatekeeper(lab)
    lab.kubectl("apply", "-f", str(HERE / "constraint-template.yaml"))
    lab.kubectl("wait", "--for=create", f"crd/{RESOURCE}", "--timeout=55s", timeout=65)
    lab.kubectl("wait", "--for=condition=Established", f"crd/{RESOURCE}", "--timeout=55s", timeout=65)
    lab.kubectl("apply", "-f", str(HERE / "constraint.yaml"))
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if expect_denied(submit(lab, budget, dry_run=True), CAP_DENIAL):
            break
        time.sleep(0.5)
    else:
        lab.block("Gatekeeper never returned the expected budget policy denial")

    for label, definition, reason in (
        ("aggregate-budget", budget, CAP_DENIAL),
        ("wrong-runtime", wrong_runtime, RUNTIME_DENIAL),
        ("missing-runtime", absent_runtime, RUNTIME_DENIAL),
    ):
        rejected = submit(lab, definition)
        record_api(lab, label, rejected)
        lookup = lab.kubectl("-n", NAMESPACE, "get", "pod", definition["metadata"]["name"],
                             "--ignore-not-found", "-o", "name").stdout
        lab.check("green", "The named Gatekeeper constraint denies the exact violating Pod create",
                  expect_denied(rejected, reason) and not lookup.strip(),
                  {"probe": label, "reason": reason, "denied": expect_denied(rejected, reason),
                   "absent_from_storage": not lookup.strip()})

    approved = fixture("probe-approved", (1, 1))
    accepted = submit(lab, approved)
    record_api(lab, "approved", accepted)
    stored = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pod", "probe-approved", "-o", "json").stdout)
    requests = [c["resources"]["requests"].get(GPU) for c in stored["spec"]["containers"]]
    lab.check("positive", "An at-budget Pod with the approved RuntimeClass persists",
              accepted.returncode == 0 and stored["spec"]["runtimeClassName"] == "saf-gpu" and requests == ["1", "1"],
              {"returncode": accepted.returncode, "runtime": stored["spec"]["runtimeClassName"],
               "gpu_requests": requests})

    cpu = submit(lab, fixture("cpu-only", (0,), "saf-ordinary"), dry_run=True)
    outside = submit(lab, fixture("scope-comparison", (1, 2), "saf-ordinary", COMPARISON), dry_run=True)
    lab.check("positive", "CPU-only and other-namespace comparators remain admissible",
              cpu.returncode == outside.returncode == 0,
              {"cpu_only": cpu.returncode, "different_namespace": outside.returncode})

    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        raw = json.loads(lab.kubectl("get", RESOURCE, CONSTRAINT, "-o", "json").stdout)
        selected = [{"kind": row["kind"], "name": row["name"], "namespace": row["namespace"],
                     "message": row["message"]} for row in raw.get("status", {}).get("violations", [])]
        if any(row["name"] == "existing-excess" for row in selected):
            break
        time.sleep(1)
    expected = [{"kind": "Pod", "name": "existing-excess", "namespace": NAMESPACE, "message": CAP_DENIAL}]
    (lab.evidence / "gatekeeper-audit.json").write_text(json.dumps(raw, indent=2) + "\n")
    lab.check("green", "Gatekeeper audit reports the pre-existing violation with its precise reason",
              selected == expected, {"violations": selected})

    advanced = runpy.run_path(str(HERE / "advanced" / "case.py"))
    advanced["run"](lab, gator)
    sibling = HERE.parent / "SAF-K8S-0605-002" / "case.py"
    runpy.run_path(str(sibling))["run"](lab)
