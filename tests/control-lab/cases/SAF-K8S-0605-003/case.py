"""Verify signed Kubewarden WASM admission for an inert model resource."""
import hashlib
import json
from pathlib import Path
import platform
import time
from zipfile import ZipFile

HERE = Path(__file__).resolve().parent
CHART_RELEASES = (
    ("kubewarden-crds", "1.28.1", "f95f454db3451c3cfa2712796d7b04c8f09d3c31e913195d4c0c51f75ec30b3a"),
    ("kubewarden-controller", "5.14.1", "8f300296c83aeee98890a4923a6df1dbbfc0f05102e05e5e2f1e610bfdd1850e"),
    ("kubewarden-defaults", "3.14.1", "e65eb5fe0e4088af222c3e4a8624c862e67fb2b166252a445a545c535341a2a9"),
)
CHART_BASE = "https://github.com/kubewarden/helm-charts/releases/download"
KWCTL_BASE = "https://github.com/kubewarden/adm-controller/releases/download/v1.36.0"
KWCTL_ARCHIVES = {
    "darwin-aarch64": "7ea1fecf92b15e3611938c2825e9b95d60ed923eb082e4169bfc2accc9a9714c",
    "darwin-x86_64": "5418ff086d5228ea50630d22d445a6393aa4f6ebc55c71cb8e62534d5fa34611",
    "linux-aarch64": "2713b454f46932ce012e4d346676568aac741ca9bd37d66bec135845f92f6f55",
    "linux-x86_64": "1fc7100becc51249b8e519c0848981f75b96690aa5266ff74d67b74ff7c9f77b",
}
CONTROLLER_VERSION = "v1.36.0@sha256:fea974cc8451f47ced796aeffd4c668f8721a1921754eecdd1fcd0054ca382b8"
SERVER_VERSION = "v1.36.0@sha256:df2c157d0b25ad909f55669d2d22d3f3edfd68617d36fe3968a6c94cb9d5c4ad"
POLICY = "registry://ghcr.io/kubewarden/policies/safe-labels@sha256:1d7bd06e95e876ac92277af3b2ac3b3db6f61de5244a59399ca74b7a36c699da"
POLICY_NAME = "saf-model-labels"
POLICY_MESSAGE = "The following mandatory labels are missing: saf-k8s.example/approved"
API_GROUP = "ai.saf-k8s.example"
API_VERSION = "v1alpha1"
RESOURCE = "modeldeployments." + API_GROUP
NS = "saf-test"
OTHER = "saf-kubewarden-other"
KW_NS = "kubewarden"
LABEL = "saf-k8s.example/approved"
SIGNATURE_CONFIG = "saf-policy-signatures"

SCOPE = (
    "One disposable Kubernetes v1.36.1 Kind cluster, pinned Kubewarden v1.36.0, and "
    "one signature-checked released WASM policy operating on an inert namespaced "
    "ModelDeployment fixture. Covers a baseline, monitor and protect modes, CREATE "
    "and UPDATE, a permitted stored declaration and an unenrolled namespace. "
    "Custom policy authorship and production policy inventory are outside this fixture."
)


def retain(lab, name, data):
    (lab.evidence / (name + ".json")).write_text(json.dumps(data, indent=2) + "\n")


def resource(name, namespace=NS, approved=False):
    labels = {LABEL: "yes"} if approved else {}
    return {
        "apiVersion": f"{API_GROUP}/{API_VERSION}",
        "kind": "ModelDeployment",
        "metadata": {"name": name, "namespace": namespace, "labels": labels},
        "spec": {"model": "inert-fixture", "replicas": 0},
    }


def submit(lab, name, definition, *, dry_run=False):
    args = ["-n", definition["metadata"]["namespace"], "create", "-f", "-", "-o", "json"]
    if dry_run:
        args.append("--dry-run=server")
    response = lab.kubectl(*args, payload=json.dumps(definition), allow_failure=True)
    return capture(lab, name, response)


def capture(lab, name, response):
    observed = {"returncode": response.returncode, "stderr": response.stderr, "status": None}
    if response.returncode == 0:
        observed["status"] = json.loads(response.stdout)
    retain(lab, name, observed)
    return observed


def deployment(lab, name):
    lab.kubectl("-n", KW_NS, "rollout", "status", f"deployment/{name}",
                "--timeout=150s", timeout=160)
    return json.loads(lab.kubectl("-n", KW_NS, "get", "deployment", name, "-o", "json").stdout)


def download_checked(lab, url, path, expected):
    lab.command("curl", "--fail", "--silent", "--show-error", "--location",
                url, "-o", str(path), timeout=75)
    observed = hashlib.sha256(path.read_bytes()).hexdigest()
    if observed != expected:
        lab.block(f"{path.name} SHA256 differs from the reviewed release")
    return observed


def verify_policy_signature(lab):
    architecture = platform.machine().lower()
    architecture = {"arm64": "aarch64", "amd64": "x86_64"}.get(architecture, architecture)
    host = f"{platform.system().lower()}-{architecture}"
    expected = KWCTL_ARCHIVES.get(host)
    if expected is None:
        lab.block(f"No pinned Kubewarden v1.36.0 kwctl CLI asset for {host}")
    stem = f"kwctl-{host}"
    directory = lab.kubeconfig.parent
    archive = directory / (stem + ".zip")
    digest = download_checked(lab, f"{KWCTL_BASE}/{archive.name}", archive, expected)
    binary = directory / "kwctl"
    with ZipFile(archive) as upstream:
        binary.write_bytes(upstream.read(stem))
    binary.chmod(0o700)
    config = directory / "policy-registry-config"
    config.mkdir()
    (config / "config.json").write_text("{}\n")
    results = {}
    for owner in ("kubewarden", "saf-lab-untrusted-fixture"):
        response = lab.command(str(binary), "verify", "--docker-config-json-path", str(config),
                               "--github-owner", owner, POLICY, allow_failure=True, timeout=90)
        results[owner] = {"returncode": response.returncode,
                          "output": response.stdout + response.stderr}
    retain(lab, "policy-signature", {"module": POLICY, "cli_asset": archive.name,
                                    "cli_sha256": digest, "decisions": results})
    rejected = results["saf-lab-untrusted-fixture"]
    trusted = results["kubewarden"]
    lab.check("green", "Predeployment Sigstore verification accepts the exact module only for the trusted signer",
              trusted["returncode"] == 0 and "Policy successfully verified" in trusted["output"]
              and rejected["returncode"] != 0 and "constraints were not satisfied" in rejected["output"]
              and "owner: saf-lab-untrusted-fixture" in rejected["output"],
              {"module": POLICY, "trusted_signer_exit": trusted["returncode"],
               "mismatched_signer_exit": rejected["returncode"]})


def server_deployment_name(lab, server):
    deadline = time.monotonic() + 95
    while time.monotonic() < deadline:
        listing = lab.kubectl("-n", KW_NS, "get", "deployments", "-o", "json")
        matches = [
            item["metadata"]["name"] for item in json.loads(listing.stdout)["items"]
            if any(owner["kind"] == "PolicyServer" and owner["uid"] == server["metadata"]["uid"]
                   for owner in item["metadata"].get("ownerReferences", []))
        ]
        if len(matches) == 1:
            return matches[0]
        time.sleep(2)
    lab.block("Kubewarden controller did not reconcile one Deployment for the default PolicyServer")


def install_stack(lab):
    settings = {
        "kubewarden-crds": [],
        "kubewarden-controller": [
            "--set", "auditScanner.enable=false", "--set-string", "image.tag=" + CONTROLLER_VERSION,
        ],
        "kubewarden-defaults": [
            "--set-string", "policyServer.image.tag=" + SERVER_VERSION,
            "--set-string", "policyServer.verificationConfig=" + SIGNATURE_CONFIG,
        ],
    }
    verification = "apiVersion: v1\nallOf:\n  - kind: githubAction\n    owner: kubewarden\n"
    lab.kubectl("create", "namespace", KW_NS)
    lab.kubectl("-n", KW_NS, "create", "configmap", SIGNATURE_CONFIG,
                "--from-literal=verification-config=" + verification)
    observed_charts = {}
    for chart, version, digest in CHART_RELEASES:
        release = f"{chart}-{version}"
        archive = lab.kubeconfig.parent / f"{release}.tgz"
        observed = download_checked(lab, f"{CHART_BASE}/{release}/{archive.name}", archive, digest)
        observed_charts[chart] = {"version": version, "sha256": observed}
        lab.command("helm", "install", chart, str(archive), "--namespace", KW_NS,
                    "--kubeconfig", str(lab.kubeconfig), "--kube-context", f"kind-{lab.cluster}",
                    "--registry-config", str(lab.kubeconfig.parent / "helm-registry.json"),
                    "--wait", "--timeout", "180s", *settings[chart], timeout=190)
    controller = deployment(lab, "kubewarden-controller")
    config = json.loads(lab.kubectl("-n", KW_NS, "get", "configmap", SIGNATURE_CONFIG,
                                   "-o", "json").stdout)
    policy_server = json.loads(lab.kubectl("get", "policyserver", "default", "-o", "json").stdout)
    server_name = server_deployment_name(lab, policy_server)
    server = deployment(lab, server_name)
    spec = policy_server["spec"]
    images = {
        "controller": controller["spec"]["template"]["spec"]["containers"][0]["image"],
        "policy_server": server["spec"]["template"]["spec"]["containers"][0]["image"],
    }
    retain(lab, "installation", {
        "charts": observed_charts, "images": images, "signature_reference": spec.get("verificationConfig"),
        "verification_config": config["data"]["verification-config"],
    })
    lab.check("positive", "Kubewarden runs the pinned controller and PolicyServer with the signature requirement",
              images["controller"] == "ghcr.io/kubewarden/adm-controller/controller:" + CONTROLLER_VERSION
              and images["policy_server"] == "ghcr.io/kubewarden/adm-controller/policy-server:" + SERVER_VERSION
              and spec.get("verificationConfig") == SIGNATURE_CONFIG
              and config["data"]["verification-config"] == verification,
              {"charts": list(observed_charts), "images": images, "verification_owner": "kubewarden"})
    return server_name


def wait_policy(lab, mode):
    deadline = time.monotonic() + 140
    status = {}
    while time.monotonic() < deadline:
        response = lab.kubectl("get", "admissionpolicy", POLICY_NAME, "-o", "json")
        active = json.loads(response.stdout)
        status = active.get("status", {})
        if status.get("policyStatus") == "active" and status.get("mode") == mode:
            retain(lab, mode + "-policy", active)
            return active
        time.sleep(2)
    lab.block(f"AdmissionPolicy did not report active in {mode} mode: {status}")


def denied_by_policy(result):
    error = result["stderr"]
    return (result["returncode"] == 1 and POLICY_NAME in error
            and "admission webhook" in error and "denied the request" in error and POLICY_MESSAGE in error)


def run(lab):
    lab.kubectl("create", "namespace", OTHER)
    lab.apply(HERE / "modeldeployments.json")
    lab.kubectl("wait", "--for=condition=Established", "crd/" + RESOURCE, "--timeout=45s")
    invalid = resource("probe-unapproved")
    baseline = submit(lab, "baseline", invalid, dry_run=True)
    lab.check("red", "The same unapproved model declaration is accepted before installing Kubewarden",
              baseline["returncode"] == 0 and baseline["status"]["metadata"]["name"] == "probe-unapproved",
              {"returncode": baseline["returncode"]})

    verify_policy_signature(lab)
    server_name = install_stack(lab)
    policy = {
        "apiVersion": "policies.kubewarden.io/v1", "kind": "AdmissionPolicy",
        "metadata": {"name": POLICY_NAME, "namespace": NS},
        "spec": {
            "policyServer": "default", "module": POLICY, "mode": "monitor", "mutating": False,
            "rules": [{"apiGroups": [API_GROUP], "apiVersions": [API_VERSION],
                       "resources": ["modeldeployments"], "operations": ["CREATE", "UPDATE"]}],
            "settings": {"mandatory_labels": [LABEL]},
        },
    }
    lab.create(policy)
    active = wait_policy(lab, "monitor")
    deadline = time.monotonic() + 95
    monitor_logs = []
    while time.monotonic() < deadline:
        monitor = submit(lab, "monitor", invalid, dry_run=True)
        logs = lab.kubectl("-n", KW_NS, "logs", f"deployment/{server_name}", "--tail=120", allow_failure=True)
        monitor_logs = [line for line in logs.stdout.splitlines()
                        if "policy evaluation (monitor mode)" in line and POLICY_NAME in line
                        and POLICY_MESSAGE in line and "allowed: false" in line]
        if monitor["returncode"] == 0 and monitor_logs:
            break
        time.sleep(2)
    retain(lab, "monitor-decision", {"lines": monitor_logs})
    lab.check("positive", "Monitor records that the exact policy would deny while the API admits the request",
              monitor["returncode"] == 0 and bool(monitor_logs) and active["spec"]["module"] == POLICY
              and active["spec"]["policyServer"] == "default",
              {"mode": active["status"]["mode"], "returncode": monitor["returncode"],
               "module": POLICY, "would_deny_recorded": bool(monitor_logs)})

    lab.kubectl("patch", "admissionpolicy", POLICY_NAME, "--type=merge",
                "-p", '{"spec":{"mode":"protect"}}')
    protect = wait_policy(lab, "protect")
    deadline = time.monotonic() + 95
    while time.monotonic() < deadline:
        ready = submit(lab, "protect-readiness", invalid, dry_run=True)
        if denied_by_policy(ready):
            break
        time.sleep(2)
    else:
        lab.check("green", "The reconciled protect policy denies the readiness dry-run",
                  False, {"returncode": ready["returncode"], "error": ready["stderr"]})
    negative = submit(lab, "protect-denial", invalid)
    missing = lab.kubectl("get", RESOURCE, "probe-unapproved", "--ignore-not-found",
                          "-o", "name").stdout
    lab.check("green", "The active protect policy denies the exact request and the object stays absent",
              denied_by_policy(negative) and not missing and protect["spec"]["module"] == POLICY,
              {"mode": protect["status"]["mode"], "returncode": negative["returncode"], "error": negative["stderr"]})

    valid = submit(lab, "approved", resource("probe-approved", approved=True))
    current = json.loads(lab.kubectl("get", RESOURCE, "probe-approved", "-o", "json").stdout)
    retain(lab, "stored", current)
    lab.check("positive", "The approved declaration is persisted by the API",
              valid["returncode"] == 0 and current["metadata"]["uid"] == valid["status"]["metadata"]["uid"]
              and current["metadata"]["labels"][LABEL] == "yes",
              {"persisted": True, "label": current["metadata"]["labels"].get(LABEL)})

    update = lab.kubectl("label", RESOURCE, "probe-approved", LABEL + "-", allow_failure=True)
    # A denial lacks a response object. Retain the original kubectl message.
    observation = {"returncode": update.returncode, "stderr": update.stderr}
    retain(lab, "update-denial", observation)
    after = json.loads(lab.kubectl("get", RESOURCE, "probe-approved", "-o", "json").stdout)
    retain(lab, "stored-after-update", after)
    lab.check("green", "Removing the required label on UPDATE is denied and the stored object is preserved",
              denied_by_policy(observation) and after["metadata"]["uid"] == current["metadata"]["uid"]
              and after["metadata"]["labels"].get(LABEL) == "yes",
              {"returncode": update.returncode, "stored_label": after["metadata"]["labels"].get(LABEL)})

    other = submit(lab, "outside", resource("probe-unapproved", namespace=OTHER))
    lab.check("positive", "The same unapproved declaration is admitted in the unenrolled namespace",
              other["returncode"] == 0 and other["status"]["metadata"]["namespace"] == OTHER,
              {"returncode": other["returncode"], "namespace": OTHER})
