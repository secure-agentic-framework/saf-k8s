"""Exercise SPO reconciliation, namespace binding and versioned profiles in owned Kind."""
from hashlib import sha256
import json
from time import monotonic, sleep

import yaml

from fixtures import BUSYBOX_IMAGE, container, pod

NAMESPACE = "saf-spo-bound"
COMPARISON = "saf-spo-unbound"
SYSTEM = "security-profiles-operator"
PROFILE_API = "security-profiles-operator.x-k8s.io/v1"
PROFILE_RESOURCE = "seccompprofiles.security-profiles-operator.x-k8s.io"
RELEASES = (
    ("cert-manager", "https://github.com/cert-manager/cert-manager/releases/download/v1.21.2/cert-manager.yaml",
     "e03b668ec8675214af6b0a671699d088f2601fa3878e0dbe1b41d3feafd1879f"),
    (SYSTEM, "https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/v1.1.0/deploy/operator.yaml",
     "525bab0d4f268c30ad72ded683fdbd42b2a8d7c338b215d2dc898e9e132ef89b"),
)
IMAGE_PINS = {
    "quay.io/jetstack/cert-manager-controller:v1.21.2": "sha256:70f532fd9cfde0b09d55687200942399d89838bc2d5d5b45152eb799a15912b8",
    "quay.io/jetstack/cert-manager-webhook:v1.21.2": "sha256:a60e2dac46dbb8a7f3df95c54ce941012f54c2fe022f0ee55aaa1ab40ed957ae",
    "quay.io/jetstack/cert-manager-cainjector:v1.21.2": "sha256:c85268c64f2e0e76684bf5fe8906caff34b82523561c6affe0fae3546bd87562",
    "registry.k8s.io/security-profiles-operator/security-profiles-operator:v1.1.0": "sha256:beb927d0d1bd784857a457bb78e889341ebef2a33bbfb393d99e9dd1cb48dc82",
}
BASE_CALLS = (
    "access", "arch_prctl", "brk", "clock_gettime", "clock_nanosleep", "close", "execve",
    "exit", "exit_group", "faccessat", "faccessat2", "fcntl", "fstat", "fstatfs", "futex", "getcwd",
    "getdents64", "getegid", "geteuid", "getgid", "getpid", "getrandom", "getrlimit", "getuid",
    "ioctl", "lseek", "mmap", "mprotect", "munmap", "nanosleep", "newfstatat", "openat", "pread64",
    "prctl", "prlimit64", "read", "readlink", "readlinkat", "rseq", "rt_sigaction", "rt_sigprocmask",
    "rt_sigreturn", "set_robust_list", "set_tid_address", "sigaltstack", "stat", "statx", "wait4", "write", "writev",
)


def get(lab, *args):
    return json.loads(lab.kubectl("get", *args, "-o", "json", timeout=20).stdout)


def cluster_kubectl(lab, *args, **kwargs):
    return lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig),
                       "--context", f"kind-{lab.cluster}", *args, **kwargs)


def create_workload(lab, obj, *, dry_run=False):
    flags = ["--dry-run=server"] if dry_run else []
    return cluster_kubectl(lab, "create", "-f", "-", "-o", "json", *flags,
                           payload=json.dumps(obj), timeout=26, allow_failure=dry_run)


def install(lab):
    for namespace, url, digest in RELEASES:
        original = lab.kubeconfig.with_name(f"{namespace}-upstream.yaml")
        lab.command("curl", "-fsSL", "--max-time", "75", url, "-o", str(original), timeout=80)
        asset = original.read_bytes()
        if sha256(asset).hexdigest() != digest:
            lab.block(f"Official {namespace} asset does not match the reviewed SHA-256")
        docs = [item for item in yaml.load_all(asset, Loader=yaml.CSafeLoader) if item]
        for item in docs:
            if item["kind"] != "Deployment":
                continue
            template = item["spec"]["template"]["spec"]
            item["spec"]["replicas"] = 1
            for spec in template.get("initContainers", []) + template["containers"]:
                image = spec["image"]
                spec["image"] = f"{image}@{IMAGE_PINS[image]}"
                spec["imagePullPolicy"] = "IfNotPresent"
        rendered = original.with_name(f"{namespace}-reviewed.yaml")
        rendered.write_text(yaml.dump_all(docs, Dumper=yaml.CSafeDumper, sort_keys=False))
        cluster_kubectl(lab, "apply", "--server-side", "-f", str(rendered), timeout=115)
        for item in docs:
            if item["kind"] == "Deployment":
                rollout(lab, namespace, f"deployment/{item['metadata']['name']}")
    deadline = monotonic() + 75
    while monotonic() < deadline:
        state = get(lab, "daemonsets", "-n", SYSTEM)
        names = [item["metadata"]["name"] for item in state["items"]]
        if "spod" in names:
            rollout(lab, SYSTEM, "daemonset/spod")
            return
        sleep(2)
    lab.block("The installed Security Profiles Operator did not create its node daemon")


def rollout(lab, namespace, resource):
    state = lab.kubectl("rollout", "status", resource, "-n", namespace, "--timeout=180s",
                        timeout=190, allow_failure=True)
    if state.returncode:
        lab.kubectl("get", "pods", "-n", namespace, "-o", "wide", allow_failure=True, timeout=20)
        lab.kubectl("describe", resource, "-n", namespace, allow_failure=True, timeout=20)
        lab.block(f"{resource} did not become ready in the fixture namespace {namespace}")


def namespace(lab, name, binding):
    labels = {f"pod-security.kubernetes.io/{level}{suffix}": setting
              for level in ("enforce", "audit", "warn")
              for suffix, setting in (("", "restricted"), ("-version", "v1.36"))}
    if binding:
        labels["spo.x-k8s.io/enable-binding"] = ""
    lab.create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name, "labels": labels}})


def install_profile(lab, name, arch, allow_uname=False):
    calls = sorted(BASE_CALLS + (("uname",) if allow_uname else ()))
    lab.create({"apiVersion": PROFILE_API, "kind": "SeccompProfile", "metadata": {"name": name},
                "spec": {"defaultAction": "SCMP_ACT_ERRNO", "architectures": [arch],
                         "syscalls": [{"action": "SCMP_ACT_ALLOW", "names": calls}]}})
    deadline = monotonic() + 90
    while monotonic() < deadline:
        result = get(lab, PROFILE_RESOURCE, name)
        status = result.get("status") or {}
        if status.get("status") == "Installed" and status.get("localhostProfile"):
            selected = status["localhostProfile"]
            if selected != f"operator/{name}.json":
                lab.block(f"SPO returned an unexpected status profile path for {name}")
            return selected
        sleep(2)
    lab.block(f"The dedicated node never reported operator profile {name} Installed")


def configure_binding(lab, name):
    binding = {"apiVersion": PROFILE_API, "kind": "ProfileBinding",
               "metadata": {"name": "fixture-binding", "namespace": NAMESPACE},
               "spec": {"image": BUSYBOX_IMAGE, "profileRef": {"kind": "SeccompProfile", "name": name}}}
    cluster_kubectl(lab, "apply", "--server-side", "-f", "-", payload=json.dumps(binding), timeout=30)


def workload(name, namespace_name, keep_running=False):
    resources = {"requests": {"cpu": "10m", "memory": "16Mi"},
                 "limits": {"cpu": "100m", "memory": "32Mi"}}
    probe = container("app", command=["/bin/busybox", "uname", "-s"], resources=resources)
    containers = [probe]
    if keep_running:
        keeper = container("keeper", command=["/bin/busybox", "sleep", "120"], resources=resources)
        writer = container("writer", command=["/bin/busybox", "echo", "fixture-io-ok"], resources=resources)
        containers.extend((keeper, writer))
    result = pod(name, containers, automountServiceAccountToken=False, activeDeadlineSeconds=150)
    result["metadata"]["namespace"] = namespace_name
    return result


def effective(pod_object):
    profile = pod_object["spec"]["containers"][0]["securityContext"]["seccompProfile"]
    return profile.get("type"), profile.get("localhostProfile")


def wait_binding(lab, obj, selected):
    deadline = monotonic() + 45
    while monotonic() < deadline:
        preview = create_workload(lab, obj, dry_run=True)
        if preview.returncode == 0 and effective(json.loads(preview.stdout)) == ("Localhost", selected):
            return
        sleep(1)
    lab.block(f"The operator webhook did not bind the approved profile for {obj['metadata']['name']}")


def observe(lab, obj, should_run):
    meta = obj["metadata"]
    expected_phase = "Running" if should_run else "Succeeded"
    deadline = monotonic() + 55
    while monotonic() < deadline:
        result = get(lab, "pod", meta["name"], "-n", meta["namespace"])
        status = result.get("status", {})
        phase = status.get("phase")
        states = {row["name"]: row.get("state", {}) for row in status.get("containerStatuses") or []}
        terminated = states.get("app", {}).get("terminated") or {}
        keeper_running = bool(states.get("keeper", {}).get("running"))
        writer_done = "exitCode" in (states.get("writer", {}).get("terminated") or {})
        if phase == expected_phase and "exitCode" in terminated and (not should_run or (keeper_running and writer_done)):
            logs = lab.kubectl("logs", meta["name"], "-n", meta["namespace"], "-c", "app", timeout=20)
            return result, terminated["exitCode"], logs.stdout.strip()
        if phase == "Failed":
            break
        sleep(1)
    lab.kubectl("logs", meta["name"], "-n", meta["namespace"], "-c", "app", allow_failure=True, timeout=15)
    lab.kubectl("describe", "pod", meta["name"], "-n", meta["namespace"], allow_failure=True, timeout=20)
    lab.block(f"Fixture Pod {meta['name']} did not reach {expected_phase} with a completed probe")


def run(lab):
    install(lab)
    namespace(lab, NAMESPACE, binding=True)
    namespace(lab, COMPARISON, binding=False)
    nodes = get(lab, "nodes")["items"]
    supported = {"arm64": "SCMP_ARCH_AARCH64", "amd64": "SCMP_ARCH_X86_64"}
    arch = supported.get(nodes[0]["status"]["nodeInfo"]["architecture"]) if len(nodes) == 1 else None
    if arch is None:
        lab.block("The SPO fixture requires one supported arm64 or amd64 Kind node")
    first, second = "saf-busybox-allowlist-v1", "saf-busybox-allowlist-v2"
    first_path = install_profile(lab, first, arch)
    configure_binding(lab, first)
    unbound = workload("spo-unbound", COMPARISON)
    create_workload(lab, unbound)
    unbound_state, unbound_rc, unbound_output = observe(lab, unbound, False)
    unbound_ok = unbound_rc == 0 and unbound_output == "Linux" and effective(unbound_state) == ("RuntimeDefault", None)
    lab.check("red", "The same workload outside the binding namespace keeps RuntimeDefault and permits the harmless call",
              unbound_ok, {"unbound_runtime_default": effective(unbound_state) == ("RuntimeDefault", None),
                           "harmless_call_allowed": unbound_rc == 0 and unbound_output == "Linux"})
    v1 = workload("spo-v1", NAMESPACE, keep_running=True)
    wait_binding(lab, v1, first_path)
    create_workload(lab, v1)
    v1_state, v1_rc, v1_output = observe(lab, v1, True)
    first_bound = effective(v1_state) == ("Localhost", first_path)
    writer_result = lab.kubectl("logs", "spo-v1", "-n", NAMESPACE, "-c", "writer", timeout=20)
    writer_spec, = [item for item in v1_state["spec"]["containers"] if item["name"] == "writer"]
    writer_profile = writer_spec["securityContext"]["seccompProfile"]
    independent_write = (writer_result.stdout.strip() == "fixture-io-ok"
                         and writer_profile.get("localhostProfile") == first_path)
    # BusyBox uname omits the name on failure and returns success. The same
    # profile can write output, and the v2 arm changes only the uname rule.
    system_name_withheld = v1_rc == 0 and v1_output == ""
    lab.check("green", "The bound v1 profile withholds the system name and still permits ordinary output",
              first_bound and system_name_withheld and independent_write,
              {"operator_reported_installed": True, "v1_bound": first_bound,
               "uname_output_withheld": system_name_withheld, "ordinary_output_allowed": independent_write})
    second_path = install_profile(lab, second, arch, allow_uname=True)
    configure_binding(lab, second)
    v2 = workload("spo-v2", NAMESPACE)
    wait_binding(lab, v2, second_path)
    create_workload(lab, v2)
    v2_state, v2_rc, v2_output = observe(lab, v2, False)
    old = get(lab, "pod", "spo-v1", "-n", NAMESPACE)
    previous_retained = old.get("status", {}).get("phase") == "Running" and effective(old) == ("Localhost", first_path)
    new_selected = effective(v2_state) == ("Localhost", second_path)
    permitted = v2_rc == 0 and v2_output == "Linux"
    lab.check("positive", "Updating the namespace binding selects v2 for a new workload while its running predecessor retains v1",
              previous_retained and new_selected and permitted,
              {"operator_reported_installed": True, "old_pod_kept_v1": previous_retained,
               "new_pod_bound_to_v2": new_selected, "new_profile_permitted_call": permitted})
