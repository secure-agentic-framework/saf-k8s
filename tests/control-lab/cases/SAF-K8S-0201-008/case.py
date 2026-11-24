"""Verify ownership and mode with selected live and synthetic kubelet file evidence."""
import json
from pathlib import Path, PurePosixPath


HERE = Path(__file__).parent
KIND_CONFIG = HERE / "kind.yaml"
NODE_IMAGE = "kindest/node:v1.34.8@sha256:02722c2dedddcfc00febf5d27fbeb9b7b2c14294c82109ff4a85d89ac9ba3256"
SCANNER = ("docker.io/aquasec/kube-bench:v0.16.0@sha256:"
           "75506f222d1eb6ce2a751a5533bdc0a3b54c898e2e49e7751d0ee22cfb862679")
PROFILE = "cis-1.12"
CONFIG = "/var/lib/kubelet/config.yaml"
KUBECONFIG = "/etc/kubernetes/kubelet.conf"
PKI = PurePosixPath("/var/lib/kubelet/pki")
CHECKS = {"4.1.5": "PASS", "4.1.6": "PASS", "4.1.9": "PASS", "4.1.10": "PASS"}
BASELINE = {check: "FAIL" if check != "4.1.10" else status for check, status in CHECKS.items()}
SCOPE = (
    "Disposable Kind v1.34.8 control-plane and worker nodes, with the pinned kube-bench "
    "CIS 1.12 node profile. Verify the running kubelet's configured path, live config mode "
    "before and after tightening, synthetic kubeconfig mode and owner changes, and metadata "
    "for the untouched live kubeconfig, bootstrap path and stock client-key symlink. "
    "Adopter guidance covers other distributions, ACLs, node coverage and provider evidence."
)


def prepare_kind(lab, temporary):
    profile = temporary / "kubelet-files.yaml"
    profile.write_bytes(KIND_CONFIG.read_bytes())
    return profile


def get(lab, *args):
    return json.loads(lab.kubectl("get", *args, "-o", "json").stdout)


def node_command(lab, node, *args, **options):
    return lab.command("docker", "exec", node, *args, **options).stdout.strip()


def effective_paths(lab, node):
    # Consume only the three selected path arguments in the node. The full command
    # line stays out of the log.
    script = r"""
        pid=$(systemctl show kubelet.service --property MainPID --value)
        test "${pid:-0}" -gt 0
        tr '\000' '\n' < "/proc/$pid/cmdline" | awk '
            function flag(s) { return s ~ /^--(bootstrap-kubeconfig|kubeconfig|config)$/ }
            want { print key "|" $0; want=0; next }
            flag($0) { key=substr($0, 3); want=1; next }
            index($0, "=") {
                i=index($0, "="); arg=substr($0, 1, i-1)
                if (flag(arg)) print substr(arg, 3) "|" substr($0, i+1)
            }
        '
    """
    fields = [line.split("|", 1) for line in node_command(lab, node, "sh", "-ec", script).splitlines()]
    paths = dict(fields)
    if (len(fields) != len(paths) or paths.get("config") != CONFIG
            or paths.get("kubeconfig") != KUBECONFIG
            or paths.get("bootstrap-kubeconfig") != "/etc/kubernetes/bootstrap-kubelet.conf"):
        lab.block("The selected scanner mounts must match the running kubelet's exact fixture paths")
    return paths


def metadata(lab, node, path):
    output = node_command(lab, node, "stat", "-c", "%F|%a|%u|%g|%d|%i", "--", str(path))
    kind, mode, uid, gid, device, inode = output.split("|")
    return {"type": kind, "mode": mode, "uid": uid, "gid": gid, "device": device, "inode": inode}


def private_file(record):
    return (record["type"] in {"regular file", "regular empty file"}
            and record["uid"] == record["gid"] == "0"
            and bool(int(record["mode"], 8) & 0o400)
            and not (int(record["mode"], 8) & ~0o600))


def file_identity(record):
    return record["device"], record["inode"], record["type"]


def scan(lab, name, node, config, synthetic_kubeconfig):
    sources = {"active-config": (config, CONFIG), "marker-kubeconfig": (synthetic_kubeconfig, KUBECONFIG)}
    spec = {
        "nodeName": node, "restartPolicy": "Never", "automountServiceAccountToken": False,
        "containers": [{
            "name": "scanner", "image": SCANNER,
            "command": ["kube-bench", "run", "--benchmark", PROFILE, "--targets", "node",
                        "--check", ",".join(CHECKS), "--json", "--noremediations"],
            "volumeMounts": [{"name": name, "mountPath": target, "readOnly": True}
                             for name, (_, target) in sources.items()],
            "securityContext": {"runAsUser": 0, "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]},
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                          "limits": {"cpu": "250m", "memory": "96Mi"}},
        }],
        "volumes": [{"name": name, "hostPath": {"path": source, "type": "File"}}
                    for name, (source, _) in sources.items()],
    }
    job = lab.create({"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
                      "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 65, "template": {"spec": spec}}})
    lab.kubectl("wait", "--for=condition=Complete", f"job/{name}", "--timeout=73s", timeout=80)
    pod, = get(lab, "pods", "-l", f"batch.kubernetes.io/job-name={name}")["items"]
    status, = pod["status"]["containerStatuses"]
    report, = [json.loads(line) for line in lab.kubectl("logs", f"job/{name}").stdout.splitlines()
               if line.startswith('{"Controls":')]
    section, = report["Controls"]
    results = [row for group in section["tests"] for row in group["results"]]
    selected = {row["test_number"]: row["status"] for row in results}
    job_uid = job["metadata"]["uid"]
    if (section["version"] != PROFILE or section["node_type"] != "node"
            or len(results) != len(CHECKS) or selected.keys() != CHECKS.keys()
            or pod["spec"]["nodeName"] != node or status["state"]["terminated"]["exitCode"] != 0
            or not status["imageID"]
            or not any(ref["uid"] == job_uid and ref.get("controller")
                       for ref in pod["metadata"]["ownerReferences"])):
        lab.block("Scan evidence must identify exactly these checks on the intended node and Job")
    return {"checks": selected, "job_uid": job_uid, "pod_uid": pod["metadata"]["uid"],
            "scanner_image_id": status["imageID"]}


def exercise_node(lab, role):
    node = f"{lab.cluster}-{role}"
    paths = effective_paths(lab, node)
    current = get(lab, "node", node)
    config = metadata(lab, node, paths["config"])
    kubeconfig = metadata(lab, node, paths["kubeconfig"])
    if config["type"] != "regular file" or config["uid"] != "0" or config["gid"] != "0":
        lab.block("Expected the stock regular root-owned kubelet configuration before tightening")
    root = node_command(lab, node, "mktemp", "-d", "/tmp/saf-kubelet-file-proof.XXXXXXXX")
    marker = f"{root}/kubelet.conf"
    node_command(lab, node, "install", "-m", "0644", "-o", "65534", "-g", "65534", "/dev/null", marker)
    marker_before = metadata(lab, node, marker)
    before = scan(lab, f"{role}-file-baseline", node, paths["config"], marker)
    lab.check("red", f"{role} scanner rejects broad live config mode and the unsafe synthetic kubeconfig",
              before["checks"] == BASELINE and config["mode"] == "644"
              and marker_before["mode"] == "644" and marker_before["uid"] == marker_before["gid"] == "65534",
              {"checks": before["checks"], "live_config_mode": config["mode"],
               "synthetic_wrong_owner_rejected": before["checks"]["4.1.6"] == "FAIL"})

    # The real kubeconfig only receives stat; all credential-file mutations target the empty marker.
    node_command(lab, node, "chmod", "0600", "--", paths["config"])
    node_command(lab, node, "chmod", "0600", "--", marker)
    node_command(lab, node, "chown", "0:0", "--", marker)
    config_after = metadata(lab, node, paths["config"])
    marker_after = metadata(lab, node, marker)
    after = scan(lab, f"{role}-file-retest", node, paths["config"], marker)
    same_files = (file_identity(config) == file_identity(config_after)
                  and file_identity(marker_before) == file_identity(marker_after))
    fresh_scan = (before["job_uid"] != after["job_uid"] and before["pod_uid"] != after["pod_uid"]
                  and before["scanner_image_id"] == after["scanner_image_id"])
    lab.check("green", f"{role} fresh scan passes on the exact corrected files",
              same_files and fresh_scan and after["checks"] == CHECKS and private_file(config_after)
              and private_file(marker_after),
              {"live_config_private": private_file(config_after),
               "synthetic_kubeconfig_private": private_file(marker_after),
               "config_and_fixture_identity_preserved": same_files, "separate_scan": fresh_scan,
               "checks": after["checks"]})

    client_link = PKI / "kubelet-client-current.pem"
    link_info = metadata(lab, node, client_link)
    target = PurePosixPath(node_command(lab, node, "readlink", "-e", "--", str(client_link)))
    if not target.is_relative_to(PKI) or target == client_link:
        lab.block("The rotating client credential must resolve to the owned fixture's certificate directory")
    target_info = metadata(lab, node, target)
    parent = metadata(lab, node, PKI)
    bootstrap_absent = node_command(
        lab, node, "sh", "-ec", 'test ! -e "$1" && test ! -L "$1" && printf absent',
        "saf-bootstrap", paths["bootstrap-kubeconfig"], allow_failure=True,
    ) == "absent"
    final = get(lab, "node", node)
    ready = any(row["type"] == "Ready" and row["status"] == "True" for row in final["status"]["conditions"])
    same_node = current["metadata"]["uid"] == final["metadata"]["uid"]
    untouched_kubeconfig = private_file(kubeconfig) and kubeconfig == metadata(lab, node, paths["kubeconfig"])
    protected_directory = (parent["type"] == "directory" and parent["uid"] == parent["gid"] == "0"
                           and not (int(parent["mode"], 8) & 0o022))
    protected_link = (link_info["type"] == "symbolic link" and link_info["uid"] == link_info["gid"] == "0"
                      and protected_directory and private_file(target_info))
    lab.check("positive", f"{role} stays Ready with unchanged private kubeconfig and a protected client-key target",
              ready and same_node and untouched_kubeconfig and protected_link and bootstrap_absent,
              {"node_ready_and_unchanged": ready and same_node, "private_kubeconfig_unchanged": untouched_kubeconfig,
               "protected_client_link_and_target": protected_link, "enrolled_bootstrap_file_absent": bootstrap_absent})
    return {"node_uid": current["metadata"]["uid"], "effective_paths": paths,
            "live_config_before": config, "live_config_after": config_after, "live_kubeconfig": kubeconfig,
            "rotation_link": link_info, "rotation_target": str(target), "rotation_target_metadata": target_info,
            "rotation_directory": parent, "synthetic_kubeconfig_before": marker_before,
            "synthetic_kubeconfig_after": marker_after, "before": before, "after": after,
            "bootstrap_absent": bootstrap_absent, "ready": ready}


def run(lab):
    server = json.loads(lab.kubectl("get", "--raw=/version").stdout)["gitVersion"]
    if server != "v1.34.8":
        lab.block("The pinned CIS 1.12 example requires Kubernetes v1.34.8")
    nodes = {role: exercise_node(lab, role) for role in ("control-plane", "worker")}
    (lab.evidence / "kubelet-file-metadata.raw.json").write_text(
        json.dumps({"profile": PROFILE, "server": server, "nodes": nodes}, indent=2) + "\n")
