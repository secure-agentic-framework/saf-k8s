"""Read-only, allowlisted observations from the exact owned Kind node."""
import json
import subprocess

REQUIRED_POLICY = {
    "kubelet_anonymous_authentication": False,
    "kubelet_authorization_mode": "Webhook",
    "kubelet_read_only_port": 0,
    "containerd_systemd_cgroup": True,
    "os_id": "debian",
}


def _run(lab, argv, stage):
    try:
        result = subprocess.run(argv, env=lab.env, text=True, capture_output=True,
                                timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        lab.block(f"Read-only node baseline observation failed at {stage}")
    if result.returncode:
        lab.block(f"Read-only node baseline observation failed at {stage}")
    return result.stdout


def _kubelet_fields(config, kubelet_version):
    # Normalize only readOnlyPort's documented zero default, only for this exact
    # external configz schema and pinned kubelet release. Other missing fields fail.
    if kubelet_version != "v1.36.1":
        raise ValueError("versioned kubelet defaults cannot be applied")
    if config.get("apiVersion") != "kubelet.config.k8s.io/v1beta1" or config.get("kind") != "KubeletConfiguration":
        raise ValueError("unexpected kubelet configz schema identity")
    try:
        anonymous = config["authentication"]["anonymous"]["enabled"]
        authorization = config["authorization"]["mode"]
        if "readOnlyPort" in config:
            read_only_port = config["readOnlyPort"]
            defaulted = []
        else:
            read_only_port = 0
            defaulted = ["readOnlyPort"]
    except (KeyError, TypeError):
        raise ValueError("missing selected effective kubelet configz field")
    if type(anonymous) is not bool or not isinstance(authorization, str) or type(read_only_port) is not int:
        raise ValueError("selected effective kubelet configz field has unexpected type")
    return {
        "kubelet_anonymous_authentication": anonymous,
        "kubelet_authorization_mode": authorization,
        "kubelet_read_only_port": read_only_port,
        "kubelet_omitted_zero_defaults_normalized": defaulted,
    }


def _read_only_listener_count(text):
    count = 0
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4 or parts[3] != "0A":
            continue
        try:
            port = int(parts[1].rsplit(":", 1)[1], 16)
        except (ValueError, IndexError):
            raise ValueError("malformed kernel socket row")
        if port == 10255:
            count += 1
    return count


def _cri_runc_systemd_cgroup(info):
    try:
        containerd = info["config"]["containerd"]
        default_name = containerd["defaultRuntimeName"]
        runc = containerd["runtimes"]["runc"]
        runtime_type = runc["runtimeType"]
        value = runc["options"]["SystemdCgroup"]
    except (KeyError, TypeError):
        raise ValueError("CRI info lacks exact default runc runtime options")
    if (default_name != "runc" or runtime_type != "io.containerd.runc.v2"
            or type(value) is not bool):
        raise ValueError("CRI info default runc identity or SystemdCgroup type is unexpected")
    return value


def _os_fields(text):
    fields = {}
    for line in text.splitlines():
        if line.startswith(("ID=", "VERSION_ID=")):
            key, value = line.split("=", 1)
            if key in fields:
                raise ValueError("duplicate OS release field")
            fields[key] = value.strip().strip("\"'")
    if set(fields) != {"ID", "VERSION_ID"} or not all(fields.values()):
        raise ValueError("missing selected OS release field")
    return {"os_id": fields["ID"], "os_version_id": fields["VERSION_ID"]}


def collect(lab, node):
    # `kind get nodes` and Docker labels bind the read-only probes to this invocation's
    # single owned node. Never enumerate arbitrary containers or host paths.
    nodes = lab.command("kind", "get", "nodes", "--name", lab.cluster).stdout.splitlines()
    expected_name = f"{lab.cluster}-control-plane"
    if nodes != [expected_name]:
        lab.block("Owned single-node Kind identity did not match the observed Kubernetes node")
    meta = lab.command(
        "docker", "inspect", "--format",
        '{{index .Config.Labels "io.x-k8s.kind.cluster"}}|{{.Name}}', expected_name,
    ).stdout.strip()
    if meta != f"{lab.cluster}|/{expected_name}" or node.get("name") != expected_name:
        lab.block("Docker node identity did not match the observed Kubernetes node")

    configz_path = f"/api/v1/nodes/{node['name']}/proxy/configz"
    configz_text = _run(lab, ["kubectl", "--kubeconfig", str(lab.kubeconfig),
                              "--context", f"kind-{lab.cluster}", "get", "--raw", configz_path],
                         "kubelet_configz_query")
    try:
        configz = json.loads(configz_text)
        kubelet_config = configz.get("kubeletconfig")
        if not isinstance(kubelet_config, dict):
            raise ValueError("kubelet configz response lacks kubeletconfig")
        observed = _kubelet_fields(kubelet_config, node.get("kubelet_version"))
        # CRI info queries the running containerd over its existing local socket.
        # Root is used only inside this disposable Kind node container to access that socket.
        runtime_info_text = _run(lab, ["docker", "exec", expected_name,
                                       "crictl", "--runtime-endpoint=unix:///run/containerd/containerd.sock",
                                       "info", "-o", "json"], "containerd_cri_info")
        try:
            runtime_info = json.loads(runtime_info_text)
        except ValueError:
            raise ValueError("containerd CRI info JSON was malformed")
        observed["containerd_systemd_cgroup"] = _cri_runc_systemd_cgroup(runtime_info)
        os_release = _run(lab, ["docker", "exec", "--user", "65534:65534", expected_name,
                                "cat", "/etc/os-release"], "os_release")
        observed.update(_os_fields(os_release))
        socket_tables = _run(lab, ["docker", "exec", "--user", "65534:65534", expected_name,
                                   "sh", "-c", "cat /proc/net/tcp /proc/net/tcp6"],
                             "kubelet_read_only_listener_probe")
        observed["kubelet_read_only_listener_count"] = _read_only_listener_count(socket_tables)
    except ValueError as error:
        lab.block(f"Selected node baseline field unavailable or ambiguous: {error}")
    current = json.loads(lab.kubectl("get", "node", node["name"], "-o", "json").stdout)
    if current.get("metadata", {}).get("uid") != node.get("uid"):
        lab.block("Observed Kubernetes node UID changed during read-only baseline measurement")
    return {"node_name": node["name"], "node_uid": node["uid"], "fields": observed}


def decide(measurement, expected_node_uid):
    if not measurement.get("node_uid") or measurement.get("node_uid") != expected_node_uid:
        return False
    fields = measurement.get("fields")
    allowed = set(REQUIRED_POLICY) | {
        "os_version_id", "kubelet_read_only_listener_count",
        "kubelet_omitted_zero_defaults_normalized",
    }
    if not isinstance(fields, dict) or set(fields) != allowed or not fields.get("os_version_id"):
        return False
    if fields.get("kubelet_read_only_listener_count") != 0:
        return False
    defaulted = fields.get("kubelet_omitted_zero_defaults_normalized")
    if defaulted not in ([], ["readOnlyPort"]):
        return False
    if defaulted and fields.get("kubelet_read_only_port") != 0:
        return False
    if type(fields.get("kubelet_anonymous_authentication")) is not bool:
        return False
    if type(fields.get("kubelet_read_only_port")) is not int:
        return False
    return all(fields.get(key) == expected for key, expected in REQUIRED_POLICY.items())
