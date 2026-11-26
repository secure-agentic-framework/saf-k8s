"""Install and verify the pinned Volcano runtime on the owned Kind cluster."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAMESPACE = "volcano-system"
DEPLOYMENTS = ("volcano-admission", "volcano-controllers", "volcano-scheduler")
CRDS = {"jobs.batch.volcano.sh": "v1alpha1",
        "podgroups.scheduling.volcano.sh": "v1beta1",
        "queues.scheduling.volcano.sh": "v1beta1"}



def _json(lab, *args):
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def _bundle(lab, pins):
    url = ("https://raw.githubusercontent.com/volcano-sh/volcano/" + pins["commit"]
           + "/installer/volcano-development.yaml")
    upstream = lab.kubeconfig.parent / "volcano-upstream.yaml"
    lab.command("curl", "--proto", "=https", "-fLSs", "--max-time", "45", url,
                "-o", str(upstream), timeout=55)
    source = upstream.read_bytes()
    actual = hashlib.sha256(source).hexdigest()
    if actual != pins["manifest_sha256"]:
        lab.block(f"Pinned Volcano installer bytes differed: {actual}")
    text = source.decode("utf-8")
    for reference, digests in pins["images"].items():
        line = "image: " + reference + "\n"
        wanted_count = 2 if "/vc-webhook-manager:" in reference else 1
        if text.count(line) != wanted_count:
            lab.block(f"Unexpected references for the pinned Volcano image {reference}")
        text = text.replace(line, line.rstrip() + "@" + digests["index"] + "\n")
    original_plugin = "- name: proportion\n"
    if text.count(original_plugin) != 1:
        lab.block("The pinned installer does not have the expected proportion plugin")
    text = text.replace(original_plugin, "- name: capacity\n")
    path = lab.kubeconfig.parent / "volcano-pinned.yaml"
    path.write_text(text)
    return path, url, actual


def _component(lab, selector, expected_by_image, architecture, completed=False):
    pods = _json(lab, "-n", NAMESPACE, "get", "pods", "-l", selector)["items"]
    if len(pods) != 1:
        lab.block(f"Expected one Volcano fixture Pod for {selector}, saw {len(pods)}")
    pod, = pods
    container, = pod["spec"]["containers"]
    statuses = pod["status"].get("containerStatuses", [])
    if len(statuses) != 1 or statuses[0].get("name") != container["name"]:
        lab.block(f"The pinned Volcano fixture Pod has no matching runtime image status: {selector}")
    observed = statuses[0].get("imageID", "")
    pin = expected_by_image.get(container["image"])
    valid_id = pin is not None and observed.rsplit("@", 1)[-1].split("://")[-1] in {
        pin["index"], pin["linux"][architecture], pin["config"][architecture],
    }
    phase = pod["status"].get("phase")
    ready = any(condition.get("type") == "Ready" and condition.get("status") == "True"
                for condition in pod["status"].get("conditions", []))
    installed = (phase == "Succeeded") if completed else (phase == "Running" and ready)
    return {"selector": selector, "pod_uid": pod["metadata"]["uid"],
            "pod_name": pod["metadata"]["name"], "container": container["name"],
            "declared_image": container["image"], "observed_image_id": observed,
            "node": pod["spec"]["nodeName"], "phase": phase, "ready": ready,
            "pinned_image_matches": valid_id, "installation_observed": installed}


def run(lab):
    pins = json.loads((HERE / "volcano-release-pins.json").read_text())
    path, url, actual = _bundle(lab, pins)
    lab.kubectl("-n", NAMESPACE, "apply", "--server-side", "-f", str(path), timeout=150)
    for name in CRDS:
        lab.kubectl("wait", "--for=condition=Established", "crd/" + name,
                    "--timeout=75s", timeout=85)
    lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Complete", "job/volcano-admission-init",
                "--timeout=210s", timeout=220)
    for deployment in DEPLOYMENTS:
        lab.kubectl("-n", NAMESPACE, "rollout", "status", "deployment/" + deployment,
                    "--timeout=180s", timeout=190)
    deployments = {name: _json(lab, "-n", NAMESPACE, "get", "deployment", name)
                   for name in DEPLOYMENTS}
    spec_selectors = {name: ",".join(f"{key}={value}" for key, value in
                      deployment["spec"]["selector"]["matchLabels"].items())
                      for name, deployment in deployments.items()}
    init_name = "volcano-admission-init"
    init_job = _json(lab, "-n", NAMESPACE, "get", "job", init_name)
    spec_selectors[init_name] = ",".join(f"{key}={value}" for key, value in
                                         init_job["spec"]["selector"]["matchLabels"].items())
    version = _json(lab, "version")["serverVersion"]["gitVersion"]
    node, = _json(lab, "get", "nodes")["items"]
    architecture = node["status"]["nodeInfo"]["architecture"]
    if architecture not in {"amd64", "arm64"}:
        lab.block(f"The pinned Volcano fixture has no Linux image for {architecture}")
    expected_by_image = {ref + "@" + pin["index"]: pin for ref, pin in pins["images"].items()}
    components = {name: _component(lab, selector, expected_by_image, architecture, completed=name == init_name)
                  for name, selector in spec_selectors.items()}
    crds = {name: _json(lab, "get", "crd", name) for name in CRDS}
    api_versions_match = all(any(v["name"] == expected and v["served"] and v["storage"]
                                 for v in crds[name]["spec"]["versions"])
                             for name, expected in CRDS.items())
    config = _json(lab, "-n", NAMESPACE, "get", "configmap", "volcano-scheduler-configmap")
    live_config = config["data"]["volcano-scheduler.conf"]
    config_matches = ('actions: "enqueue, allocate, backfill"' in live_config
                      and "- name: capacity" in live_config
                      and "- name: gang" in live_config and "- name: proportion" not in live_config)
    images_match = all(value["pinned_image_matches"] and value["installation_observed"]
                       for value in components.values())
    scope = {"release": pins["ref"], "commit": pins["commit"], "source_url": url,
             "upstream_sha256": actual, "installed_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
             "images": pins["images"], "components": components, "apiserver": version,
             "node_architecture": architecture,
             "crd_versions": {name: [{"name": v["name"], "served": v["served"], "storage": v["storage"]}
                                     for v in doc["spec"]["versions"]] for name, doc in crds.items()}}
    (lab.evidence / "volcano-install.json").write_text(json.dumps(scope, indent=2, sort_keys=True) + "\n")
    config_evidence = {"configmap": config, "scheduler": components["volcano-scheduler"],
                       "deployment_revision": deployments["volcano-scheduler"]["metadata"]
                       .get("annotations", {}).get("deployment.kubernetes.io/revision")}
    (lab.evidence / "volcano-scheduler-config.json").write_text(
        json.dumps(config_evidence, indent=2, sort_keys=True) + "\n")
    lab.check("positive", "The pinned Volcano components run with the declared gang and capacity scheduler configuration",
              api_versions_match and config_matches and images_match,
              {"release": pins["ref"], "established_api_versions_match": api_versions_match,
               "live_configuration_matches": config_matches, "component_image_ids_match": images_match})
