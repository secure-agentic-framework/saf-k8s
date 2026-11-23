"""Run the case's device and node containment checks on the patched image."""
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import time

LOCAL_NODE_VERSION = "v1.37.2"
SCOPE = (
    "Disposable Kind v1.37.2 cluster. The pinned upstream mock DRA driver "
    "provides two inert devices. Exercises authorized device containment, "
    "continued service on the other allocation, and the existing isolated "
    "node scheduling and pod disruption budget checks. No real accelerator, "
    "production workload, vendor backport, or incident process is exercised."
)


def load_fixture(name):
    spec = spec_from_file_location(name, Path(__file__).with_name(f"{name}.py"))
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(lab):
    lab.apply(Path(__file__).with_name("mock-driver.yaml"))
    lab.kubectl("rollout", "status", "daemonset/saf-dra-dra-example-driver-kubeletplugin",
                "--timeout=125s", timeout=135)
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        slices = json.loads(lab.kubectl("get", "resourceslices", "-o", "json").stdout)
        devices = {device["name"] for row in slices["items"]
                   if row["spec"]["driver"] == "gpu.example.com"
                   for device in row["spec"]["devices"]}
        if len(devices) == 2:
            break
        time.sleep(1)
    else:
        lab.kubectl("logs", "daemonset/saf-dra-dra-example-driver-kubeletplugin",
                    "--tail=50", allow_failure=True)
        lab.block("Mock driver did not publish two distinct devices")
    load_fixture("device").run(lab)
    load_fixture("case").run(lab)
