"""Verify runtime timeout and restrict unverified streaming paths."""
import importlib.util
from pathlib import Path

SCOPE = ("Containerd port-forward idle timing and namespace RBAC restrictions on "
         "routine exec and attach, with each stream path measured independently.")


def run(lab):
    spec = importlib.util.spec_from_file_location(
        "stream_runtime", Path(__file__).with_name("runtime_case.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.run_profile(lab, {"port-forward"}, ("exec", "attach"))
