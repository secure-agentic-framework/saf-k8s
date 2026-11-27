"""Build and run the bounded CPU collective using the local pinned wheel set."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


def _load(name, path):
    spec = spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("required pinned fixture module is unavailable")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(lab, case_dir):
    case_dir = Path(case_dir)
    runtime_path = case_dir / "gloo_runtime.py"
    runtime = _load("saf_0901_002_gloo_runtime", runtime_path)
    image, provenance = runtime.build_and_import(lab)
    collective = _load("saf_0901_002_gloo_collective", case_dir / "gloo_collective.py")
    collective.run(lab, case_dir, image, provenance)
