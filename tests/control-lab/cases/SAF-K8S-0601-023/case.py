"""Reference case: preserve 0601-023 and add verified private pull rotation."""
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load reviewed source module: {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


BASE = _load("saf_0601_023_base", HERE / "base_case.py")
COMPANION = _load("saf_0601_022_private_pull", HERE.parent / "SAF-K8S-0601-022" / "case.py")
ROTATION = _load("saf_0601_023_rotation", HERE / "rotation.py")

SCOPE = (
    "One disposable Kind namespace. Preserve 0601-023's scheduled CronJob marker and "
    "live ConfigMap propagation checks. Reuse 0601-022's case-owned registry, wrong and "
    "correct initial credential checks, and pinned ESO provider. Add one synthetic "
    "credential rotation, Periodic ESO Secret refresh, retired-value registry denial, "
    "and one new exact-digest Kubernetes image pull. No provider-wide expiry or "
    "production credential behavior is inferred."
)


def run(lab):
    BASE.run(lab)
    if not hasattr(COMPANION, "PrivatePullFixture"):
        lab.block("The verified 0601-022 companion with rotation lifecycle support is required")
    COMPANION.run_private_pull_checks(
        lab, on_pull_verified=lambda context: ROTATION.rotate_and_verify(lab, COMPANION, context))
