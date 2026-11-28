"""Run the owned A100 admission fixture using an inert input record on Kind."""

import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location("a100_admission", Path(__file__).with_name("a100_admission.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
RUNID = "a1000001"


def run(lab):
    def request(*args, obj=None, allow_failure=False):
        return lab.kubectl("-n", gate.NAMESPACE, *args,
                           payload=json.dumps(obj) if obj is not None else None,
                           allow_failure=allow_failure)

    lab.kubectl("create", "namespace", gate.NAMESPACE)
    gate.configure_identity(request, RUNID)
    hold = {"apiVersion": "v1", "kind": "ConfigMap", "immutable": True,
            "metadata": {"name": gate.names(RUNID)[0], "namespace": gate.NAMESPACE},
            "data": {"disposition": "hold", "workload": "approved", "signal": "high",
                     "corroboration": "missing", "source_age": "synthetic",
                     "receipt_sha256": "a" * 64}}
    escalation = gate.escalation_for(hold, RUNID)
    baseline = gate.submit(request, escalation).returncode == 0
    lab.check("a100-admission-baseline", "The same synthetic escalation is admitted in dry-run before the binding",
              baseline, {"identical_dry_run_admitted_without_binding": baseline})
    gate.install(request, RUNID)
    attempts = gate.establish_enforcement(request, RUNID, hold, escalation)
    observed = gate.retain_hold_and_check(request, RUNID, hold, escalation)

    corroborated = gate.escalation_for(hold, RUNID)
    corroborated["data"].update(workload="unapproved", corroboration="verified-independent")
    observed["corroborated_comparator_dry_run_admitted"] = gate.submit(request, corroborated).returncode == 0
    observed["effective_binding_proved_before_hold"] = attempts > 0
    (lab.evidence / "a100-admission-replay.json").write_text(json.dumps({
        **observed, "input": "synthetic ConfigMap", "readiness_attempts": attempts,
        "gpu_or_response_action_tested": False,
    }, indent=2, sort_keys=True) + "\n")
    lab.check("a100-admission-enforced", "The effective A100 fixture binding retains the exact hold and denies escalation",
              all(observed.values()), observed)
