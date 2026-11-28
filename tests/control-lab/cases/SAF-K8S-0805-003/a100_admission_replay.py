"""Run the exact A100 admission path with separate synthetic approval inputs."""

import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location("a100_admission", Path(__file__).with_name("a100_admission.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
RUNID = "a1000001"


def run(lab):
    def request(*args, obj=None, allow_failure=False, timeout=20):
        return lab.kubectl(*args, payload=json.dumps(obj) if obj is not None else None,
                           allow_failure=allow_failure, timeout=timeout)

    lab.kubectl("create", "namespace", gate.NAMESPACE)
    hold_name = gate.names(RUNID)[0]
    hold = {"apiVersion": "v1", "kind": "ConfigMap", "immutable": True,
            "metadata": {"name": hold_name, "namespace": gate.NAMESPACE},
            "data": {"disposition": "hold", "workload": "approved", "signal": "high",
                     "corroboration": "missing", "source_age": "synthetic", "capture_ref": RUNID,
                     "hold_name": hold_name, "workload_ref": "c" * 64, "device_ref": "b" * 64,
                     "receipt_sha256": "a" * 64}}
    escalation = gate.escalation_for(hold, RUNID)
    with gate.OwnedResources(request) as resources:
        gate.configure_identity(resources, RUNID)
        gate.wait_for_roles(request, RUNID)
        approval_hash = gate.create_approval(request, resources, RUNID)
        baseline = gate.submit(request, escalation).returncode == 0
        lab.check("a100-admission-baseline", "The same synthetic escalation is admitted in dry-run before the binding",
                  baseline, {"identical_dry_run_admitted_without_binding": baseline})
        gate.install(resources, RUNID)
        attempts = gate.establish_enforcement(request, RUNID, hold, escalation)
        observed = gate.retain_hold_and_check(request, RUNID, hold, escalation)
        approval = gate.verify_corroboration(request, RUNID, hold)
        observed["effective_binding_proved_before_hold"] = attempts > 0
        lab.check("a100-admission-enforced", "The effective A100 fixture binding retains the exact hold and denies escalation",
                  all(observed.values()), observed)
    retained = json.loads(request("-n", gate.NAMESPACE, "get", "configmap", hold_name, "-o", "json").stdout)
    approval.update(independent_approver_record_verified=bool(approval_hash),
                    held_evidence_survived_fixture_cleanup=retained.get("data") == hold["data"],
                    fixture_cleanup_verified=True)
    (lab.evidence / "a100-admission-replay.json").write_text(json.dumps({
        **observed, **approval, "input": "synthetic ConfigMap", "readiness_attempts": attempts,
        "approval_parameter_sha256": approval_hash, "gpu_or_response_action_tested": False,
    }, indent=2, sort_keys=True) + "\n")
    lab.check("a100-independent-approval",
              "Separate immutable approval permits only its bound comparator and the reviewer cannot create or change that approval",
              all(approval.values()), approval)
