"""Verify targeted native Audit events and recurring drift detection."""
import json
from pathlib import Path
from runpy import run_path

ROOT = Path(__file__).resolve().parent
GUEST = run_path(str(ROOT / "audit_fixtures.py"))
SCOPE = (
    "Kind checks kubelet path types through metadata only. A separate mount-free Debian guest "
    "loads the prescribed persistent rules, demonstrates rule drift and recovery under a "
    "systemd timer, and records attribution for harmless read and write events."
)
FIXTURE_PATHS = {
    "kubelet_config": ("-s", "/var/lib/kubelet/config.yaml"),
    "kubeconfig": ("-s", "/etc/kubernetes/kubelet.conf"),
    "pki_directory": ("-d", "/var/lib/kubelet/pki"),
}


def run(lab):
    node = f"{lab.cluster}-control-plane"
    paths = {
        field: lab.command("docker", "exec", node, "test", flag, path,
                           allow_failure=True, timeout=15).returncode == 0
        for field, (flag, path) in FIXTURE_PATHS.items()
    }
    lab.check("positive", "The disposable Kubernetes node has the expected kubelet path types",
              all(paths.values()), paths)
    observed = GUEST["observe_guest"](lab)
    events = observed["events"]
    baseline = {name: observed.get(name) is True for name in ("baseline_unwatched", "collector_canary_logged")}
    lab.check("red", "Unwatched accesses have no marker events while a successful daemon canary is captured",
              all(baseline.values()), baseline)
    platform = observed["platform"]
    pinned = platform["package"] == GUEST["AUDITD_PACKAGE"] and bool(platform["kernel"])
    lab.check("positive", "The guest runs the pinned audit package with a recorded architecture and kernel",
              pinned and platform["architecture"] in {"aarch64", "x86_64"},
              {"pinned_audit_package": pinned, "platform_identified": bool(platform["architecture"])})
    recurrence = observed["recurrence"]
    initial, drift, restored = (recurrence[key] for key in ("initial", "drift", "restored"))
    independent = len({row["invocation"] for row in (initial, drift, restored)}) == 3
    ordered = initial["sequence"] < drift["sequence"] < restored["sequence"]
    lab.check("red", "A later timer invocation identifies the exact configured watch removed from the loaded rules",
              independent and ordered and initial["missing"] == 0 and drift["missing"] == 1
              and drift["kind"] == "kubeconfig",
              {"distinct_ordered_invocations": independent and ordered,
               "selected_kubeconfig_rule_missing": drift["kind"] == "kubeconfig" and drift["missing"] == 1})
    lab.check("green", "Reloading the persistent rules restores coverage on a new timer invocation",
              ordered and restored["missing"] == 0 and recurrence["restored_from_persistent_source"],
              {"persistent_source_reloaded": recurrence["restored_from_persistent_source"],
               "loaded_watch_set_restored": restored["missing"] == 0})
    intended = {(kind, op) for kind in ("config", "kubeconfig", "pki") for op in ("read", "write")}
    intended.add(("heartbeat", "write"))
    actual = {(event["kind"], event["operation"]) for event in events if event["success"]}
    all_events = actual == intended and len({str(event["serial"]) for event in events}) == len(intended)
    lab.check("green", "Native audit serials and syscall access modes identify all successful marker events",
              all_events and observed["no_audit_loss"],
              {"attributable_marker_event_count": len(actual), "unique_event_serials": all_events,
               "no_audit_loss": observed["no_audit_loss"]})
    lab.check("positive", "The owned rules are removed and the isolated guest is deleted",
              observed["rules_removed"] and observed["guest_deleted"],
              {"rules_removed": observed["rules_removed"], "guest_deleted": observed["guest_deleted"]})
    (lab.evidence / "native-audit-recurrence.json").write_text(json.dumps(observed, indent=2) + "\n")
