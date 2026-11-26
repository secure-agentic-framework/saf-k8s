"""Verify native namespace quota admission and tenant/admin authorization."""
import json
import runpy
import time
from pathlib import Path


HERE = Path(__file__).parent
NAMESPACE = "saf-0901-006"
TENANT = "saf-0901-006-tenant"
PLATFORM = "saf-0901-006-platform"
PROBE = "saf-0901-006-probe"
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
NODE_IMAGE = (
    "kindest/node:v1.36.1@sha256:"
    "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
)
QUOTA_NAME = "saf-0901-006-tenant-quota"
SCOPE = (
    "A disposable Kind v1.36.1 cluster verifies native namespace quota, selected tenant "
    "and platform RBAC, and the pinned Kueue v0.17.7 controller's quota, readiness-timeout, "
    "and named tenant workload-priority behavior. A case-owned timeout Job's exact "
    "Workload UID and raw requeue state are captured before foreground cleanup because "
    "the pinned controller has a global PodsReady gate. Separate CPU-only LocalQueues "
    "demonstrate sampled historical-use ordering with Admission Fair Sharing enabled: "
    "with equal live priorities and sufficient quota after release, the newer lower-use "
    "Workload is admitted first. A distinct ClusterQueue explicitly disables Admission "
    "Fair Sharing and uses StrictFIFO; it observes the exact 100m seed admitted, Ready, "
    "and completed in its queue while the peer remains unseeded, then observes the older "
    "of two equal-priority, seed-matched candidates admitted first after release. These "
    "are bounded CPU-only scheduler observations. A third isolated Kueue ClusterQueue enables only within-queue LowerPriority "
    "preemption; it observes a 100m victim's eviction by a higher-priority Job and recovery of the same victim Job with a "
    "replacement Ready Pod after exact preemptor Job, Workload and owned Pod cleanup. A separate Volcano v1.16.1 "
    "fixture verifies the exact controller and scheduler inputs, scoped authorization and a two-worker CPU group "
    "held below its Queue capacity requirement and admitted after capacity is raised. Accelerator quotas, "
    "representative workload demand and adopted deployments remain distinct evidence requirements."
)


def probe_pod(service_account, name=PROBE):
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "labels": {
                "saf-k8s.example/control": "SAF-K8S-0901-006",
                "saf-k8s.example/fixture": "synthetic-only",
            },
        },
        "spec": {
            "serviceAccountName": service_account,
            "automountServiceAccountToken": True,
            "restartPolicy": "Always",
            "containers": [{
                "name": "probe",
                "image": IMAGE,
                "command": ["python", "-c", "import time; time.sleep(3600)"],
                "resources": {
                    "requests": {"cpu": "50m", "memory": "32Mi"},
                },
                "volumeMounts": [{
                    "name": "probe-source", "mountPath": "/fixture", "readOnly": True,
                }],
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                    "runAsNonRoot": True,
                    "runAsUser": 65534,
                    "readOnlyRootFilesystem": True,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
            }],
            "volumes": [{
                "name": "probe-source",
                "configMap": {"name": "saf-0901-006-probe"},
            }],
        },
    }


def run_probe(lab, operation, pod_name=PROBE):
    result = lab.kubectl(
        "-n", NAMESPACE, "exec", pod_name, "--", "python", "/fixture/probe.py", operation,
    )
    return json.loads(result.stdout)


def run(lab):
    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("-n", NAMESPACE, "apply", "-f", str(HERE / "fixtures" / "access.yaml"))
    probe_map = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "saf-0901-006-probe", "namespace": NAMESPACE,
                     "annotations": {"saf-k8s.example/fixture": "synthetic-only"}},
        "data": {"probe.py": (HERE / "fixtures" / "probe.py").read_text()},
    }
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-", payload=json.dumps(probe_map))
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-",
                payload=json.dumps(probe_pod(TENANT)))
    lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{PROBE}",
                "--timeout=120s", timeout=130)

    absent = lab.kubectl("-n", NAMESPACE, "get", "resourcequota", "-o", "json")
    quota_list = json.loads(absent.stdout)
    lab.check(
        "positive", "The baseline namespace has no quota before the control is applied",
        quota_list.get("items") == [], {"resourcequota_count": len(quota_list.get("items", []))},
    )

    baseline = run_probe(lab, "baseline-pod")
    baseline_created = baseline.get("status") == 201
    lab.check(
        "red", "Without a namespace quota, the 600m synthetic request is admitted",
        baseline_created, baseline,
    )
    if not baseline_created or not baseline.get("name"):
        lab.block("Baseline Pod was not created; cannot compare quota admission")
    baseline_name = baseline["name"]
    lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{baseline_name}",
                "--timeout=120s", timeout=130)
    lab.kubectl("-n", NAMESPACE, "delete", "pod", baseline_name, "--wait=true")

    denied_before_quota = run_probe(lab, "tenant-create-quota")
    lab.check(
        "positive", "Tenant ServiceAccount cannot create a ResourceQuota",
        denied_before_quota.get("status") == 403, denied_before_quota,
    )

    lab.kubectl("-n", NAMESPACE, "apply", "-f", str(HERE / "fixtures" / "quota.yaml"))
    quota = json.loads(lab.kubectl(
        "-n", NAMESPACE, "get", "resourcequota", QUOTA_NAME, "-o", "json",
    ).stdout)
    hard = quota.get("spec", {}).get("hard", {})
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and quota.get("status", {}).get("hard") != hard:
        time.sleep(0.3)
        quota = json.loads(lab.kubectl("-n", NAMESPACE, "get", "resourcequota", QUOTA_NAME, "-o", "json").stdout)
    if quota.get("status", {}).get("hard") != hard:
        lab.block("The ResourceQuota controller did not initialize the reviewed hard limits")
    exact_quota = hard == {
        "pods": "4", "requests.cpu": "500m", "requests.memory": "256Mi",
    }
    lab.check("positive", "The namespace quota has the reviewed ordinary limits",
              exact_quota, {"hard": hard})

    rejected = run_probe(lab, "over-quota-pod")
    quota_rejected = (
        rejected.get("status") == 403
        and "exceeded quota" in rejected.get("message", "").lower()
        and QUOTA_NAME in rejected.get("message", "")
    )
    lab.check(
        "green", "The same 600m request is rejected by the named namespace quota",
        quota_rejected, rejected,
    )

    allowed = run_probe(lab, "small-pod")
    allowed_created = allowed.get("status") == 201 and bool(allowed.get("name"))
    lab.check("green", "A low-request synthetic Pod remains admissible within quota",
              allowed_created, allowed)
    if not allowed_created:
        lab.block("Low-request positive workload was not created")
    lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{allowed['name']}",
                "--timeout=120s", timeout=130)

    tenant_quota_write = run_probe(lab, "tenant-create-quota")
    lab.check(
        "green", "Tenant remains forbidden from changing namespace quota policy",
        tenant_quota_write.get("status") == 403, tenant_quota_write,
    )
    platform_probe = "saf-0901-006-platform-probe"
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-",
                payload=json.dumps(probe_pod(PLATFORM, platform_probe)))
    lab.kubectl("-n", NAMESPACE, "wait", "--for=condition=Ready", f"pod/{platform_probe}",
                "--timeout=120s", timeout=130)
    admin_quota_write = run_probe(lab, "platform-dry-run-create-quota", platform_probe)
    lab.check(
        "positive", "The separately bound platform identity can dry-run create a quota",
        admin_quota_write.get("status") == 201, admin_quota_write,
    )

    refused = lab.kubectl("-n", NAMESPACE, "get", "pod", "saf-0901-006-over-quota",
                          "-o", "name", "--ignore-not-found").stdout.strip()
    live_quotas = json.loads(lab.kubectl("-n", NAMESPACE, "get", "resourcequota", "-o", "json").stdout)
    remaining = sorted(item["metadata"]["name"] for item in live_quotas["items"])
    lab.check("positive", "The rejected Pod and both dry-run quotas left no persisted objects",
              not refused and remaining == [QUOTA_NAME],
              {"over_quota_pod_absent": not refused, "persisted_resource_quotas": remaining})
    (lab.evidence / "quota-observations.json").write_text(json.dumps({
        "baseline": baseline, "over_quota_denial": rejected, "small_allowed": allowed,
        "tenant_dry_run": tenant_quota_write, "platform_dry_run": admin_quota_write,
        "current_resource_quota_names": remaining, "hard_limits": hard,
    }, indent=2) + "\n")

    runpy.run_path(str(HERE / "queue_admission.py"))["run"](lab)
    runpy.run_path(str(HERE / "admission_fair_sharing.py"))["run"](lab)
    runpy.run_path(str(HERE / "admission_fair_sharing_off.py"))["run"](lab)
    runpy.run_path(str(HERE / "kueue_priority_preemption.py"))["run"](lab)
    runpy.run_path(str(HERE / "volcano_install.py"))["run"](lab)
    runpy.run_path(str(HERE / "volcano_workload.py"))["run"](lab)
