"""Distinguish aggregate extended-resource quota from per-object LimitRange bounds.

All Pod requests use Kubernetes server-side dry-run. The fake extended-resource
name is an inert accounting key; no device plugin or accelerator is installed.
"""

from __future__ import annotations

import json
import time

NAMESPACE = "saf-0901-006-resource-scope"
FIXTURE = "SAF-K8S-0901-006-accounting-only"
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
RESOURCE = "saf.example/lab-accelerator"
QUOTA_KEY = "requests." + RESOURCE
QUOTA = "saf-0901-006-fake-accelerator-quota"
LIMIT_RANGE = "saf-0901-006-container-cpu-bound"


def _pod(name: str, requests: dict[str, str]) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": NAMESPACE,
            "labels": {"saf-k8s.example/fixture": FIXTURE},
            "annotations": {"saf-k8s.example/purpose": "accounting-only-dry-run"},
        },
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "containers": [{
                "name": "inert",
                "image": IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "resources": {"requests": requests, "limits": requests},
            }],
        },
    }


def _dry_run(lab, pod: dict) -> dict:
    result = lab.kubectl(
        "-n", NAMESPACE, "create", "-f", "-", "-o", "json", "--dry-run=server",
        payload=json.dumps(pod, sort_keys=True), allow_failure=True,
    )
    raw = {"returncode": result.returncode,
           "stdout": result.stdout.strip(), "stderr": result.stderr.strip(),
           "pod_name": pod["metadata"]["name"]}
    if result.returncode == 0:
        raw["response"] = json.loads(result.stdout)
    return raw


def _message(result: dict) -> str:
    return (result.get("stderr", "") + "\n" + result.get("stdout", "")).lower()


def run(lab) -> None:
    raw = {"scope": "Kubernetes API server dry-run admission only",
           "synthetic_extended_resource": RESOURCE,
           "quota_resource_name": QUOTA_KEY,
           "device_plugin_or_accelerator": False,
           "stages": {}}

    def persist() -> None:
        (lab.evidence / "resource-quota-limitrange-raw.json").write_text(
            json.dumps(raw, indent=2, sort_keys=True) + "\n")

    lab.kubectl("create", "namespace", NAMESPACE)
    lab.kubectl("-n", NAMESPACE, "label", "namespace", NAMESPACE,
                "saf-k8s.example/fixture=" + FIXTURE, "--overwrite")

    # A request with the synthetic extended-resource key is accepted by the API
    # server before any quota exists; dry-run means no Pod or device is created.
    no_quota = json.loads(lab.kubectl("-n", NAMESPACE, "get", "resourcequota", "-o", "json").stdout)
    baseline = _dry_run(lab, _pod("fake-accelerator", {RESOURCE: "1"}))
    raw["stages"]["baseline"] = {"resourcequotas": no_quota, "same_request": baseline}
    persist()
    baseline_accepted = no_quota.get("items") == [] and baseline["returncode"] == 0
    lab.check("red", "Without ResourceQuota the same synthetic extended-resource Pod is admitted by server dry-run",
              baseline_accepted,
              {"quota_absent": no_quota.get("items") == [],
               "dry_run_created": baseline["returncode"] == 0,
               "resource_key": RESOURCE})

    quota_object = {
        "apiVersion": "v1", "kind": "ResourceQuota",
        "metadata": {"name": QUOTA, "namespace": NAMESPACE,
                     "labels": {"saf-k8s.example/fixture": FIXTURE}},
        "spec": {"hard": {QUOTA_KEY: "0"}},
    }
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-",
                payload=json.dumps(quota_object, sort_keys=True))
    quota = None
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        quota = json.loads(lab.kubectl("-n", NAMESPACE, "get", "resourcequota", QUOTA, "-o", "json").stdout)
        if quota.get("status", {}).get("hard") == quota_object["spec"]["hard"]:
            break
        time.sleep(0.25)
    if quota is None or quota.get("status", {}).get("hard") != quota_object["spec"]["hard"]:
        lab.block("The accounting-only extended-resource quota did not become active")

    denied = _dry_run(lab, _pod("fake-accelerator", {RESOURCE: "1"}))
    denial_message = _message(denied)
    quota_denied = (denied["returncode"] != 0 and "forbidden" in denial_message
                    and "exceeded quota" in denial_message and QUOTA in denial_message
                    and QUOTA_KEY in denial_message)
    raw["stages"]["quota_active"] = {"quota": quota, "same_request": denied}
    persist()
    lab.check("green", "A zero ResourceQuota for requests.saf.example/lab-accelerator refuses that same dry-run request",
              quota_denied,
              {"quota_uid_observed": bool(quota.get("metadata", {}).get("uid")),
               "hard": quota.get("spec", {}).get("hard"),
               "denial_has_exact_quota": QUOTA in denial_message,
               "denial_has_exact_resource": QUOTA_KEY in denial_message,
               "denied": quota_denied})

    cpu_pod = _dry_run(lab, _pod("ordinary-cpu-memory-allowed",
                                 {"cpu": "50m", "memory": "32Mi"}))
    raw["stages"]["ordinary_cpu_memory"] = cpu_pod
    persist()
    cpu_allowed = cpu_pod["returncode"] == 0
    lab.check("positive", "The extended-resource quota leaves an ordinary CPU/memory Pod admissible",
              cpu_allowed,
              {"dry_run_created": cpu_allowed, "requests": {"cpu": "50m", "memory": "32Mi"}})

    limit_range_object = {
        "apiVersion": "v1", "kind": "LimitRange",
        "metadata": {"name": LIMIT_RANGE, "namespace": NAMESPACE,
                     "labels": {"saf-k8s.example/fixture": FIXTURE}},
        "spec": {"limits": [{"type": "Container", "max": {"cpu": "100m"}}]},
    }
    lab.kubectl("-n", NAMESPACE, "create", "-f", "-",
                payload=json.dumps(limit_range_object, sort_keys=True))
    limit_range = json.loads(lab.kubectl("-n", NAMESPACE, "get", "limitrange", LIMIT_RANGE, "-o", "json").stdout)
    oversized = _dry_run(lab, _pod("oversized-container-cpu-denied",
                                   {"cpu": "200m", "memory": "32Mi"}))
    lr_message = _message(oversized)
    lr_denied = (oversized["returncode"] != 0 and "forbidden" in lr_message
                 and "cpu" in lr_message and "200m" in lr_message and "100m" in lr_message)
    raw["stages"]["limit_range"] = {"limit_range": limit_range, "oversized_request": oversized}
    persist()
    limits = limit_range.get("spec", {}).get("limits", [])
    bound_is_observed = (len(limits) == 1 and limits[0].get("type") == "Container"
                         and limits[0].get("max") == {"cpu": "100m"})
    lab.check("green", "LimitRange independently rejects a synthetic per-container CPU request above its 100m bound",
              bound_is_observed and lr_denied,
              {"matching_container_max_read_back": bound_is_observed,
               "limit_range_uid_observed": bool(limit_range.get("metadata", {}).get("uid")),
               "per_container_max_cpu": "100m", "request_cpu": "200m",
               "denied_by_cpu_bound": lr_denied})

    live_pods = json.loads(lab.kubectl("-n", NAMESPACE, "get", "pods", "-o", "json").stdout)
    no_dry_run_pods_persisted = live_pods.get("items", []) == []
    raw["stages"]["cleanup"] = {"dry_run_pods_persisted": len(live_pods.get("items", [])),
                                 "no_dry_run_pods_persisted": no_dry_run_pods_persisted}
    persist()
    lab.check("positive", "All server-side dry-run requests leave the owned namespace without Pods",
              no_dry_run_pods_persisted,
              {"pod_count": len(live_pods.get("items", [])),
               "no_dry_run_pods_persisted": no_dry_run_pods_persisted})
    lab.kubectl("delete", "namespace", NAMESPACE, "--wait=true", timeout=60)
