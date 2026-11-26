"""Bounded lifecycle checks for the owned synthetic Prometheus monitors."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import time
import urllib.parse

HERE = Path(__file__).resolve().parent
NAMESPACE = "saf-test"
PROMETHEUS = "http://saf-prometheus:9090"
RETIREMENT_SECONDS = 240
SYNTHETIC_QUERY_LOOKBACK = "30s"
FIXTURE_SELECTOR = '{fixture="1002-003"}'
LLAMA_SELECTOR = 'llamacpp:tokens_predicted_total{pod="saf-llama-real",namespace="saf-test"}'
LLAMA_UP_SELECTOR = 'up{pod="saf-llama-real",namespace="saf-test"}'
EXPECTED_LLAMA_POOL = "serviceMonitor/saf-test/saf-llama-real/0"
TRAINING_METRICS = {"saf_training_stage", "saf_stage_duration_seconds"}
INFERENCE_METRICS = {"saf_inference_latency_seconds", "saf_model_quality_marker"}
SENSITIVE_LOG_VALUE = re.compile(
    r"(?i)(authorization|bearer|token|password|secret|credential|api[_-]?key)([=: ]+)([^,\s\"]+|\"[^\"]*\")")


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _api(lab, endpoint, query=None, timeout=20, lookback=None):
    url = PROMETHEUS + endpoint
    if query is not None:
        parameters = {"query": query}
        if lookback is not None:
            parameters["lookback_delta"] = lookback
        url += "?" + urllib.parse.urlencode(parameters)
    script = "import sys,urllib.request; print(urllib.request.urlopen(sys.argv[1],timeout=8).read().decode())"
    started = time.monotonic()
    result = lab.kubectl("exec", "pod/saf-query", "--", "python", "-c", script,
                         url, timeout=timeout, allow_failure=True)
    observation = {"endpoint": endpoint, "query": query,
                   "elapsed_seconds": round(time.monotonic() - started, 3),
                   "returncode": result.returncode, "lookback_delta": lookback}
    if result.returncode:
        observation["error"] = (result.stderr or result.stdout)[-1200:]
        return observation, None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        observation["error"] = str(error)
        observation["response_tail"] = result.stdout[-1200:]
        return observation, None
    if payload.get("status") != "success":
        observation["error"] = "Prometheus API status was not success"
        observation["api_error_type"] = payload.get("errorType")
        observation["api_error"] = payload.get("error")
        return observation, None
    return observation, payload.get("data", {})


def _query_rows(lab, expression, lookback=None):
    return _api(lab, "/api/v1/query", expression, lookback=lookback)


def _target_summary(data):
    if data is None:
        return None
    targets = data.get("activeTargets", [])
    return sorted(({
        "scrapePool": item.get("scrapePool"),
        "health": item.get("health"),
        "lastScrape": item.get("lastScrape"),
        "lastError": item.get("lastError", ""),
        "labels": item.get("labels", {}),
    } for item in targets), key=lambda row: row["scrapePool"] or "")


def _metric_summary(rows):
    if rows is None:
        return None
    return sorted(({
        "labels": item.get("metric", {}),
        "sample": item.get("value", []),
    } for item in rows), key=lambda row: json.dumps(row["labels"], sort_keys=True))


def _capture_reloader_diagnostics(lab, phase):
    """Read only bounded Pod args and current logs; never read config Secrets."""
    started = time.monotonic()
    result = lab.kubectl("get", "pod", "prometheus-saf-prometheus-0", "-o", "json",
                         timeout=20, allow_failure=True)
    item = {"captured_at": _utc_now(), "phase": phase,
            "pod_get_elapsed_seconds": round(time.monotonic() - started, 3),
            "pod_get_returncode": result.returncode}
    if not result.returncode:
        try:
            pod = json.loads(result.stdout)
            containers = pod.get("spec", {}).get("containers", [])
            container = next((c for c in containers if c.get("name") == "config-reloader"), None)
            item["reloader_args"] = container.get("args", []) if container else None
            statuses = pod.get("status", {}).get("containerStatuses", [])
            status = next((c for c in statuses if c.get("name") == "config-reloader"), None)
            if status:
                item["reloader_ready"] = status.get("ready")
                item["reloader_restart_count"] = status.get("restartCount")
                item["reloader_image_id"] = status.get("imageID")
        except (json.JSONDecodeError, AttributeError):
            item["pod_parse_error"] = "Prometheus Pod status was not valid JSON"
    log_started = time.monotonic()
    logs = lab.kubectl("logs", "pod/prometheus-saf-prometheus-0", "-c", "config-reloader",
                       "--since=10m", "--tail=80", timeout=15, allow_failure=True)
    item["logs_elapsed_seconds"] = round(time.monotonic() - log_started, 3)
    item["logs_returncode"] = logs.returncode
    safe_lines = []
    for line in (logs.stdout + logs.stderr).splitlines()[-80:]:
        safe_lines.append(SENSITIVE_LOG_VALUE.sub(r"\1\2[REDACTED]", line))
    item["logs"] = "\n".join(safe_lines)[-12000:]
    return item


def _runtime_info(lab):
    command, data = _api(lab, "/api/v1/status/runtimeinfo")
    selected = None if data is None else {
        key: data.get(key) for key in ("serverTime", "lastConfigTime", "reloadConfigSuccess")
        if key in data
    }
    return {"request": command, "selected_fields": selected}


def _observe(lab):
    stage = {"observed_at": _utc_now()}
    target_command, targets_data = _api(lab, "/api/v1/targets?state=active")
    stage["target_request"] = target_command
    stage["active_targets"] = _target_summary(targets_data)
    series_command, series_data = _query_rows(lab, FIXTURE_SELECTOR, SYNTHETIC_QUERY_LOOKBACK)
    stage["fixture_series_request"] = series_command
    stage["fixture_series"] = _metric_summary(
        None if series_data is None else series_data.get("result"))
    llama_command, llama_data = _query_rows(lab, LLAMA_SELECTOR)
    stage["llama_counter_request"] = llama_command
    stage["llama_counter_series"] = _metric_summary(
        None if llama_data is None else llama_data.get("result"))
    up_command, up_data = _query_rows(lab, LLAMA_UP_SELECTOR)
    stage["llama_up_request"] = up_command
    stage["llama_up_series"] = _metric_summary(
        None if up_data is None else up_data.get("result"))
    return stage


def _valid_retained(metrics, workload, names):
    if metrics is None:
        return False
    matches = [row for row in metrics if row["labels"].get("__name__") in names]
    return (len(matches) == len(names)
            and {row["labels"].get("__name__") for row in matches} == names
            and all(row["labels"].get("workload") == workload for row in matches))


def _llama_healthy(stage):
    targets = stage.get("active_targets") or []
    pools = [item for item in targets if item.get("scrapePool") == EXPECTED_LLAMA_POOL]
    up = stage.get("llama_up_series") or []
    counter = stage.get("llama_counter_series") or []
    return (len(pools) == 1 and pools[0].get("health") == "up"
            and len(up) == 1 and up[0]["sample"][1] == "1"
            and up[0]["labels"].get("pod") == "saf-llama-real"
            and len(counter) == 1 and counter[0]["sample"][1] == "4"
            and counter[0]["labels"].get("pod") == "saf-llama-real")


def _run_phase(lab, phase, claim, monitor, removed_pool, expected_pools,
               removed_metrics, retained_metrics, retained_workload):
    evidence_path = lab.evidence / "telemetry-retirement.raw.json"
    if evidence_path.exists():
        evidence = json.loads(evidence_path.read_text())
    else:
        evidence = {"bound_seconds_per_phase": RETIREMENT_SECONDS,
                    "diagnostic_note": "No Prometheus config Secret contents are read.",
                    "phases": []}
    initial = _observe(lab)
    initial_names = {row["labels"].get("__name__") for row in initial.get("fixture_series") or []}
    phase_data = {"phase": phase, "claim": claim, "monitor": monitor,
                  "initial": initial, "observations": []}
    initial_pools = {row["scrapePool"] for row in initial.get("active_targets") or []}
    if (initial_pools != expected_pools | {removed_pool}
            or initial_names != removed_metrics | retained_metrics or not _llama_healthy(initial)):
        evidence["phases"].append(phase_data)
        evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        lab.block(f"The bounded baseline did not observe all expected live targets and samples before deleting {monitor}")
    phase_data["delete_requested_at"] = _utc_now()
    delete = lab.kubectl("delete", monitor, timeout=20, allow_failure=True)
    phase_data["delete_returncode"] = delete.returncode
    phase_data["delete_output"] = (delete.stdout + delete.stderr)[-2000:]
    get = lab.kubectl("get", monitor, "-o", "json", "--ignore-not-found",
                      timeout=20, allow_failure=True)
    phase_data["get_after_delete_returncode"] = get.returncode
    phase_data["object_absent_after_delete"] = get.returncode == 0 and not get.stdout.strip()
    phase_data["reloader_diagnostics"] = _capture_reloader_diagnostics(lab, phase)
    phase_data["runtimeinfo_at_phase_start"] = _runtime_info(lab)
    if delete.returncode != 0 or not phase_data["object_absent_after_delete"]:
        evidence["phases"].append(phase_data)
        evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        lab.block(f"The retirement fixture did not remove its exact monitor {monitor}")

    deadline = time.monotonic() + RETIREMENT_SECONDS
    last = None
    while time.monotonic() < deadline:
        last = _observe(lab)
        last["elapsed_seconds"] = round(RETIREMENT_SECONDS - max(0, deadline - time.monotonic()), 3)
        phase_data["observations"].append(last)
        pools = {item["scrapePool"] for item in last.get("active_targets") or []}
        fixtures = last.get("fixture_series")
        removed_absent = (fixtures is not None and not any(
            row["labels"].get("__name__") in removed_metrics for row in fixtures))
        if retained_workload is None:
            retained_ok = fixtures == []
        else:
            retained_ok = _valid_retained(fixtures, retained_workload, retained_metrics)
        llama_ok = _llama_healthy(last)
        if pools == expected_pools and removed_absent and retained_ok and llama_ok:
            phase_data["converged"] = True
            break
        time.sleep(2)
    if last is None:
        last = _observe(lab)
        phase_data["observations"].append(last)

    if not phase_data.get("converged"):
        phase_data["reloader_diagnostics_at_bound"] = _capture_reloader_diagnostics(lab, phase)
    phase_data["runtimeinfo_at_phase_end"] = _runtime_info(lab)
    default_request, default_response = _query_rows(lab, FIXTURE_SELECTOR)
    phase_data["default_instant_query"] = {
        "request": default_request, "series": _metric_summary(
            None if default_response is None else default_response.get("result")),
    }
    history_request, history_response = _query_rows(lab, FIXTURE_SELECTOR + "[5m]")
    phase_data["recent_history"] = {"request": history_request,
        "series": None if history_response is None else history_response.get("result")}

    pools = {item["scrapePool"] for item in last.get("active_targets") or []}
    fixtures = last.get("fixture_series")
    removed_absent = (fixtures is not None and not any(
        row["labels"].get("__name__") in removed_metrics for row in fixtures))
    if retained_workload is None:
        retained_ok = fixtures == []
    else:
        retained_ok = _valid_retained(fixtures, retained_workload, retained_metrics)
    llama_ok = _llama_healthy(last)
    phase_data.update({"finished_at": _utc_now(), "observed_pool_set": sorted(pools),
                       "expected_pool_set": sorted(expected_pools),
                       "expected_pool_set_matches": pools == expected_pools,
                       "removed_instant_series_absent": removed_absent,
                       "retained_instant_series_match": retained_ok,
                       "llama_target_and_four_token_counter_still_healthy": llama_ok,
                       "last_observation": last})
    evidence["phases"].append(phase_data)
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")

    if not phase_data.get("converged"):
        lab.block(f"Target and instant-series retirement for {monitor} was not observed within {RETIREMENT_SECONDS}s")
    lab.check("positive", phase_data["claim"], True,
              {"monitor_api_object_absent": phase_data["object_absent_after_delete"],
               "expected_active_pool_set_matches": phase_data["expected_pool_set_matches"],
               "removed_instant_series_absent": removed_absent,
               "retained_series_state_matches": retained_ok,
               "native_llama_target_survives": llama_ok,
               "synthetic_query_lookback": SYNTHETIC_QUERY_LOOKBACK})


def run(lab):
    _run_phase(
        lab, "training_monitor_removed",
        "Removing the training monitor retires its target and 30s-lookback series while inference and native llama remain available",
        "servicemonitor/training", "serviceMonitor/saf-test/training/0",
        {"podMonitor/saf-test/inference/0", EXPECTED_LLAMA_POOL},
        TRAINING_METRICS, INFERENCE_METRICS, "saf-inference")
    _run_phase(
        lab, "inference_monitor_removed",
        "Removing the inference monitor retires its target and 30s-lookback series while native llama remains available",
        "podmonitor/inference", "podMonitor/saf-test/inference/0", {EXPECTED_LLAMA_POOL},
        INFERENCE_METRICS, set(), None)

