"""Observe synthetic generation budgets and a real BPE-backed HTTP stream in Kind."""
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
POD = "saf-token-accounting"
IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
         "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
SCOPE = (
    "A pinned llama.cpp engine also loads a tiny CPU model and checks real tokenizer and completion counts. "
    "A second Pod uses the exact same executable and prompts with only the input guard disabled. "
    "Disposable Kubernetes v1.36.1 Pods run deterministic synthetic generation fixtures. "
    "The original in-process fixture has on/off branches for whitespace-token input and fake "
    "output, with fixed synthetic session IDs and a logical clock. The BPE HTTP fixture uses "
    "fixed template-expanded cl100k_base prompts, synthetic tokens, a guarded path and a same-worker input-guard-off comparison. The guarded serving container's effective CPU quota and memory cgroup ceiling are observed and compared with declared limits. This is container-bound evidence only; no CPU load, GPU, or cache validation. "
    "The HTTP fixture has no authenticated caller/session identity or concurrent generation. "
    "Neither fixture runs a real model or serving framework, configures a real KV cache, or "
    "measures GPU memory. Production route coverage, identity binding, concurrency, cache and "
    "device budgets, cgroup behavior, and monitoring require separate adopter evidence."
)


def deploy(lab):
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": POD},
                "immutable": True, "data": {
                    name: (HERE / name).read_text() for name in ("worker.py", "fixture.py")}})
    lab.create({
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": POD},
        "spec": {
            "automountServiceAccountToken": False, "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "volumes": [{"name": "fixture", "configMap": {"name": POD}}],
            "containers": [{
                "name": "tokens", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
                "command": ["python", "-B", "-c", "import time; time.sleep(600)"],
                "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                              "limits": {"cpu": "200m", "memory": "96Mi"}},
                "volumeMounts": [
                    {"name": "fixture", "mountPath": "/fixture", "readOnly": True}],
                "securityContext": {"allowPrivilegeEscalation": False,
                                    "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
            }],
        },
    })
    lab.kubectl("wait", "--for=condition=Ready", "pod/" + POD, "--timeout=80s", timeout=90)


def read_observations(lab):
    default = {"max_input_tokens": 4, "max_request_output_tokens": 4,
               "max_session_output_tokens": 6, "token_rate": 100, "burst": 100}
    cases = {
        "red": {"policy": None, "requests": [["red", "a b c d e", 7, 0]]},
        "input": {"policy": default, "requests": [
            ["input", "a b c d", 4, 0], ["input", "a b c d e", 1, 0]]},
        "budget": {"policy": default, "requests": [
            ["budget", "ok", 9, 0], ["budget", "ok", 9, 0], ["budget", "ok", 1, 0],
            ["second", "ok", 1, 0]]},
        "positive": {"policy": default, "requests": [["positive", "one two", 3, 0]]},
        "rate": {"policy": {**default, "token_rate": 1, "burst": 2}, "requests": [
            ["rate", "ok", 4, 0], ["rate", "ok", 1, 0], ["rate", "ok", 1, 1],
            ["rate", "ok", 1, 2]]},
    }
    result = lab.kubectl("exec", "-i", "pod/" + POD, "--", "python", "-B",
                         "/fixture/worker.py", payload=json.dumps(cases), timeout=20)
    try:
        observed = json.loads(result.stdout)
        assert observed.keys() == cases.keys()
        for name, rows in observed.items():
            assert len(rows) == len(cases[name]["requests"])
            assert all(row.keys() == {"response", "backend", "session_output"} for row in rows)
    except (AttributeError, AssertionError, TypeError, json.JSONDecodeError) as error:
        lab.block(f"Token fixture returned incomplete observations: {error}")
    return observed


def response(accepted, reason, input_tokens, output_tokens):
    return {"accepted": accepted, "reason": reason, "input_tokens": input_tokens,
            "output_tokens": output_tokens, "text": " ".join(["tok"] * output_tokens)}


def backend(requests, prompt_tokens, generated_tokens):
    return {"requests": requests, "prompt_tokens": prompt_tokens,
            "generated_tokens": generated_tokens}


def run(lab):
    deploy(lab)
    rows = read_observations(lab)
    (lab.evidence / "token-accounting.raw.json").write_text(json.dumps(rows, indent=2) + "\n")
    [red] = rows["red"]
    lab.check("red", "With token policy disabled, the fake model processes the five-token input and seven outputs",
              red["response"] == response(True, "unguarded", 5, 7)
              and red["backend"] == backend(1, 5, 7), red)

    exact, above = rows["input"]
    lab.check("green", "The exact four-token input is admitted and a fifth token is rejected before backend work",
              exact["response"] == response(True, "complete", 4, 4)
              and above["response"] == response(False, "input_limit", 5, 0)
              and exact["backend"] == above["backend"] == backend(1, 4, 4), rows["input"])

    first, second, exhausted, other = rows["budget"]
    lab.check("green", "Backend accounting confirms request and cumulative session output caps",
              [item["response"] for item in rows["budget"][:3]] == [
                  response(True, "request_budget", 1, 4), response(True, "session_budget", 1, 2),
                  response(True, "session_budget", 1, 0)]
              and [item["session_output"] for item in rows["budget"][:3]] == [4, 6, 6]
              and first["backend"] == backend(1, 1, 4)
              and second["backend"] == exhausted["backend"] == backend(2, 2, 6),
              rows["budget"][:3])
    lab.check("positive", "A distinct fixture session keeps its own output allowance",
              other["response"] == response(True, "complete", 1, 1)
              and other["session_output"] == 1 and other["backend"] == backend(3, 3, 7),
              other)

    lab.check("green", "The two-token burst exhausts at the same tick and refills by one token per tick",
              [item["response"] for item in rows["rate"]] == [
                  response(True, "token_rate", 1, 2), response(True, "token_rate", 1, 0),
                  response(True, "complete", 1, 1), response(True, "complete", 1, 1)]
              and [item["backend"]["generated_tokens"] for item in rows["rate"]] == [2, 2, 3, 4]
              and [item["session_output"] for item in rows["rate"]] == [2, 2, 3, 4], rows["rate"])

    [ordinary] = rows["positive"]
    lab.check("positive", "An ordinary request produces exactly three tokens with corresponding backend work",
              ordinary["response"] == response(True, "complete", 2, 3)
              and ordinary["backend"] == backend(1, 2, 3)
              and ordinary["session_output"] == 3, ordinary)

    spec = importlib.util.spec_from_file_location("stream_case", HERE / "stream_case.py")
    stream = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stream)
    report, provenance = stream.run(lab)
    (lab.evidence / "tokenizer-stream.raw.json").write_text(
        json.dumps({"reference": provenance, "report": report}, indent=2) + "\n")

    stream_checks = {
        "reference_bpe_counts": ("green", "Pinned BPE counts include prompt expansion and differ from whitespace counts"),
        "reference_output_oracle": ("positive", "Pinned BPE vocabulary produces the reviewed token ID vector"),
        "ready_and_caps": ("positive", "The BPE worker serves through the Kubernetes Service with exact fixture caps"),
        "bounded_real_http_stream": ("positive", "The ordinary HTTP stream emits two exact token chunks and completes"),
        "expanded_prompt_rejected_before_dispatch": ("green", "The expanded prompt above the BPE cap is refused before dispatch"),
        "output_cap_counts_emitted_tokens": ("green", "The HTTP stream stops at four emitted tokens for a request of five"),
        "independent_backend_counters": ("green", "Backend counters reflect only accepted requests and emitted tokens"),
        "bounded_http_request_count": ("positive", "The client performs exactly five bounded fixture requests"),
    }
    checks = report.get("checks", [])
    if report.get("check_count") != len(stream_checks) or [
            check.get("name") for check in checks] != list(stream_checks):
        lab.block("The streaming client did not return the exact reviewed check set")
    for check in checks:
        name = check["name"]
        phase, claim = stream_checks[name]
        detail = check["detail"]
        if name == "reference_bpe_counts":
            detail = {"reference": provenance, "counts": detail}
        lab.check(phase, claim, check["passed"] is True, detail)

    comparison = report.get("input_limit_off_comparison", {})
    comparison_checks = comparison.get("checks", [])
    expected_comparison = {
        "same_prompt_guard_switch_accepts":
            "The identical oversized prompt is dispatched only with the fixture input guard disabled",
        "guard_off_finite_output_and_counters":
            "The comparison remains within the same finite output and request caps",
    }
    if comparison.get("check_count") != len(expected_comparison) or [
            check.get("name") for check in comparison_checks] != list(expected_comparison):
        lab.block("The guard-off comparator did not return the exact reviewed check set")
    for check in comparison_checks:
        lab.check("positive", expected_comparison[check["name"]],
                  check.get("passed") is True, check.get("detail"))

    bounds = report["serving_cgroup_bounds"]
    lab.check("green", "The guarded serving container's observed CPU and memory bounds match its live Pod limits",
              bounds["matches"], bounds["observed"])

    engine_path = HERE / "llama_runtime.py"
    engine_spec = importlib.util.spec_from_file_location("llama_runtime", engine_path)
    engine = importlib.util.module_from_spec(engine_spec)
    engine_spec.loader.exec_module(engine)
    engine.run(lab)
