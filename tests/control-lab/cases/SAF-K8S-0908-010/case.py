"""Exercise a persistent, deliberately narrow DP-release budget in Kind."""
import importlib.util
import json
from pathlib import Path

from fixtures import container, pod, ready

HERE = Path(__file__).resolve().parent


CODE = "fixture-privacy-budget-code"
GOVERNED = "fixture-privacy-budget-governed"
BASELINE = "fixture-privacy-budget-baseline"
GOVERNED_PVC = "fixture-privacy-budget-ledger"
BASELINE_PVC = "fixture-privacy-budget-baseline-ledger"
LIMIT = 2
SCOPE = (
    "A single-node, local Kubernetes fixture atomically charges one ln(3) unit for each "
    "synthetic one-bit randomized-response release against a named protected population. "
    "The same population ledger is shared across unauthenticated fixture-client labels, "
    "persists on a PVC across Pod recreation, and refuses the third release before another "
    "random draw. A distinct synthetic population has a distinct ledger. The baseline "
    "accepts a third otherwise-valid release after two charges."
)


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load runtime helper: {path}")
    item = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(item)
    return item


def create(lab, kind, name, api="v1", **fields):
    return lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})


def claim(lab, name):
    create(lab, "PersistentVolumeClaim", name, spec={
        "accessModes": ["ReadWriteOnce"],
        "resources": {"requests": {"storage": "1Gi"}},
    })


def launch(lab, name, pvc, mode, image):
    unit = container("fixture", image=image, imagePullPolicy="Never",
                     command=["python", "/fixture/budget_fixture.py", "serve", mode],
                     volumeMounts=[{"name": "source", "mountPath": "/fixture", "readOnly": True},
                                   {"name": "ledger", "mountPath": "/ledger"}])
    unit["readinessProbe"] = {"exec": {"command": ["python", "-c",
        "import socket; socket.create_connection(('127.0.0.1',8080),2).close()"]}, "periodSeconds": 1}
    lab.create(pod(name, [unit], automountServiceAccountToken=False,
                   volumes=[{"name": "source", "configMap": {"name": CODE}},
                            {"name": "ledger", "persistentVolumeClaim": {"claimName": pvc}}],
                   securityContext={"fsGroup": 65532}))
    ready(lab, name)
    lab.kubectl("wait", "--for=jsonpath={.status.phase}=Bound", "pvc/" + pvc, "--timeout=15s")


def command(lab, pod_name, *args):
    result = lab.kubectl("exec", pod_name, "--", "python", "/fixture/budget_fixture.py", *args, timeout=15)
    return json.loads(result.stdout)


def ask(lab, pod_name, scope, client):
    return command(lab, pod_name, "release", scope, client)


def scope_state(lab, pod_name, scope):
    return command(lab, pod_name, "state", scope)


def run(lab):
    runtime = module(HERE.parent / "SAF-K8S-0908-001" / "case.py", "saf_fixture_runtime")
    image = runtime.load_runtime(lab)
    create(lab, "ConfigMap", CODE, immutable=True,
           data={
               "budget_fixture.py": (HERE / "budget_fixture.py").read_text(),
               "mechanism.py": (HERE.parent / "SAF-K8S-0908-009" / "mechanism.py").read_text(),
           })
    claim(lab, BASELINE_PVC)
    claim(lab, GOVERNED_PVC)
    launch(lab, BASELINE, BASELINE_PVC, "baseline", image)
    launch(lab, GOVERNED, GOVERNED_PVC, "governed", image)

    mechanism = command(lab, GOVERNED, "review")
    mechanism_ok = mechanism == {
        "counts": [{"0": 3, "1": 1}, {"0": 1, "1": 3}],
        "common_support": True,
        "approved_likelihood_bound": True,
        "bound_is_tight_on_an_event": True,
    }
    lab.check("positive", "The local one-bit fixture has exact ln(3) likelihood bound",
              mechanism_ok, mechanism)

    # Red control: identical mechanism and two prior charges, but no cutoff.
    base_first = ask(lab, BASELINE, "protected-population", "fixture-client-a")
    base_second = ask(lab, BASELINE, "protected-population", "fixture-client-b")
    base_before = scope_state(lab, BASELINE, "protected-population")
    base_third = ask(lab, BASELINE, "protected-population", "fixture-client-a")
    base_after = scope_state(lab, BASELINE, "protected-population")
    red = {
        "first_two_valid_releases_accepted": [base_first.get("status"), base_second.get("status")] == [200, 200],
        "ledger_reached_two_ln3_units": base_before == {"epsilon_units": 2, "random_draws": 2, "persisted_samples": 2},
        "baseline_accepts_third_after_limit": base_third.get("status") == 200,
        "baseline_persists_third_charge_and_sample": base_after == {"epsilon_units": 3, "random_draws": 3, "persisted_samples": 3},
    }
    lab.check("red", "An ungoverned valid release continues after the two-unit limit", all(red.values()), red)

    # Same scope, different fixture-client labels; the PVC is retained across restart.
    first = ask(lab, GOVERNED, "protected-population", "fixture-client-a")
    second = ask(lab, GOVERNED, "protected-population", "fixture-client-b")
    protected_before = scope_state(lab, GOVERNED, "protected-population")
    lab.kubectl("delete", "pod", GOVERNED, "--wait=true")
    launch(lab, GOVERNED, GOVERNED_PVC, "governed", image)
    protected_after_restart = scope_state(lab, GOVERNED, "protected-population")
    third = ask(lab, GOVERNED, "protected-population", "fixture-client-a")
    protected_after_denial = scope_state(lab, GOVERNED, "protected-population")
    independent = ask(lab, GOVERNED, "independent-population", "fixture-client-b")
    independent_state = scope_state(lab, GOVERNED, "independent-population")

    green = {
        "first_two_releases_accepted_across_fixture_client_labels":
            [first.get("status"), second.get("status")] == [200, 200],
        "exactly_two_ln3_units_persisted": protected_before ==
            {"epsilon_units": 2, "random_draws": 2, "persisted_samples": 2},
        "ledger_survives_pod_recreation": protected_after_restart == protected_before,
        "third_is_denied_without_release": third == {"status": 429, "decision": "budget-exhausted"},
        "denial_adds_no_charge_random_draw_or_sample": protected_after_denial == protected_after_restart,
    }
    lab.check("green", "The persistent population ledger charges twice and cuts off before a third draw",
              all(green.values()), green)
    positive = {
        "authorized_responses_include_one_binary_release": all(
            set(reply) == {"status", "decision", "result"} and reply["status"] == 200
            and reply["decision"] == "released" and type(reply["result"]) is int
            and reply["result"] in (0, 1) for reply in (first, second, independent)
        ),
        "separate_fixture_scope_keeps_its_own_charge": independent_state ==
            {"epsilon_units": 1, "random_draws": 1, "persisted_samples": 1},
        "first_scope_spend_remains_unchanged":
            scope_state(lab, GOVERNED, "protected-population") == protected_after_denial,
    }
    lab.check("positive", "The separate fixture scope can still perform its approved release",
              all(positive.values()), positive)
    (lab.evidence / "privacy-budget-observations.json").write_text(json.dumps({
        "accounting_unit": "one exact ln(3) per synthetic release",
        "limit_units": LIMIT,
        "red_baseline": red,
        "mechanism": mechanism,
        "governed": green,
        "positive": positive,
        "protected_after_denial": protected_after_denial,
        "independent_scope": independent_state,
        "fixture_client_labels_authenticated": False,
        "scope": "two named synthetic populations; no population partition claim",
    }, sort_keys=True, indent=2) + "\n")
