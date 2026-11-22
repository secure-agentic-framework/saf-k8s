"""Exercise MLflow 3.17 basic-auth RBAC at experiment and run APIs."""
import json
import tempfile
import time
from pathlib import Path

CONTROL_ID = "SAF-K8S-0904-015"
IMAGE = "ghcr.io/mlflow/mlflow:v3.17.0-full@sha256:2b86b1151296dd4639729ac699a6db783e753aed31f69be91134476aa66cb2a0"
NAMESPACE = "saf-test"
SCOPE = (
    "One fresh Kind v1.36.1 cluster runs one official MLflow 3.17.0 tracking server with its "
    "basic-auth RBAC app, SQLite tracking/auth stores, and two fixed fixture principals. Each "
    "principal initially receives EDIT on all experiments, then that same role grant is replaced "
    "with EDIT on its named experiment. Through MLflow's authenticated tracking APIs, the case "
    "checks experiment search/get, run search/get, run-tag writes, and permitted own-experiment "
    "writes before and after narrowing. The experiment is the tested project boundary. This does "
    "not establish native tenant/project isolation, artifact-store authorization, deployment "
    "integration, production identity lifecycle, or parity across tracking platforms."
)
ROOT = Path(__file__).resolve().parent


def _pod(lab):
    return json.loads(lab.kubectl("get", "pod", "mlflow-tracker", "-o", "json").stdout)


def _wait_ready(lab):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        pod = _pod(lab)
        if pod.get("status", {}).get("phase") == "Running" and any(
            c.get("type") == "Ready" and c.get("status") == "True"
            for c in pod.get("status", {}).get("conditions", [])
        ):
            return pod
        time.sleep(1)
    lab.block("MLflow fixture Pod did not become Ready")


def _script(lab, source, *, timeout=55):
    result = lab.kubectl("exec", "-i", "pod/mlflow-tracker", "--", "python", "-B", "-",
                         payload=source, timeout=timeout)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        lab.block(f"MLflow fixture returned non-JSON output: {error}")


def _fixture_script(ids=None, phase=None):
    context = json.dumps({"ids": ids, "phase": phase}, sort_keys=True)
    return r'''import json, os
import mlflow
from mlflow import MlflowClient
from mlflow.server import get_app_client

BASE = "http://127.0.0.1:5000"
CONTEXT = json.loads(''' + repr(context) + r''')
USERS = {
    "alice": ("fixture-alice", os.environ["FIXTURE_ALICE_PASSWORD"]),
    "bob": ("fixture-bob", os.environ["FIXTURE_BOB_PASSWORD"]),
}
ADMIN = ("admin", os.environ["MLFLOW_AUTH_ADMIN_PASSWORD"])

def credentials(user):
    os.environ["MLFLOW_TRACKING_USERNAME"], os.environ["MLFLOW_TRACKING_PASSWORD"] = user

def tracking(user):
    credentials(user)
    return MlflowClient(tracking_uri=BASE)

def auth(user=ADMIN):
    credentials(user)
    return get_app_client("basic-auth", tracking_uri=BASE)

def status(error):
    value = getattr(error, "http_status_code", None)
    if value is None:
        getter = getattr(error, "get_http_status_code", None)
        value = getter() if getter else None
    return value

def probe(call):
    try:
        return {"status": 200, "value": call()}
    except Exception as error:
        code = status(error)
        if code not in (401, 403):
            raise
        return {"status": code}

if CONTEXT["phase"] == "setup":
    if mlflow.__version__ != "3.17.0":
        raise RuntimeError("fixture image did not provide MLflow 3.17.0")
    admin = tracking(ADMIN)
    auth_admin = auth()
    experiment_ids, run_ids = {}, {}
    for tenant in ("alice", "bob"):
        username, password = USERS[tenant]
        auth_admin.create_user(username=username, password=password)
        experiment_name = "saf-0904-015-" + tenant
        eid = admin.create_experiment(experiment_name, tags={"fixture": "public-inert-metadata", "tenant": tenant})
        run = admin.create_run(eid, tags={"fixture": "public-inert-run", "tenant": tenant})
        admin.log_param(run.info.run_id, "fixture_parameter", "inert-" + tenant)
        admin.log_metric(run.info.run_id, "fixture_metric", 1.0)
        experiment_ids[tenant] = eid
        run_ids[tenant] = run.info.run_id
        role = auth_admin.create_role(name="saf-0904-015-" + tenant, workspace="default")
        auth_admin.add_role_permission(role.id, "experiment", "*", "EDIT")
        auth_admin.assign_role(username=username, role_id=role.id)
    print(json.dumps({"version": mlflow.__version__, "experiment_ids": experiment_ids,
                      "run_ids": run_ids}, sort_keys=True))
elif CONTEXT["phase"] == "narrow":
    client = auth()
    for tenant in ("alice", "bob"):
        role = next(r for r in client.list_roles(workspace="default")
                    if r.name == "saf-0904-015-" + tenant)
        grants = client.list_role_permissions(role.id)
        broad = [g for g in grants if g.resource_type == "experiment" and g.resource_pattern == "*"]
        if len(broad) != 1:
            raise RuntimeError("expected exactly one broad experiment grant before narrowing")
        client.remove_role_permission(broad[0].id)
        client.add_role_permission(role.id, "experiment", CONTEXT["ids"][tenant], "EDIT")
    print(json.dumps({"narrowed": True}, sort_keys=True))
else:
    ids, runs = CONTEXT["ids"]["experiments"], CONTEXT["ids"]["runs"]
    tenant = CONTEXT["phase"]["tenant"]
    other = "bob" if tenant == "alice" else "alice"
    client = tracking(USERS[tenant])
    listed = probe(lambda: sorted(e.experiment_id for e in client.search_experiments(filter_string="name LIKE 'saf-0904-015-%'")
                                  if e.experiment_id in ids.values()))
    own_get = probe(lambda: client.get_experiment(ids[tenant]).experiment_id)
    other_get = probe(lambda: client.get_experiment(ids[other]).experiment_id)
    own_runs = probe(lambda: sorted(r.info.run_id for r in client.search_runs([ids[tenant]])))
    other_runs = probe(lambda: sorted(r.info.run_id for r in client.search_runs([ids[other]])))
    other_run_get = probe(lambda: client.get_run(runs[other]).info.run_id)
    own_experiment_write = probe(lambda: client.set_experiment_tag(
        ids[tenant], "fixture-" + CONTEXT["phase"]["stage"] + "-experiment-write", tenant) or "written")
    other_experiment_write = probe(lambda: client.set_experiment_tag(
        ids[other], "fixture-cross-" + CONTEXT["phase"]["stage"] + "-experiment", tenant) or "written")
    own_write = probe(lambda: client.set_tag(runs[tenant], "fixture-" + CONTEXT["phase"]["stage"] + "-write", tenant)
                       or "written")
    other_write = probe(lambda: client.set_tag(runs[other], "fixture-cross-" + CONTEXT["phase"]["stage"], tenant)
                         or "written")
    print(json.dumps({"tenant": tenant, "other": other, "experiments": {
        "list": listed, "own_get": own_get, "other_get": other_get}, "runs": {
        "own_search": own_runs, "other_search": other_runs, "other_get": other_run_get},
        "writes": {"own_experiment": own_experiment_write,
                   "other_experiment": other_experiment_write,
                   "own_run": own_write, "other_run": other_write}}, sort_keys=True))
'''


def _summary_observations(observations, tenants, ids, runs, *, broad):
    for tenant in tenants:
        row = observations[tenant]
        other = "bob" if tenant == "alice" else "alice"
        expected_ids = sorted(ids.values()) if broad else [ids[tenant]]
        if row["experiments"]["list"] != {"status": 200, "value": expected_ids}:
            return False
        if row["experiments"]["own_get"] != {"status": 200, "value": ids[tenant]}:
            return False
        if broad:
            if row["experiments"]["other_get"] != {"status": 200, "value": ids[other]}:
                return False
            if row["runs"]["other_search"] != {"status": 200, "value": [runs[other]]}:
                return False
            if row["runs"]["other_get"] != {"status": 200, "value": runs[other]}:
                return False
            if row["writes"]["other_experiment"] != {"status": 200, "value": "written"}:
                return False
            if row["writes"]["other_run"] != {"status": 200, "value": "written"}:
                return False
        else:
            if row["experiments"]["other_get"] != {"status": 403}:
                return False
            if row["runs"]["other_search"] != {"status": 200, "value": []}:
                return False
            if row["runs"]["other_get"] != {"status": 403}:
                return False
            if row["writes"]["other_experiment"] != {"status": 403}:
                return False
            if row["writes"]["other_run"] != {"status": 403}:
                return False
        if row["runs"]["own_search"] != {"status": 200, "value": [runs[tenant]]}:
            return False
        if row["writes"]["own_experiment"] != {"status": 200, "value": "written"}:
            return False
        if row["writes"]["own_run"] != {"status": 200, "value": "written"}:
            return False
    return True


def stable_observations(observations):
    return {
        tenant: {
            section: {name: {
                "status": decision["status"],
                "results": len(decision["value"]) if isinstance(decision.get("value"), list) else None,
            } for name, decision in row[section].items()}
            for section in ("experiments", "runs", "writes")
        }
        for tenant, row in observations.items()
    }


def _write_raw(lab, version, ids, runs, baseline, narrowed):
    (lab.evidence / "mlflow-access-control.raw.json").write_text(json.dumps({
        "mlflow_version": version, "experiment_ids": ids, "run_ids": runs,
        "before_narrowing": baseline, "after_narrowing": narrowed,
        "fixture_identities": ["fixture-alice", "fixture-bob"]}, indent=2, sort_keys=True) + "\n")


def run(lab):
    fixture_secrets = {
        "MLFLOW_AUTH_ADMIN_PASSWORD": "fixture-admin-password-0904-015",
        "FIXTURE_ALICE_PASSWORD": "fixture-alice-password-0904-015",
        "FIXTURE_BOB_PASSWORD": "fixture-bob-password-0904-015",
        "MLFLOW_FLASK_SERVER_SECRET_KEY": "saf-0904-015-lab-only-secret-key",
    }
    with tempfile.TemporaryDirectory(prefix="saf-mlflow-fixture-") as secret_dir:
        files = []
        for key, value in fixture_secrets.items():
            path = Path(secret_dir) / key
            path.write_text(value)
            path.chmod(0o600)
            files.append(f"--from-file={key}={path}")
        lab.kubectl("create", "secret", "generic", "mlflow-fixture-auth", *files, "-o", "name")
    lab.create({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "mlflow-auth-config"},
                "data": {"basic_auth.ini": (ROOT / "fixtures" / "basic_auth.ini").read_text()}})
    lab.create({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "mlflow-tracker"},
                "spec": {"selector": {"app": "mlflow-tracker"},
                         "ports": [{"name": "http", "port": 5000, "targetPort": 5000}]}})
    container = {
        "name": "mlflow", "image": IMAGE, "imagePullPolicy": "IfNotPresent",
        "command": ["mlflow", "server", "--host", "0.0.0.0", "--port", "5000",
                    "--app-name", "basic-auth", "--backend-store-uri", "sqlite:////tmp/mlflow.db",
                    "--default-artifact-root", "/tmp/artifacts", "--workers", "1"],
        "env": [{"name": name, "valueFrom": {"secretKeyRef": {"name": "mlflow-fixture-auth", "key": name}}}
                for name in fixture_secrets] + [
            {"name": "MLFLOW_AUTH_CONFIG_PATH", "value": "/fixture-auth/basic_auth.ini"},
            {"name": "MLFLOW_DISABLE_TELEMETRY", "value": "true"},
            {"name": "DO_NOT_TRACK", "value": "true"},
        ],
        "ports": [{"name": "http", "containerPort": 5000}],
        "readinessProbe": {"tcpSocket": {"port": "http"}, "periodSeconds": 2, "failureThreshold": 45},
        "resources": {"requests": {"cpu": "100m", "memory": "400Mi"},
                      "limits": {"cpu": "1500m", "memory": "2560Mi"}},
        "volumeMounts": [{"name": "auth-config", "mountPath": "/fixture-auth", "readOnly": True}],
    }
    lab.create({"apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": "mlflow-tracker", "labels": {"app": "mlflow-tracker"}},
                "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never",
                         "containers": [container], "volumes": [
                             {"name": "auth-config", "configMap": {"name": "mlflow-auth-config"}},
                         ]}})
    _wait_ready(lab)

    setup = _script(lab, _fixture_script(phase="setup"))
    if setup.get("version") != "3.17.0" or set(setup.get("experiment_ids", {})) != {"alice", "bob"}:
        lab.block("MLflow setup did not return the exact pinned server version and fixture records")
    ids, runs = setup["experiment_ids"], setup["run_ids"]
    baseline, narrowed = {}, {}
    _write_raw(lab, setup["version"], ids, runs, baseline, narrowed)
    lab.check("positive", "The pinned official MLflow server and two inert fixture experiment/run pairs are ready",
              setup["version"] == "3.17.0" and set(ids) == {"alice", "bob"} and set(runs) == {"alice", "bob"},
              {"mlflow_version": setup["version"], "fixture_experiments": 2, "fixture_runs": 2})

    for tenant in ("alice", "bob"):
        baseline[tenant] = _script(lab, _fixture_script(
            ids={"experiments": ids, "runs": runs}, phase={"stage": "broad", "tenant": tenant}))
        _write_raw(lab, setup["version"], ids, runs, baseline, narrowed)
    lab.check("red", "Before narrowing, both principals can list, read, search and modify the other experiment's metadata",
              _summary_observations(baseline, ("alice", "bob"), ids, runs, broad=True), stable_observations(baseline))

    _script(lab, _fixture_script(ids=ids, phase="narrow"))
    for tenant in ("alice", "bob"):
        narrowed[tenant] = _script(lab, _fixture_script(
            ids={"experiments": ids, "runs": runs}, phase={"stage": "narrow", "tenant": tenant}))
        _write_raw(lab, setup["version"], ids, runs, baseline, narrowed)
    lab.check("green", "After replacing wildcard grants with exact experiment grants, cross-tenant reads and writes are denied or filtered",
              _summary_observations(narrowed, ("alice", "bob"), ids, runs, broad=False), stable_observations(narrowed))
    lab.check("positive", "Both principals retain their own experiment and run read/write operations after narrowing",
              all(narrowed[t]["experiments"]["own_get"] == {"status": 200, "value": ids[t]}
                  and narrowed[t]["writes"]["own_experiment"] == {"status": 200, "value": "written"}
                  and narrowed[t]["writes"]["own_run"] == {"status": 200, "value": "written"}
                  for t in ("alice", "bob")),
              {t: {"own_experiment_read": narrowed[t]["experiments"]["own_get"]["status"],
                   "own_experiment_write": narrowed[t]["writes"]["own_experiment"]["status"],
                   "own_run_write": narrowed[t]["writes"]["own_run"]["status"]}
               for t in ("alice", "bob")})

    _write_raw(lab, setup["version"], ids, runs, baseline, narrowed)
