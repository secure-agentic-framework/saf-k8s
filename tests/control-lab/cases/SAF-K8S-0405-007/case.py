"""Observe APF classification and authentication-path health under ordinary traffic."""
import base64
import json
import ssl
import subprocess
import time
from urllib.error import HTTPError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

NS = "saf-test"
CLIENT = "fixture-priority-observer"
OTHER = "fixture-ordinary-observer"
ITEM = "fixture-auth-path"
FLOW = "fixture-designated-read-flow"
LEVEL = "fixture-designated-read-priority"
VERSION = "flowcontrol.apiserver.k8s.io/v1"
SCOPE = (
    "A fresh owned Kubernetes API server provides real readiness and authenticated fixture reads, "
    "ordinary authentication and authorization status decisions, and observed APF classification. "
    "Only a small number of sequential requests is used. External identity providers, provider-side "
    "controls, queuing under contention, brute-force defenses and production capacity remain separate."
)
MARKER = "owned-available-authenticated-read"


def put(lab, kind, name, api="v1", **fields):
    return lab.create({"apiVersion": api, "kind": kind, "metadata": {"name": name}, **fields})


def native(lab, field):
    return lab.kubectl("config", "view", "--minify", "--raw", "-o",
                       "jsonpath={.clusters[0].cluster." + field + "}").stdout.strip()


def issuer_token(lab, account):
    args = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
            "--namespace", NS, "create", "token", account, "--duration=10m"]
    out = subprocess.run(args, capture_output=True, text=True, timeout=20, env=lab.env)
    if out.returncode or len(out.stdout.strip().split(".")) != 3:
        lab.block("The case-owned API credential could not be issued")
    return out.stdout.strip()


def health(lab, endpoint):
    out = lab.kubectl("get", f"--raw=/{endpoint}", allow_failure=True, timeout=12)
    return out.returncode == 0 and out.stdout.strip() == "ok"


def authority(lab):
    put(lab, "ConfigMap", ITEM, data={"marker": MARKER})
    api = "rbac.authorization.k8s.io/v1"
    for account in (CLIENT, OTHER):
        put(lab, "ServiceAccount", account, automountServiceAccountToken=False)
    put(lab, "Role", ITEM, api, rules=[
        {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": [ITEM], "verbs": ["get"]}])
    put(lab, "RoleBinding", ITEM, api,
        roleRef={"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": ITEM},
        subjects=[{"kind": "ServiceAccount", "name": CLIENT, "namespace": NS}])


def classify(lab):
    put(lab, "PriorityLevelConfiguration", LEVEL, VERSION,
        spec={"type": "Limited", "limited": {"nominalConcurrencyShares": 12, "lendablePercent": 0,
              "limitResponse": {"type": "Queue", "queuing": {"queues": 8, "handSize": 2, "queueLengthLimit": 10}}}})
    put(lab, "FlowSchema", FLOW, VERSION,
        spec={"matchingPrecedence": 100, "priorityLevelConfiguration": {"name": LEVEL},
              "distinguisherMethod": {"type": "ByUser"},
              "rules": [{"subjects": [{"kind": "ServiceAccount", "serviceAccount": {"namespace": NS, "name": CLIENT}}],
                         "resourceRules": [{"verbs": ["get"], "apiGroups": [""], "resources": ["configmaps"],
                                            "clusterScope": False, "namespaces": [NS]}]}]})
    report = {}
    for kind, name, field in (("flowschema", FLOW, "flow"),
                              ("prioritylevelconfiguration", LEVEL, "priority")):
        obj = json.loads(lab.kubectl("get", kind, name, "-o", "json").stdout)
        report[field] = obj["metadata"]["uid"]
    return report


def ordinary_get(client, endpoint, token):
    url = endpoint + f"/api/v1/namespaces/{NS}/configmaps/{ITEM}"
    request = Request(url, headers={"Authorization": "Bearer " + token})
    try:
        with client.open(request, timeout=5) as response:
            return {"status": response.status, "marker": json.load(response)["data"]["marker"],
                    "flow": response.headers.get("X-Kubernetes-PF-FlowSchema-UID"),
                    "priority": response.headers.get("X-Kubernetes-PF-PriorityLevel-UID")}
    except HTTPError as error:
        return {"status": error.code}


def run(lab):
    authority(lab)
    endpoint = native(lab, "server")
    trust = base64.b64decode(native(lab, "certificate-authority-data")).decode()
    https = HTTPSHandler(context=ssl.create_default_context(cadata=trust))
    requester = build_opener(ProxyHandler({}), https)
    approved = issuer_token(lab, CLIENT)
    ordinary = issuer_token(lab, OTHER)
    initial = ordinary_get(requester, endpoint, approved)
    baseline = {"initial_read_succeeded": initial.get("marker") == MARKER,
                "livez_before": health(lab, "livez"), "readyz_before": health(lab, "readyz"),
                "has_initial_apf_classification": bool(initial.get("flow") and initial.get("priority"))}
    lab.check("red", "The approved path works before the dedicated classification is installed",
              all(baseline.values()), baseline)

    governed = classify(lab)
    result = {}
    for _ in range(6):
        result = ordinary_get(requester, endpoint, approved)
        if result.get("flow") == governed["flow"]:
            break
        time.sleep(1)
    observed = {"dedicated_priority_resolved_from_live_response": result.get("priority") == governed["priority"],
                "dedicated_flow_resolved_from_live_response": result.get("flow") == governed["flow"],
                "flow_and_priority_changed": initial.get("flow") != governed["flow"]
                and initial.get("priority") != governed["priority"],
                "same_allowed_read_preserved": result.get("marker") == MARKER}
    lab.check("green", "A real authenticated request moves into the dedicated flow and priority",
              all(observed.values()), observed)

    authentication = ordinary_get(requester, endpoint, "public-fixture-invalid")
    authorization = ordinary_get(requester, endpoint, ordinary)
    after = {"invalid_identity_returns_401": authentication.get("status") == 401,
             "verified_but_unapproved_identity_returns_403": authorization.get("status") == 403,
             "livez_after": health(lab, "livez"), "readyz_after": health(lab, "readyz"),
             "authorized_request_remains_available": ordinary_get(requester, endpoint, approved).get("marker") == MARKER}
    lab.check("positive", "API health remains observable and authentication failure is distinct from authorization denial",
              all(after.values()), after)
    (lab.evidence / "authentication-availability-observations.json").write_text(json.dumps({
        "baseline": baseline, "bounded_flow_observation": observed, "final": after,
    }, indent=2) + "\n")
