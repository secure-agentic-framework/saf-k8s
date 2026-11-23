"""Synthetic response-minimization case; run(lab) is the SAF harness entry point."""
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REFERENCE_HELPER = HERE.parent / "SAF-K8S-0908-001" / "case.py"
NS = "saf-test"
SCOPE = (
    "Owned synthetic inference services demonstrate field allowlists on live success and error paths. "
    "The TLS diagnostics route uses a projected audience-restricted caller identity, TokenReview and "
    "an independent Kubernetes authorization decision for one named record."
)

# Keep server and client sources in one immutable ConfigMap so the case has no
# external code or model dependencies. Every value below is synthetic.
APP = r'''import json, ssl, sys, urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

MODE = sys.argv[2] if len(sys.argv) > 2 else "client"
TOKEN_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/token"
CA_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
CLIENT_TOKEN = "/caller/token"
AUDIENCE = "saf-fixture-diagnostics"
RECORD = {"record_id":"fixture-17", "feature_summary":{"synthetic_feature_a":0.25},
          "architecture":{"family":"fixture-only", "layers":2},
          "logits":[1.25, -0.75]}

def api_request(path, body=None):
    token = open(TOKEN_FILE).read().strip()
    data=json.dumps(body).encode() if body is not None else None
    headers={"Authorization":"Bearer "+token}
    if data is not None: headers["Content-Type"]="application/json"
    req=urllib.request.Request("https://kubernetes.default.svc"+path,data=data,headers=headers,
                               method="POST" if data is not None else "GET")
    with urllib.request.urlopen(req, context=ssl.create_default_context(cafile=CA_FILE), timeout=3) as r:
        return json.loads(r.read())

def api_post(path, body): return api_request(path, body)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # No request bodies, tokens, features, or model outputs in access logs.
        print(json.dumps({"event":"http_request", "path":self.path,
                          "status":getattr(self, "_status", 200)}, sort_keys=True))
    def reply(self, status, obj):
        self._status=status
        data=json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_POST(self):
        if self.path == "/v1/infer":
            raw=self.rfile.read(int(self.headers.get("Content-Length", "0")))
            try:
                request=json.loads(raw)
                if not isinstance(request, dict) or request.get("text") != "hello" or set(request) != {"text"}:
                    raise ValueError("request shape")
            except Exception as exc:
                if MODE == "baseline":
                    return self.reply(400, {"error":"invalid request", "detail":str(exc),
                        "exception":type(exc).__name__, "debug":"fixture parser at app.py:31"})
                return self.reply(400, {"error":"invalid_request"})
            if MODE == "baseline":
                return self.reply(200, {"result":"synthetic-cedar", "logits":[1.25,-0.75],
                    "probabilities":[0.88,0.12], "features":{"synthetic_feature_a":0.25},
                    "architecture":{"family":"fixture-only","layers":2,"parameters":12}})
            return self.reply(200, {"result":"synthetic-cedar"})
        if self.path == "/internal/diagnostics/fixture-17":
            if MODE == "baseline":
                return self.reply(200, RECORD)
            auth=self.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return self.reply(401, {"error":"unauthorized"})
            try:
                review=api_post("/apis/authentication.k8s.io/v1/tokenreviews",
                    {"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview",
                     "spec":{"token":auth[7:],"audiences":[AUDIENCE]}})
                status=review.get("status", {})
                if not status.get("authenticated") or AUDIENCE not in status.get("audiences", []):
                    return self.reply(401, {"error":"unauthorized"})
                sar=api_post("/apis/authorization.k8s.io/v1/subjectaccessreviews",
                    {"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview",
                     "spec":{"user":status.get("user",{}).get("username", ""),
                       "groups":status.get("user",{}).get("groups",[]),
                       "resourceAttributes":{"namespace":"saf-test","verb":"get",
                         "group":"","resource":"configmaps","name":"fixture-diagnostic-record"}}})
                allowed=sar.get("status",{}).get("allowed",False)
            except Exception:
                return self.reply(503, {"error":"diagnostics_unavailable"})
            if not allowed:
                return self.reply(403, {"error":"forbidden"})
            try:
                cm=api_request("/api/v1/namespaces/saf-test/configmaps/fixture-diagnostic-record")
                record=json.loads(cm["data"]["record.json"])
            except Exception:
                return self.reply(503, {"error":"diagnostics_unavailable"})
            return self.reply(200, record)
        return self.reply(404, {"error":"not_found"})

if MODE in ("baseline", "enforced"):
    server = HTTPServer(("0.0.0.0", 8443), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain("/certificate/tls.crt", "/certificate/tls.key")
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
else:
    # Client CLI: probe HOST PATH TOKEN_MODE BODY_MODE. It emits only bounded,
    # sanitized status and parsed fixture response; no credentials are printed.
    host,path,token_mode,body_mode=sys.argv[2:6]
    body=b"{" if body_mode == "malformed" else b'{"text":"hello"}'
    headers={"Content-Type":"application/json"}
    if token_mode == "token": headers["Authorization"]="Bearer "+open(CLIENT_TOKEN).read().strip()
    req=urllib.request.Request("https://"+host+path,data=body,headers=headers,method="POST")
    try:
        with urllib.request.urlopen(req, context=ssl.create_default_context(cafile="/trust/ca.crt"), timeout=6) as r: status=r.status; payload=r.read()
    except urllib.error.HTTPError as e: status=e.code; payload=e.read()
    try: response=json.loads(payload)
    except Exception: response={"unparseable":True}
    print(json.dumps({"status":status,"body":response},sort_keys=True,separators=(",",":")))
'''


def runtime_loader():
    """Dynamically load the published adjacent helper without invoking Docker/Kind."""
    module_name = "saf_0908_001_runtime_helper"
    spec = importlib.util.spec_from_file_location(module_name, REFERENCE_HELPER)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load adjacent published runtime helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_runtime


def create(lab, kind, name, api="v1", **fields):
    metadata={"name":name}
    if kind not in {"ClusterRole", "ClusterRoleBinding"}:
        metadata["namespace"]=NS
    return lab.create({"apiVersion":api,"kind":kind,"metadata":metadata,**fields})


def wait_ready(lab, name):
    lab.kubectl("wait", "--for=condition=Ready", "pod/"+name, "-n", NS,
                "--timeout=90s")


def run(lab):
    """Run deterministic red/green/positive observations in an isolated SAF lab."""
    image = runtime_loader()(lab)
    key = lab.kubeconfig.parent / "diagnostics.key"
    cert = lab.kubeconfig.parent / "diagnostics.crt"
    lab.command("openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
                "-subj", "/CN=fixture-api-enforced.saf-test.svc",
                "-addext", "subjectAltName=DNS:fixture-api-enforced.saf-test.svc,DNS:fixture-api-baseline.saf-test.svc",
                "-addext", "basicConstraints=critical,CA:TRUE", "-addext",
                "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
                "-keyout", str(key), "-out", str(cert))
    lab.kubectl("create", "secret", "tls", "fixture-diagnostics-tls",
                "--key="+str(key), "--cert="+str(cert), "-o", "name")
    create(lab, "ConfigMap", "fixture-diagnostics-trust", immutable=True,
           data={"ca.crt": cert.read_text()})
    create(lab, "ConfigMap", "fixture-code", immutable=True,
           data={"app.py": APP})
    create(lab, "ConfigMap", "fixture-diagnostic-record", immutable=True,
           data={"record.json": json.dumps({"record_id":"fixture-17",
               "feature_summary":{"synthetic_feature_a":0.25},
               "architecture":{"family":"fixture-only","layers":2},
               "logits":[1.25,-0.75]}, sort_keys=True)})
    for account in ("fixture-diagnostics-approved", "fixture-diagnostics-unapproved", "fixture-api-verifier"):
        create(lab, "ServiceAccount", account, automountServiceAccountToken=False)
    create(lab, "Role", "fixture-diagnostic-reader", "rbac.authorization.k8s.io/v1", rules=[{
        "apiGroups":[""], "resources":["configmaps"], "resourceNames":["fixture-diagnostic-record"], "verbs":["get"]}])
    create(lab, "RoleBinding", "fixture-diagnostic-reader", "rbac.authorization.k8s.io/v1",
        roleRef={"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"fixture-diagnostic-reader"},
        subjects=[{"kind":"ServiceAccount","name":"fixture-diagnostics-approved","namespace":NS}])
    create(lab, "Role", "fixture-record-reader", "rbac.authorization.k8s.io/v1", rules=[
        {"apiGroups":[""],"resources":["configmaps"],"resourceNames":["fixture-diagnostic-record"],"verbs":["get"]}])
    create(lab, "RoleBinding", "fixture-record-reader", "rbac.authorization.k8s.io/v1",
        roleRef={"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"fixture-record-reader"},
        subjects=[{"kind":"ServiceAccount","name":"fixture-api-verifier","namespace":NS}])
    create(lab, "ClusterRole", "fixture-api-verifier", "rbac.authorization.k8s.io/v1", rules=[
        {"apiGroups":["authentication.k8s.io"],"resources":["tokenreviews"],"verbs":["create"]},
        {"apiGroups":["authorization.k8s.io"],"resources":["subjectaccessreviews"],"verbs":["create"]}])
    create(lab, "ClusterRoleBinding", "fixture-api-verifier", "rbac.authorization.k8s.io/v1",
        roleRef={"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"fixture-api-verifier"},
        subjects=[{"kind":"ServiceAccount","name":"fixture-api-verifier","namespace":NS}])

    def pod(name, command, account="default", verifier=False):
        mounts=[{"name":"code","mountPath":"/fixture","readOnly":True}]
        volumes=[{"name":"code","configMap":{"name":"fixture-code"}}]
        if verifier:
            mounts.append({"name":"tls", "mountPath":"/certificate", "readOnly":True})
            volumes.append({"name":"tls", "secret":{"secretName":"fixture-diagnostics-tls"}})
            mounts.append({"name":"api-identity","mountPath":"/var/run/secrets/kubernetes.io/serviceaccount","readOnly":True})
            volumes.append({"name":"api-identity","projected":{"sources":[{"serviceAccountToken":{"path":"token","expirationSeconds":600}},
                {"configMap":{"name":"kube-root-ca.crt","items":[{"key":"ca.crt","path":"ca.crt"}]}}]}})
        else:
            mounts.append({"name":"trust", "mountPath":"/trust", "readOnly":True})
            volumes.append({"name":"trust", "configMap":{"name":"fixture-diagnostics-trust"}})
        if not verifier and account != "default":
            mounts.append({"name":"caller-token","mountPath":"/caller","readOnly":True})
            volumes.append({"name":"caller-token","projected":{"sources":[{"serviceAccountToken":{"path":"token","audience":"saf-fixture-diagnostics","expirationSeconds":600}}]}})
        app=command
        spec={"apiVersion":"v1","kind":"Pod","metadata":{"name":name,"namespace":NS},"spec":{
            "restartPolicy":"Always" if name.startswith("fixture-api-") else "Never",
            "serviceAccountName":account,"automountServiceAccountToken":False,
            "containers":[{"name":"fixture","image":image,"imagePullPolicy":"Never",
              "command":(["sleep","300"] if name.startswith("fixture-client-") else ["python","/fixture/app.py"]+app),
              "volumeMounts":mounts}],"volumes":volumes}}
        if verifier:
            spec["spec"]["containers"][0]["readinessProbe"] = {
                "tcpSocket":{"port":8443}, "periodSeconds":1}
        lab.create(spec)
    # Server-side API verifier credentials are independent from the presented principal.
    for mode in ("baseline","enforced"):
        pod("fixture-api-"+mode,["serve",mode],"fixture-api-verifier",True)
        create(lab,"Service","fixture-api-"+mode,spec={"selector":{"run":"fixture-api-"+mode},"ports":[{"port":8443}]})
        lab.kubectl("label","pod/fixture-api-"+mode,"run=fixture-api-"+mode,"-n",NS)
    for name,account in (("fixture-client-public","default"),
                         ("fixture-client-approved","fixture-diagnostics-approved"),
                         ("fixture-client-unapproved","fixture-diagnostics-unapproved")):
        pod(name,["client"],account)
    for name in ("fixture-api-baseline","fixture-api-enforced", "fixture-client-public",
                 "fixture-client-approved", "fixture-client-unapproved"):
        wait_ready(lab,name)

    def call(client, service, path, token, body):
        command=["exec",client,"-n",NS,"--","python","/fixture/app.py","client",
                 service+"."+NS+".svc:8443",path,token,body]
        result=lab.kubectl(*command,timeout=15)
        return json.loads(result.stdout.strip().splitlines()[-1])

    base_public=call("fixture-client-public","fixture-api-baseline","/v1/infer","none","valid")
    base_bad=call("fixture-client-public","fixture-api-baseline","/v1/infer","none","malformed")
    base_diag=call("fixture-client-public","fixture-api-baseline","/internal/diagnostics/fixture-17","none","valid")
    red={"public_success_leaks_named_logits":base_public["body"].get("logits")==[1.25,-0.75],
         "public_success_leaks_feature_and_architecture":
             "features" in base_public["body"] and "architecture" in base_public["body"],
         "malformed_error_leaks_details":all(k in base_bad["body"] for k in ("detail","exception","debug")),
         "diagnostic_view_publicly_exposes_feature_and_architecture":base_diag["status"]==200
             and "feature_summary" in base_diag["body"] and "architecture" in base_diag["body"]}
    lab.check("red","Baseline public response and diagnostics expose named synthetic fixture fields",all(red.values()),red)

    good=call("fixture-client-public","fixture-api-enforced","/v1/infer","none","valid")
    bad=call("fixture-client-public","fixture-api-enforced","/v1/infer","none","malformed")
    noauth=call("fixture-client-public","fixture-api-enforced","/internal/diagnostics/fixture-17","none","valid")
    denied=call("fixture-client-unapproved","fixture-api-enforced","/internal/diagnostics/fixture-17","token","valid")
    green={"public_success_exact_allowlist":good=={"status":200,"body":{"result":"synthetic-cedar"}},
           "malformed_error_exact_allowlist":bad=={"status":400,"body":{"error":"invalid_request"}},
           "diagnostics_requires_identity":noauth=={"status":401,"body":{"error":"unauthorized"}},
           "independent_rbac_denies_unapproved":denied=={"status":403,"body":{"error":"forbidden"}}}
    lab.check("green","Public success and malformed error use exact allowlists; diagnostics deny unauthorized callers",all(green.values()),green)

    approved=call("fixture-client-approved","fixture-api-enforced","/internal/diagnostics/fixture-17","token","valid")
    positive={"public_inference_remains_available":good["status"]==200,
              "approved_diagnostic_record_available":approved=={"status":200,"body":{
                  "architecture":{"family":"fixture-only","layers":2},"feature_summary":{"synthetic_feature_a":0.25},
                  "logits":[1.25,-0.75],"record_id":"fixture-17"}},
              "diagnostic_view_only_for_named_owned_record":approved["body"].get("record_id")=="fixture-17"}
    lab.check("positive","Valid public inference and independently RBAC-approved diagnostic record both work",all(positive.values()),positive)
    observations={"fixture":"synthetic-only","red":red,"green":green,"positive":positive,
        "routes":{"public":"POST /v1/infer","diagnostics":"POST /internal/diagnostics/fixture-17"},
        "identity_observation":"Kubernetes TokenReview of caller token; SubjectAccessReview for get configmaps/fixture-diagnostic-record",
        "limitations":["fixture route coverage is not production ingress or gateway coverage","no claim about extraction resistance, privacy, timing, utility parity, or service-wide availability"]}
    (lab.evidence/"inference-exposure-observations.json").write_text(json.dumps(observations,sort_keys=True,separators=(",",":"))+"\n")
