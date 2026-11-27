"""One synthetic detector-to-authenticated-receiver delivery comparison."""
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time


DNS = "saf-1001-012-alert-receiver.saf-test.svc.cluster.local"
HERE = Path(__file__).resolve().parent
SERVICE = "saf-1001-012-alert-receiver"
IMAGE = (
    "docker.io/library/python:3.13-slim@sha256:"
    "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"
)
EVENT_ID = "SYNTH-1001-012-rate-positive-001"
NEGATIVE_ID = "SYNTH-1001-012-rate-benign-001"

RECEIVER = r'''from http.server import BaseHTTPRequestHandler, HTTPServer
import base64, hmac, json, ssl
from pathlib import Path
STORE=Path("/state/alerts.json")
USER=Path("/auth/username").read_bytes().strip()
PASSWORD=Path("/auth/password").read_bytes().strip()
FIELDS={"alert_id","event_id","rule","actor","repository"}
def read_state():
    return json.loads(STORE.read_text()) if STORE.exists() else {}
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): return
    def reply(self,status,value):
        body=json.dumps(value,sort_keys=True,separators=(",",":")).encode()
        self.send_response(status); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    def authorized(self):
        header=self.headers.get("Authorization","")
        if not header.startswith("Basic "): return False
        try: user,password=base64.b64decode(header[6:],validate=True).split(b":",1)
        except Exception: return False
        return hmac.compare_digest(user,USER) and hmac.compare_digest(password,PASSWORD)
    def do_GET(self):
        if self.path=="/health": return self.reply(200,{"ready":True})
        if self.path!="/alerts": return self.reply(404,{"error":"route"})
        if not self.authorized(): return self.reply(401,{"error":"auth"})
        return self.reply(200,{"alerts":read_state()})
    def do_POST(self):
        if self.path!="/alerts": return self.reply(404,{"error":"route"})
        if not self.authorized(): return self.reply(401,{"error":"auth"})
        try:
            size=int(self.headers.get("Content-Length","0"))
            if not 0<size<=2048: return self.reply(413,{"error":"size"})
            value=json.loads(self.rfile.read(size))
        except Exception: return self.reply(400,{"error":"json"})
        if not isinstance(value,dict) or set(value)!=FIELDS or not all(isinstance(value[k],str) and value[k] for k in FIELDS):
            return self.reply(422,{"error":"shape"})
        state=read_state(); old=state.get(value["alert_id"])
        if old is not None: return self.reply(409,{"error":"duplicate"})
        state[value["alert_id"]]=value
        temp=STORE.with_suffix(".tmp"); temp.write_text(json.dumps(state,sort_keys=True)); temp.replace(STORE)
        return self.reply(201,{"accepted":True})
server=HTTPServer(("0.0.0.0",8443),Handler)
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain("/tls/tls.crt","/tls/tls.key")
server.socket=ctx.wrap_socket(server.socket,server_side=True); server.serve_forever()
'''

DELIVER = r'''import base64, json, ssl, sys
from urllib.request import Request, urlopen
from pathlib import Path
from rate_predicate import rate_exceeds_baseline
base=sys.argv[1]; source=json.loads(Path("/app/records.json").read_text())
rows=source["records"]; thresholds=source["thresholds"]
alerts=[]; decisions={}
for row in rows:
    triggered=rate_exceeds_baseline(row,thresholds)
    decisions[row["event_id"]]=triggered
    if triggered:
        alerts.append({"alert_id":"alert-"+row["event_id"],"event_id":row["event_id"],
          "rule":row["rule"],"actor":"fixture-inference-service","repository":"synthetic-inference-fixture"})
ctx=ssl.create_default_context(cafile="/ca/ca.pem")
user=Path("/auth/username").read_text().strip(); password=Path("/auth/password").read_text().strip()
auth=base64.b64encode((user+":"+password).encode()).decode()
statuses=[]
for alert in alerts:
    req=Request(base+"/alerts",data=json.dumps(alert,sort_keys=True,separators=(",",":")).encode(),
      headers={"Content-Type":"application/json","Authorization":"Basic "+auth},method="POST")
    with urlopen(req,context=ctx,timeout=8) as response: statuses.append(response.status)
print(json.dumps({"decision_count":len(decisions),"positive_triggered":decisions.get("SYNTH-1001-012-rate-positive-001") is True,
 "benign_suppressed":decisions.get("SYNTH-1001-012-rate-benign-001") is False,
 "delivery_count":len(statuses),"delivery_statuses":statuses,"credential_or_event_body_emitted":False},sort_keys=True))
'''

OBSERVE = r'''import base64,json,ssl,sys
from pathlib import Path
from urllib.request import Request,urlopen
base=sys.argv[1]; user=Path("/auth/username").read_text().strip(); password=Path("/auth/password").read_text().strip()
auth=base64.b64encode((user+":"+password).encode()).decode()
req=Request(base+"/alerts",headers={"Authorization":"Basic "+auth})
ctx=ssl.create_default_context(cafile="/ca/ca.pem")
with urlopen(req,context=ctx,timeout=8) as r: status=r.status; state=json.loads(r.read())
expected={"alert-SYNTH-1001-012-rate-positive-001":{"alert_id":"alert-SYNTH-1001-012-rate-positive-001",
 "event_id":"SYNTH-1001-012-rate-positive-001","rule":"inference_request_rate_spike",
 "actor":"fixture-inference-service","repository":"synthetic-inference-fixture"}}
print(json.dumps({"read_status":status,"exact_positive_present":state.get("alerts")==expected,
 "positive_id_present":list(state.get("alerts",{}))==["alert-SYNTH-1001-012-rate-positive-001"],
 "benign_comparator_withheld":"alert-SYNTH-1001-012-rate-benign-001" not in state.get("alerts",{}),
 "record_count":len(state.get("alerts",{})),"alert_body_emitted":False},sort_keys=True))
'''

NO_CREDENTIALS = r'''import json,ssl,sys
from urllib.error import HTTPError
from urllib.request import Request,urlopen
base=sys.argv[1]
body={"alert_id":"unauthenticated-fixture-probe","event_id":"SYNTH-1001-012-unauthenticated-probe",
      "rule":"inference_request_rate_spike","actor":"fixture-inert-probe","repository":"synthetic-inference-fixture"}
ctx=ssl.create_default_context(cafile="/ca/ca.pem")
req=Request(base+"/alerts",data=json.dumps(body,sort_keys=True,separators=(",",":")).encode(),
            headers={"Content-Type":"application/json"},method="POST")
try:
    with urlopen(req,context=ctx,timeout=8) as r: status=r.status
except HTTPError as e:
    status=e.code
print(json.dumps({"status":status,"authorization_header_sent":False,"probe_body_emitted":False},sort_keys=True))
'''


def _container(name, command, mounts, ports=None):
    value = {
        "name": name, "image": IMAGE, "imagePullPolicy": "IfNotPresent", "command": command,
        "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                            "runAsNonRoot": True, "runAsUser": 65534,
                            "readOnlyRootFilesystem": True,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "resources": {"requests": {"cpu": "10m", "memory": "24Mi"},
                       "limits": {"cpu": "100m", "memory": "64Mi"}},
        "volumeMounts": mounts,
    }
    if ports:
        value["ports"] = ports
    return value


def _deployment(name, container, volumes):
    return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": name}},
                     "template": {"metadata": {"labels": {"app": name}},
                                  "spec": {"automountServiceAccountToken": False,
                                           "securityContext": {"runAsNonRoot": True,"runAsUser": 65534,
                                                               "fsGroup": 65534},
                                           "containers": [container], "volumes": volumes}}}}


def _create(lab, obj):
    lab.kubectl("create", "-f", "-", payload=json.dumps(obj))


def _security(lab):
    try:
        with tempfile.TemporaryDirectory(prefix="saf-1001-012-alert-", dir=lab.kubeconfig.parent) as d:
            root=Path(d); os.chmod(root,0o700)
            ca_key=root/"ca.key"; ca_csr=root/"ca.csr"; ca_cert=root/"ca.pem"
            leaf_key=root/"tls.key"; leaf_csr=root/"tls.csr"; leaf_cert=root/"tls.crt"
            ca_ext=root/"ca.ext"; leaf_ext=root/"leaf.ext"
            username=root/"username"; password=root/"password"
            ca_ext.write_text("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\n")
            leaf_ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nsubjectAltName=DNS:"+DNS+"\n")
            username.write_text("fixture-alert-forwarder\n"); password.write_text(secrets.token_urlsafe(24)+"\n")
            for p in (ca_ext,leaf_ext,username,password): os.chmod(p,0o600)
            commands=[
              ["openssl","req","-new","-newkey","rsa:2048","-nodes","-keyout",str(ca_key),"-out",str(ca_csr),"-subj","/CN=SAF-K8S-1001-012 fixture CA"],
              ["openssl","x509","-req","-in",str(ca_csr),"-signkey",str(ca_key),"-days","1","-extfile",str(ca_ext),"-out",str(ca_cert)],
              ["openssl","req","-new","-newkey","rsa:2048","-nodes","-keyout",str(leaf_key),"-out",str(leaf_csr),"-subj","/CN="+DNS],
              ["openssl","x509","-req","-in",str(leaf_csr),"-CA",str(ca_cert),"-CAkey",str(ca_key),"-CAcreateserial","-days","1","-extfile",str(leaf_ext),"-out",str(leaf_cert)],
            ]
            for cmd in commands:
                subprocess.run(cmd,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20,env=lab.env)
            lab.kubectl("create","configmap","saf-1001-012-alert-ca",f"--from-file=ca.pem={ca_cert}")
            lab.kubectl("create","secret","tls","saf-1001-012-alert-tls",f"--cert={leaf_cert}",f"--key={leaf_key}")
            lab.kubectl("create","secret","generic","saf-1001-012-alert-auth",f"--from-file=username={username}",f"--from-file=password={password}")
    except Exception:
        lab.block("Could not prepare short-lived local alert receiver trust (details suppressed)")


def run(lab):
    _security(lab)
    telemetry=json.loads((HERE/"fixtures"/"telemetry.json").read_text(encoding="utf-8"))
    source_rows={row["id"]:row for row in telemetry["records"]}
    inputs=[]
    for fixture_id,event_id in (("SYNTH-1001-012-04A",EVENT_ID),("SYNTH-1001-012-04B",NEGATIVE_ID)):
        row=source_rows[fixture_id]
        inputs.append({key:value for key,value in row.items() if key in {
            "rule","requests_per_minute","baseline_requests_per_minute"}} | {"event_id":event_id})
    scripts={"receiver.py":RECEIVER,"deliver.py":DELIVER,"observe.py":OBSERVE,
             "no_credentials.py":NO_CREDENTIALS,
             "rate_predicate.py":(HERE/"fixtures"/"rate_predicate.py").read_text(encoding="utf-8"),
             "records.json":json.dumps({"thresholds":telemetry["thresholds"],"records":inputs},sort_keys=True)}
    _create(lab,{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"saf-1001-012-alert-code"},"immutable":True,"data":scripts})
    code={"name":"code","configMap":{"name":"saf-1001-012-alert-code"}}
    code_mount={"name":"code","mountPath":"/app","readOnly":True}
    tls={"name":"tls","secret":{"secretName":"saf-1001-012-alert-tls"}}
    auth={"name":"auth","secret":{"secretName":"saf-1001-012-alert-auth"}}
    ca={"name":"ca","configMap":{"name":"saf-1001-012-alert-ca"}}
    receiver=_container("receiver",["python","-B","/app/receiver.py"],
      [code_mount,{"name":"state","mountPath":"/state"},{"name":"tls","mountPath":"/tls","readOnly":True},{"name":"auth","mountPath":"/auth","readOnly":True}],
      [{"name":"https","containerPort":8443}])
    receiver["readinessProbe"]={"httpGet":{"path":"/health","port":"https","scheme":"HTTPS"},"periodSeconds":1}
    _create(lab,_deployment("saf-1001-012-alert-receiver",receiver,[code,{"name":"state","emptyDir":{"medium":"Memory","sizeLimit":"2Mi"}},tls,auth]))
    _create(lab,{"apiVersion":"v1","kind":"Service","metadata":{"name":SERVICE},"spec":{"selector":{"app":"saf-1001-012-alert-receiver"},"ports":[{"name":"https","port":8443,"targetPort":8443}]}})
    lab.kubectl("rollout","status","deployment/saf-1001-012-alert-receiver","--timeout=60s",timeout=70)
    pod_specs=(
      ("saf-1001-012-alert-sender","deliver.py",True),
      ("saf-1001-012-alert-no-credentials","no_credentials.py",False),
      ("saf-1001-012-alert-observer","observe.py",True),
    )
    for name, script, with_auth in pod_specs:
        mounts=[code_mount,{"name":"ca","mountPath":"/ca","readOnly":True}]
        volumes=[code,ca]
        if with_auth:
            mounts.append({"name":"auth","mountPath":"/auth","readOnly":True})
            volumes.append(auth)
        command=["python","-B","/app/"+script,"https://"+DNS+":8443"]
        pod={"apiVersion":"v1","kind":"Pod","metadata":{"name":name},"spec":{"restartPolicy":"Never","automountServiceAccountToken":False,
          "securityContext":{"runAsNonRoot":True,"runAsUser":65534,"seccompProfile":{"type":"RuntimeDefault"}},
          "containers":[_container(script.removesuffix(".py").replace("_","-"),command,mounts)],"volumes":volumes}}
        _create(lab,pod)
        lab.kubectl("wait","--for=jsonpath={.status.phase}=Succeeded",f"pod/{name}","--timeout=70s",timeout=80)
    sender=json.loads(lab.kubectl("logs","pod/saf-1001-012-alert-sender").stdout.strip().splitlines()[-1])
    no_credentials=json.loads(lab.kubectl("logs","pod/saf-1001-012-alert-no-credentials").stdout.strip().splitlines()[-1])
    observer=json.loads(lab.kubectl("logs","pod/saf-1001-012-alert-observer").stdout.strip().splitlines()[-1])
    passed=(sender=={"decision_count":2,"positive_triggered":True,"benign_suppressed":True,
                    "delivery_count":1,"delivery_statuses":[201],"credential_or_event_body_emitted":False}
            and observer=={"read_status":200,"exact_positive_present":True,"positive_id_present":True,
                           "benign_comparator_withheld":True,"record_count":1,"alert_body_emitted":False})
    lab.check("positive","A bounded synthetic positive is delivered over verified TLS and the receiver independently stores only that exact alert",
      passed,{"decision":sender,"independent_receiver_readback":observer,
              "tls_peer_verification":True,"credentials_or_raw_event_values_emitted":False,
              "external_targets_contacted":False,"siem_connected":False})
    lab.check("green","The receiver rejects a credential-free inert alert POST",
      no_credentials=={"status":401,"authorization_header_sent":False,"probe_body_emitted":False}
      and observer=={"read_status":200,"exact_positive_present":True,"positive_id_present":True,
                     "benign_comparator_withheld":True,"record_count":1,"alert_body_emitted":False},
      {"credential_free_status":no_credentials["status"],"authorization_header_sent":False,
       "probe_body_emitted":False,"receiver_still_contains_only_positive":observer["record_count"]==1})
    return {"sender":sender,"unauthenticated_probe":no_credentials,"receiver_readback":observer,
            "external_targets_contacted":False,"siem_connected":False}
