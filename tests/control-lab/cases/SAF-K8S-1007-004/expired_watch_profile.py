"""Run one isolated Kind profile proving expired NetworkPolicy watch recovery."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import uuid

NODE_IMAGE = ("kindest/node:v1.36.1@sha256:"
              "3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5")
PYTHON_IMAGE = ("docker.io/library/python:3.13-slim@sha256:"
                "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
NS = "saf-1007-004-expired-owned"
POLICY = "expired-watch-default-deny"
SA = "expired-policy-observer"
JOB = "expired-policy-observer"
LABEL = "saf-k8s.example/expired-watch-fixture"
BASELINE = {"podSelector": {"matchLabels": {"app": "inert"}}, "policyTypes": ["Ingress"]}
WIDENED = {**BASELINE, "ingress": [{}]}
CLIENT = r'''import json, os, pathlib, ssl, time, urllib.error, urllib.parse, urllib.request
ns=os.environ["WATCH_NAMESPACE"]; name=os.environ["WATCH_POLICY"]; expected_uid=os.environ["WATCH_UID"]
identity=pathlib.Path("/var/run/saf-watch"); token=(identity/"token").read_text().strip()
tls=ssl.create_default_context(cafile=str(identity/"ca.crt")); client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=tls))
base=f"https://kubernetes.default.svc/apis/networking.k8s.io/v1/namespaces/{ns}/networkpolicies"
selector=f"metadata.name={name}"
def emit(phase, **fields): print(json.dumps({"phase":phase,"observed_at_monotonic_ns":time.monotonic_ns(),**fields},sort_keys=True),flush=True)
def request(query, timeout=8):
    return urllib.request.Request(base+"?"+urllib.parse.urlencode(query),headers={"Accept":"application/json","Authorization":"Bearer "+token})
def listing():
    with client.open(request({"fieldSelector":selector}),timeout=8) as r: return json.load(r)
initial=listing(); item,=initial["items"]
assert item["metadata"]["uid"]==expected_uid and item["spec"]==json.loads(os.environ["EXPECTED_SPEC"])
old_rv=initial["metadata"]["resourceVersion"]
emit("checkpoint",list_resource_version=old_rv,uid=expected_uid,spec=item["spec"],pod_uid=os.environ["WATCH_POD_UID"])
gate=pathlib.Path("/gate")
def wait_gate(name, seconds):
    deadline=time.monotonic()+seconds
    while not (gate/name).exists():
        if time.monotonic()>=deadline: raise RuntimeError("bounded gate timed out")
        time.sleep(0.2)
wait_gate("try-expired",90)
query={"fieldSelector":selector,"watch":"true","resourceVersion":old_rv,"timeoutSeconds":2}
expired_status={"http_status":None,"status_code":None,"reason":None}
try:
    with client.open(request(query),timeout=5) as response:
        expired_status["http_status"]=response.status
        # A watch can deliver a Kubernetes Status in an in-stream ERROR event.
        line = response.readline(4097)
        if 0 < len(line) <= 4096:
            event = json.loads(line)
            status = event.get("object", {})
            if event.get("type") == "ERROR" and status.get("kind") == "Status":
                expired_status["status_code"] = status.get("code")
                expired_status["reason"] = status.get("reason")
except urllib.error.HTTPError as error:
    body=error.read(4096)
    expired_status["http_status"]=error.code
    try:
        status=json.loads(body)
        if status.get("kind")=="Status":
            expired_status["status_code"]=status.get("code")
            expired_status["reason"]=status.get("reason")
    except (ValueError,TypeError): pass
emit("expired_attempt",old_resource_version=old_rv,**expired_status,pod_uid=os.environ["WATCH_POD_UID"])
if expired_status["http_status"]!=410 and expired_status["status_code"]!=410:
    emit("not_expired",observed_http_status=expired_status["http_status"])
    raise RuntimeError("stale resourceVersion did not produce HTTP 410")
fresh=listing(); fresh_item,=fresh["items"]
assert fresh_item["metadata"]["uid"]==expected_uid and fresh_item["spec"]==json.loads(os.environ["EXPECTED_SPEC"])
fresh_rv=fresh["metadata"]["resourceVersion"]
emit("relisted",list_resource_version=fresh_rv,object_resource_version=fresh_item["metadata"]["resourceVersion"],uid=expected_uid,spec=fresh_item["spec"],pod_uid=os.environ["WATCH_POD_UID"])
wait_gate("resume",45)
query={"fieldSelector":selector,"watch":"true","resourceVersion":fresh_rv,"timeoutSeconds":20}
events=[]
with client.open(request(query),timeout=25) as response:
    emit("resumed",http_status=response.status,resource_version=fresh_rv,pod_uid=os.environ["WATCH_POD_UID"])
    for line in response:
        event=json.loads(line)
        if event.get("type")=="BOOKMARK": continue
        obj=event.get("object",{}); meta=obj.get("metadata",{})
        events.append({"type":event.get("type"),"uid":meta.get("uid"),"resource_version":meta.get("resourceVersion"),"generation":meta.get("generation"),"spec":obj.get("spec")})
        if len(events)==2: break
assert len(events)==2
emit("complete",events=events,pod_uid=os.environ["WATCH_POD_UID"])
'''

class ProfileLab:
    def __init__(self, parent, cluster, kubeconfig):
        self.parent, self.cluster, self.kubeconfig = parent, cluster, kubeconfig
        self.evidence = parent.evidence
    def command(self, *args, payload=None, timeout=45, allow_failure=False):
        return self.parent.command(*args, payload=payload, timeout=timeout, allow_failure=allow_failure)
    def kubectl(self, *args, timeout=30, payload=None, allow_failure=False):
        return self.command("kubectl", "--kubeconfig", str(self.kubeconfig), "--context", f"kind-{self.cluster}",
                            "--request-timeout=20s", *args, payload=payload, timeout=timeout, allow_failure=allow_failure)
    def check(self, *args, **kwargs): return self.parent.check(*args, **kwargs)
    def block(self, message): return self.parent.block(message)

def _json(lab, *args, payload=None, timeout=30):
    return json.loads(lab.kubectl(*args, "-o", "json", payload=payload, timeout=timeout).stdout)

def _logs(lab):
    result=lab.kubectl("-n",NS,"logs",f"job/{JOB}","--limit-bytes=32768",timeout=15,allow_failure=True)
    return [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]

def _wait_phase(lab, phase, timeout):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        records=_logs(lab)
        found=[record for record in records if record.get("phase")==phase]
        if found: return found[-1]
        time.sleep(1)
    raise RuntimeError(f"bounded wait expired for observer phase {phase}")

def _patch(lab, spec):
    patch = {"spec": {**spec, "ingress": spec.get("ingress")}}
    output=lab.kubectl("-n",NS,"patch","networkpolicy",POLICY,"--type=merge","-p",json.dumps(patch),"-o","json",timeout=20)
    obj=json.loads(output.stdout)
    return {"uid":obj["metadata"]["uid"],"resource_version":obj["metadata"]["resourceVersion"],"generation":obj["metadata"].get("generation"),"spec":obj["spec"]}

def run(parent_lab, case_dir):
    cluster="saf-expired-"+uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix="saf-expired-watch-") as tmp:
        root=Path(tmp); kubeconfig=root/"kubeconfig"; config=root/"kind.yaml"
        config.write_text("kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n  - role: control-plane\n"
                         "kubeadmConfigPatches:\n  - |\n    apiVersion: kubeadm.k8s.io/v1beta4\n    kind: ClusterConfiguration\n"
                         "    apiServer:\n      extraArgs:\n"
                         "        - name: watch-cache-sizes\n          value: networkpolicies.networking.k8s.io#0\n"
                         "        - name: etcd-compaction-interval\n          value: 15s\n")
        lab=ProfileLab(parent_lab,cluster,kubeconfig)
        created=False
        try:
            lab.command("kind","create","cluster","--name",cluster,"--image",NODE_IMAGE,"--config",str(config),
                        "--kubeconfig",str(kubeconfig),"--wait","90s",timeout=480)
            created=True
            lab.kubectl("wait","--for=condition=Ready","node","--all","--timeout=90s",timeout=95)
            api_pod=_json(lab,"-n","kube-system","get","pods","-l","component=kube-apiserver")
            pod,=api_pod["items"]
            apiserver_args=pod["spec"]["containers"][0]["command"]
            config_evidence={"cluster":cluster,"node_image":NODE_IMAGE,"watch_cache_size_arg":next((x for x in apiserver_args if x.startswith("--watch-cache-sizes=")),None),
                             "compaction_interval_arg":next((x for x in apiserver_args if x.startswith("--etcd-compaction-interval=")),None),
                             "apiserver_pod_uid":pod["metadata"]["uid"]}
            (lab.evidence/"expired-watch-apiserver-profile.raw.json").write_text(json.dumps(config_evidence,indent=2,sort_keys=True)+"\n")
            if config_evidence["watch_cache_size_arg"]!="--watch-cache-sizes=networkpolicies.networking.k8s.io#0" or config_evidence["compaction_interval_arg"]!="--etcd-compaction-interval=15s":
                raise RuntimeError("dedicated API-server profile did not preserve exact bounded flags")
            lab.kubectl("create","namespace",NS)
            lab.kubectl("-n",NS,"label","--overwrite","namespace",NS,LABEL+"=owned")
            policy={"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":POLICY,"namespace":NS,"labels":{LABEL:"owned"}},"spec":BASELINE}
            policy_live=_json(lab,"create","-f","-",payload=json.dumps(policy))
            uid=policy_live["metadata"]["uid"]
            lab.kubectl("-n",NS,"create","-f","-",payload=json.dumps({"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":SA,"namespace":NS,"labels":{LABEL:"owned"}},"automountServiceAccountToken":False}))
            lab.kubectl("-n",NS,"create","-f","-",payload=json.dumps({"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":SA,"namespace":NS},"rules":[{"apiGroups":["networking.k8s.io"],"resources":["networkpolicies"],"resourceNames":[POLICY],"verbs":["list","watch"]}]}))
            lab.kubectl("-n",NS,"create","-f","-",payload=json.dumps({"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":SA,"namespace":NS},"subjects":[{"kind":"ServiceAccount","name":SA,"namespace":NS}],"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":SA}}))
            cm={"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":JOB,"namespace":NS,"labels":{LABEL:"owned"}},"immutable":True,"data":{"client.py":CLIENT}}
            lab.kubectl("-n",NS,"create","-f","-",payload=json.dumps(cm))
            job={"apiVersion":"batch/v1","kind":"Job","metadata":{"name":JOB,"namespace":NS,"labels":{LABEL:"owned"}},"spec":{"backoffLimit":0,"activeDeadlineSeconds":300,"template":{"metadata":{"labels":{LABEL:"owned"}},"spec":{"restartPolicy":"Never","serviceAccountName":SA,"automountServiceAccountToken":False,"securityContext":{"runAsNonRoot":True,"runAsUser":65534,"fsGroup":65534,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"watch","image":PYTHON_IMAGE,"imagePullPolicy":"IfNotPresent","command":["python","-B","/fixture/client.py"],"env":[{"name":"WATCH_NAMESPACE","value":NS},{"name":"WATCH_POLICY","value":POLICY},{"name":"WATCH_UID","value":uid},{"name":"EXPECTED_SPEC","value":json.dumps(BASELINE)},{"name":"WATCH_POD_UID","valueFrom":{"fieldRef":{"fieldPath":"metadata.uid"}}}],"resources":{"requests":{"cpu":"10m","memory":"16Mi"},"limits":{"cpu":"100m","memory":"64Mi"}},"securityContext":{"readOnlyRootFilesystem":True,"allowPrivilegeEscalation":False,"capabilities":{"drop":["ALL"]}},"volumeMounts":[{"name":"fixture","mountPath":"/fixture","readOnly":True},{"name":"gate","mountPath":"/gate"},{"name":"identity","mountPath":"/var/run/saf-watch","readOnly":True}]}],"volumes":[{"name":"fixture","configMap":{"name":JOB}},{"name":"gate","emptyDir":{"medium":"Memory","sizeLimit":"1Mi"}},{"name":"identity","projected":{"sources":[{"serviceAccountToken":{"path":"token","expirationSeconds":3600}},{"configMap":{"name":"kube-root-ca.crt","items":[{"key":"ca.crt","path":"ca.crt"}]}}]}}]}}}}
            created_job=_json(lab,"-n",NS,"create","-f","-",payload=json.dumps(job))
            job_uid=created_job["metadata"]["uid"]
            checkpoint=_wait_phase(lab,"checkpoint",90)
            time.sleep(20)
            gap_widen=_patch(lab,WIDENED); gap_restore=_patch(lab,BASELINE)
            gap_live=_json(lab,"-n",NS,"get","networkpolicy",POLICY)
            if gap_live["metadata"]["uid"]!=uid or gap_live["spec"]!=BASELINE:
                raise RuntimeError("pre-expiry controlled policy writes did not restore the same owned object")
            time.sleep(35)  # With 15s compaction interval, allow bounded compaction after the checkpoint is older than the retained interval.
            _logs(lab)
            pod_list=_json(lab,"-n",NS,"get","pods","-l",f"batch.kubernetes.io/job-name={JOB}")
            pod,=pod_list["items"]
            pod_uid=pod["metadata"]["uid"]
            owner_ok=any(o.get("kind")=="Job" and o.get("uid")==job_uid and o.get("controller") is True for o in pod["metadata"].get("ownerReferences",[])) and pod["spec"].get("serviceAccountName")==SA
            lab.kubectl("-n",NS,"exec",pod["metadata"]["name"],"-c","watch","--","python","-B","-c","from pathlib import Path; Path('/gate/try-expired').touch(exist_ok=False)")
            expired=_wait_phase(lab,"expired_attempt",15)
            expiration_confirmed = expired.get("http_status") == 410 or expired.get("status_code") == 410
            if not expiration_confirmed:
                lab.block(f"Stale watch did not return an API expiration status: {expired}")
            relisted=_wait_phase(lab,"relisted",10)
            lab.kubectl("-n",NS,"exec",pod["metadata"]["name"],"-c","watch","--","python","-B","-c","from pathlib import Path; Path('/gate/resume').touch(exist_ok=False)")
            resumed=_wait_phase(lab,"resumed",10)
            after_widen=_patch(lab,WIDENED); after_restore=_patch(lab,BASELINE)
            lab.kubectl("-n",NS,"wait","--for=condition=Complete",f"job/{JOB}","--timeout=35s",timeout=40)
            records=_logs(lab); complete=_wait_phase(lab,"complete",5)
            events=complete.get("events",[])
            aged=(expired.get("observed_at_monotonic_ns",0)-checkpoint.get("observed_at_monotonic_ns",0))>=45_000_000_000
            identity_ok=(checkpoint.get("uid")==uid and expired.get("old_resource_version")==checkpoint.get("list_resource_version")
                         and checkpoint.get("pod_uid")==expired.get("pod_uid")==relisted.get("pod_uid")==resumed.get("pod_uid")==complete.get("pod_uid")==pod_uid
                         and resumed.get("http_status")==200 and resumed.get("resource_version")==relisted.get("list_resource_version")
                         and relisted.get("uid")==uid and relisted.get("spec")==BASELINE
                         and bool(checkpoint.get("list_resource_version")) and bool(relisted.get("list_resource_version"))
                         and relisted.get("list_resource_version")!=checkpoint.get("list_resource_version"))
            exact_events=(len(events)==2 and [event.get("type") for event in events]==["MODIFIED","MODIFIED"]
                          and [event.get("spec") for event in events]==[WIDENED,BASELINE]
                          and [event.get("resource_version") for event in events]==[after_widen["resource_version"],after_restore["resource_version"]]
                          and [event.get("generation") for event in events]==[after_widen["generation"],after_restore["generation"]]
                          and all(event.get("uid")==uid for event in events) and all(w["uid"]==uid for w in [gap_widen,gap_restore,after_widen,after_restore])
                          and len({e.get("resource_version") for e in events})==2)
            raw={"scope":{"cluster":cluster,"namespace":NS,"policy_name":POLICY,"policy_uid":uid,"job_uid":job_uid,"pod_uid":pod_uid,"service_account":SA,"no_external_target":True,"no_network_probes":True},"profile":config_evidence,"checkpoint":checkpoint,"pre_expiry_writes":[gap_widen,gap_restore],"pre_expiry_restored_get":{"uid":gap_live["metadata"]["uid"],"resource_version":gap_live["metadata"]["resourceVersion"],"spec":gap_live["spec"]},"stale_watch":expired,"fresh_list":relisted,"post_relist_writes":[after_widen,after_restore],"resumed":resumed,"events":events,"pod_job_owner_and_service_account_bound":owner_ok,"records":records}
            (lab.evidence/"expired-networkpolicy-watch-recovery.raw.json").write_text(json.dumps(raw,indent=2,sort_keys=True)+"\n")
            lab.check("positive","Stale named NetworkPolicy watch receives a real 410 and same observer relists exact owned state",expiration_confirmed and identity_ok and aged and owner_ok and config_evidence["watch_cache_size_arg"] is not None and config_evidence["compaction_interval_arg"] is not None,
                      {"observed_api_410":expiration_confirmed,"stale_checkpoint_aged_at_least_45s":bool(aged),"same_policy_uid_and_baseline_after_fresh_list":bool(identity_ok),"same_job_pod_service_account_identity":bool(owner_ok and expired.get("pod_uid")==relisted.get("pod_uid")),"resource_cache_disabled_only_for_networkpolicy":config_evidence["watch_cache_size_arg"]=="--watch-cache-sizes=networkpolicies.networking.k8s.io#0"})
            lab.check("green","Same observer resumes from fresh collection resourceVersion and matches next drift and recovery writes",exact_events and identity_ok,
                      {"resumed_watch_http_200":resumed.get("http_status")==200,"events_match_two_independent_writes":bool(exact_events),"fresh_list_resource_version_used":resumed.get("resource_version")==relisted.get("list_resource_version"),"watcher_identity_unchanged":bool(identity_ok)})
            # Confirm exact case-owned identities before namespace teardown.
            current_job=_json(lab,"-n",NS,"get","job",JOB)
            current_policy=_json(lab,"-n",NS,"get","networkpolicy",POLICY)
            if current_job["metadata"]["uid"]!=job_uid or current_policy["metadata"]["uid"]!=uid:
                raise RuntimeError("owned cleanup identity changed")
            lab.kubectl("delete","namespace",NS,"--wait=true","--timeout=30s",timeout=35)
        finally:
            deletion = lab.command("kind", "delete", "cluster", "--name", cluster,
                                   "--kubeconfig", str(kubeconfig), timeout=90, allow_failure=True)
            listing = lab.command("kind", "get", "clusters", timeout=25, allow_failure=True)
            nodes = lab.command("docker", "ps", "-aq", "--filter",
                                f"label=io.x-k8s.kind.cluster={cluster}", timeout=25, allow_failure=True)
            absent = (deletion.returncode == 0 and listing.returncode == 0
                      and cluster not in listing.stdout.splitlines()
                      and nodes.returncode == 0 and not nodes.stdout.strip())
            (lab.evidence / "expired-watch-profile-cleanup.raw.json").write_text(
                json.dumps({"cluster": cluster, "created": created, "deleted": absent}, indent=2) + "\n")
            if not absent:
                lab.block("The owned secondary watch cluster cleanup could not be verified")
