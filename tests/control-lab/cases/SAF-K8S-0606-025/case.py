"""Test the CI freshness decision on signed receipts and actual Git objects."""
import base64
from hashlib import sha256
import json
from pathlib import Path
import secrets

HERE=Path(__file__).resolve().parent
PYTHON=("docker.io/library/python:3.13-slim@sha256:"
        "e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
GIT=("docker.gitea.com/gitea:1.23.8-rootless@sha256:"
     "331875f35bdcc3c1110fc8410a4e809e3103ebb091ef424fec2df53ac1b658fc")
ACCOUNT="saf-freshness-promoter"
SCOPE=(
    "One disposable Kind cluster and synthetic clock. Separate in-cluster Jobs create "
    "and verify authenticated fixture receipts for exact artifacts. The gate reads "
    "real Git objects from a bundle, and proves bounded age, chronology and byte "
    "binding before creating inert markers. Real production source trust remains separate."
)


def git(lab, repo, *args):
    return lab.command("git","-C",str(repo),*args).stdout.strip()


def seed_repo(lab, work, specification):
    repo=work/"git-fixtures"
    repo.mkdir()
    git(lab,repo,"init","--template=","-b","main")
    reference=specification["reference_epoch"]
    rows, artifacts = [], {}
    for sample in specification["scenarios"]:
        name=sample["name"]
        epoch=reference-sample["source_age"]
        value=(json.dumps({"fixture":name,"source_epoch":epoch},sort_keys=True)+"\n").encode()
        (repo/"artifact.json").write_bytes(value)
        git(lab,repo,"add","artifact.json")
        lab.command("env",f"GIT_AUTHOR_DATE=@{epoch} +0000",f"GIT_COMMITTER_DATE=@{epoch} +0000",
                    "git","-C",str(repo),"-c","user.name=SAF fixture","-c","user.email=fixture@example.invalid",
                    "-c","core.hooksPath=/dev/null","-c","commit.gpgsign=false","commit","-m",name)
        commit=git(lab,repo,"rev-parse","HEAD")
        assert int(git(lab,repo,"show","-s","--format=%ct",commit))==epoch
        git(lab,repo,"branch",f"seed-{name}",commit)
        rows.append({"name":name,"commit":commit,"source_epoch":epoch,"build_epoch":reference-sample["build_age"]})
        artifacts[f"{name}.json"]=value
    bundle=work/"source.bundle"
    git(lab,repo,"bundle","create",str(bundle),"--all")
    return rows,artifacts,bundle.read_bytes()


def config(lab,name,values):
    lab.create({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":name},"immutable":True,
                "binaryData":{key:base64.b64encode(value).decode() for key,value in values.items()}})


def bootstrap(lab):
    rbac="rbac.authorization.k8s.io"
    lab.create({"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":ACCOUNT}})
    lab.create({"apiVersion":f"{rbac}/v1","kind":"Role","metadata":{"name":ACCOUNT},
                "rules":[{"apiGroups":[""],"resources":["configmaps"],"verbs":["create"]}]})
    lab.create({"apiVersion":f"{rbac}/v1","kind":"RoleBinding","metadata":{"name":ACCOUNT},
                "subjects":[{"kind":"ServiceAccount","name":ACCOUNT,"namespace":"saf-test"}],
                "roleRef":{"apiGroup":rbac,"kind":"Role","name":ACCOUNT}})


def run_job(lab,name,program,*,gate=False):
    mounts=[{"name":"input","mountPath":"/input","readOnly":True},
            {"name":"authority","mountPath":"/authority","readOnly":True}]
    volumes=[{"name":"input","configMap":{"name":name}},
             {"name":"authority","secret":{"secretName":"fixture-receipt-authority"}}]
    policy={"runAsNonRoot":True,"runAsUser":1000,"fsGroup":1000,"seccompProfile":{"type":"RuntimeDefault"}}
    security={"allowPrivilegeEscalation":False,"readOnlyRootFilesystem":True,"capabilities":{"drop":["ALL"]}}
    pod={"securityContext":policy,"automountServiceAccountToken":False,"restartPolicy":"Never",
         "volumes":volumes,"containers":[{"name":"execute","image":PYTHON,"command":["python","/input/"+program],
                                         "securityContext":security,"volumeMounts":mounts}]}
    if gate:
        work={"name":"work","mountPath":"/work"}
        mounts.extend((work,{"name":"credential","mountPath":"/var/run/secrets/kubernetes.io/serviceaccount",
                            "readOnly":True}))
        volumes.extend((
            {"name":"work","emptyDir":{}},
            {"name":"credential","projected":{"sources":[
                {"serviceAccountToken":{"path":"token","expirationSeconds":600}},
                {"configMap":{"name":"kube-root-ca.crt","items":[{"key":"ca.crt","path":"ca.crt"}]}},
            ]}},
        ))
        pod["serviceAccountName"]=ACCOUNT
        pod["initContainers"]=[{"name":"git","image":GIT,"securityContext":security,
                               "env":[{"name":"HOME","value":"/work"}],
                               "command":["sh","-ec","git clone -q /input/source.bundle /work/git && git -C /work/git for-each-ref --format='%(objectname) %(committerdate:unix)' refs/remotes/origin > /work/git-dates"],
                               "volumeMounts":[mounts[0],work]}]
    lab.create({"apiVersion":"batch/v1","kind":"Job","metadata":{"name":name},
                "spec":{"backoffLimit":0,"template":{"spec":pod}}})
    done=lab.kubectl("wait","--for=condition=complete",f"job/{name}","--timeout=80s",
                    timeout=90,allow_failure=True)
    if done.returncode:
        lab.kubectl("describe",f"job/{name}",allow_failure=True)
        lab.kubectl("logs",f"job/{name}","--all-containers",allow_failure=True)
        lab.block(f"Fixture Job {name} did not complete")
    return json.loads(lab.kubectl("logs",f"job/{name}","-c","execute").stdout)


def run(lab):
    spec=json.loads((HERE/"scenarios.json").read_text())
    work=lab.kubeconfig.parent
    rows,artifacts,bundle=seed_repo(lab,work,spec)
    authority=work/"fixture-hmac.key"
    authority.write_bytes(secrets.token_bytes(32))
    authority.chmod(0o600)
    lab.kubectl("create","secret","generic","fixture-receipt-authority",f"--from-file=key={authority}")
    authority.unlink()
    config(lab,"receipt-builder",artifacts | {
        "claims.json":json.dumps(rows).encode(),"receipts.py":(HERE/"receipts.py").read_bytes()})
    receipts=run_job(lab,"receipt-builder","receipts.py")
    lab.check("positive","The receipt Job signs the exact artifact bytes for every Git fixture",
              [r["claims"]["commit"] for r in receipts]==[r["commit"] for r in rows]
              and all(r["claims"]["sha256"]==sha256(artifacts[r["claims"]["name"]+".json"]).hexdigest()
                      for r in receipts),
              {"receipt_count":len(receipts),"commit_count":len({r["commit"] for r in rows})})
    bootstrap(lab)
    config(lab,"freshness-gate",artifacts | {
        "changed-bytes.json":b'{"fixture":"changed"}\n',"source.bundle":bundle,
        "receipts.json":json.dumps(receipts).encode(),"policy.json":json.dumps(spec).encode(),
        "gate.py":(HERE/"gate.py").read_bytes()})
    observed=run_job(lab,"freshness-gate","gate.py",gate=True)
    (lab.evidence/"fixture-receipts.json").write_text(json.dumps(receipts,indent=2)+"\n")
    if len(observed) != len(spec["scenarios"]):
        lab.block("Freshness Job returned the wrong number of fixture decisions")
    for sample,result in zip(spec["scenarios"],observed):
        name=sample["name"]
        marker=lab.kubectl("get",f"configmap/promotion-{name}","--ignore-not-found","-o","json").stdout
        marker_matches=bool(marker) and json.loads(marker)["data"]=={
            "digest":result["digest"],"commit":result["commit"]}
        correct=(
            result["name"]==name and result["reason"]==sample["reason"] and
            result["source_age"]==sample["source_age"] and result["build_age"]==sample["build_age"] and
            result["receipt_valid"] and result["source_matches"] and
            result["admitted"]==result["marker_created"]==sample["admitted"] and
            ((not marker) if not sample["admitted"] else marker_matches)
        )
        lab.check("green" if sample["admitted"] else "red",f"Freshness policy applies to the {name} fixture",
                  correct,result | {"marker_present":bool(marker)})
