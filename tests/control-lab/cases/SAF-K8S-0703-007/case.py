"""Run Kueue cohort admission and fair-sharing reclamation on synthetic jobs."""
from hashlib import sha256
import json
import time

from fixtures import BUSYBOX_IMAGE

VERSION = "v0.20.6"
RELEASE = f"https://github.com/kubernetes-sigs/kueue/releases/download/{VERSION}/manifests.yaml"
RELEASE_SHA256 = "b5f643595cfe4799b47acd3499f535fb7137af1dd734a5a66ed67a4fe9f9e466"
IMAGE = f"registry.k8s.io/kueue/kueue:{VERSION}"
IMAGE_SHA256 = "20465f0e56a4eed90ec07fa7838866a90f7b6890c0adc84be86aaee307a6744a"
API = "kueue.x-k8s.io/v1beta2"
RESOURCE = "example.com/virtual-gpu"
TEAMS = ("team-a", "team-b")
JOB_OWNERS = {"a-baseline": "team-a", "a-borrowed": "team-a", "b-demand": "team-b"}
SCOPE = (
    "Kueue v0.20.6 controller with Fair Sharing and two single-unit quotas, "
    "on disposable kind Kubernetes v1.36.1. Three owned Kubernetes Jobs request "
    "only an unallocated synthetic resource. Kueue admission and reclamation "
    "are inspected, including the recovered nominal unit and queued overage. "
    "Actual devices and placement, broad fairness, access control and production "
    "integrations require separate evidence."
)


def create(lab, resource):
    namespace = resource["metadata"].get("namespace")
    arguments = ("-n", namespace) if namespace else ()
    lab.kubectl(*arguments, "create", "-f", "-", payload=json.dumps(resource))


def install(lab):
    package = lab.kubeconfig.parent / "kueue.yaml"
    lab.command("curl", "--fail", "--silent", "--show-error", "--location", "--max-time", "90",
                RELEASE, "-o", str(package), timeout=100)
    contents = package.read_bytes()
    if sha256(contents).hexdigest() != RELEASE_SHA256:
        lab.block("The official release manifest did not match its publisher digest")
    image = f"        image: {IMAGE}\n".encode()
    if contents.count(image) != 1:
        lab.block("The release manifest did not include its expected exact controller image")
    declaration = b"    #fairSharing:\n    #  preemptionStrategies: [LessThanOrEqualToFinalShare, LessThanInitialShare]\n"
    settings = b"    fairSharing:\n      preemptionStrategies: [LessThanOrEqualToFinalShare, LessThanInitialShare]\n"
    if contents.count(declaration) != 1:
        lab.block("The release manifest did not include the expected Fair Sharing configuration")
    manifest = contents.replace(image, f"        image: {IMAGE}@sha256:{IMAGE_SHA256}\n".encode())
    package.write_bytes(manifest.replace(declaration, settings))
    lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                "apply", "--server-side", "-f", str(package), timeout=120)
    deployment = "deploy/kueue-controller-manager"
    lab.kubectl("wait", "--for=condition=available", deployment, "-n", "kueue-system",
                "--timeout=150s", timeout=155)

    lab.check("positive", "The release manifest digest and pinned controller image are retained",
              True, {"release": VERSION, "manifest_digest": RELEASE_SHA256, "image_digest": IMAGE_SHA256})


def configure_queues(lab):
    flavor = {"apiVersion": API, "kind": "ResourceFlavor",
              "metadata": {"name": "virtual-capacity"}, "spec": {}}
    end = time.monotonic() + 40
    while True:
        result = lab.kubectl("create", "-f", "-", "--dry-run=server", payload=json.dumps(flavor),
                             allow_failure=True)
        if result.returncode == 0:
            break
        if "failed calling webhook" not in result.stderr or time.monotonic() >= end:
            lab.block(f"Kueue admission readiness: {result.stderr.strip()}")
        time.sleep(0.75)
    create(lab, flavor)
    for team in TEAMS:
        create(lab, {"apiVersion": "v1", "kind": "Namespace",
                     "metadata": {"name": team, "labels": {"saf-k8s.example/team": team}}})
        create(lab, {
            "apiVersion": API, "kind": "ClusterQueue", "metadata": {"name": f"{team}-cq"},
            "spec": {"namespaceSelector": {"matchLabels": {"saf-k8s.example/team": team}},
                     "cohortName": "virtual-capacity",
                     "resourceGroups": [{"coveredResources": [RESOURCE],
                                         "flavors": [{"name": "virtual-capacity",
                                                      "resources": [{"name": RESOURCE, "nominalQuota": "1"}]}]}],
                     "preemption": {"reclaimWithinCohort": "Never", "withinClusterQueue": "Never"},
                     "fairSharing": {"weight": "1"}},
        })
        create(lab, {"apiVersion": API, "kind": "LocalQueue",
                     "metadata": {"name": "virtual", "namespace": team},
                     "spec": {"clusterQueue": f"{team}-cq"}})
        lab.kubectl("wait", "--for=condition=Active", f"clusterqueue/{team}-cq",
                    "--timeout=60s", timeout=65)
        lab.kubectl("wait", "--for=condition=Active", "localqueue/virtual", "-n", team,
                    "--timeout=60s", timeout=65)


def job(lab, name):
    team = JOB_OWNERS[name]
    create(lab, {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": team, "labels": {"kueue.x-k8s.io/queue-name": "virtual"}},
        "spec": {"suspend": True, "backoffLimit": 0, "template": {"spec": {
            "restartPolicy": "Never", "automountServiceAccountToken": False,
            "containers": [{"name": "bounded", "image": BUSYBOX_IMAGE,
                            "command": ["sleep", "15"],
                            "resources": {"requests": {RESOURCE: "1"}, "limits": {RESOURCE: "1"}}}],
        }}},
    })


def objects(lab, command):
    args = command.split()
    return json.loads(lab.kubectl(*args, "-o", "json").stdout)


def observation(lab):
    out = {}
    for team in TEAMS:
        records = objects(lab, f"get workloads -n {team}")["items"]
        for record in records:
            names = [item["name"] for item in record["metadata"].get("ownerReferences", [])
                     if item["kind"] == "Job"]
            if len(names) != 1 or JOB_OWNERS.get(names[0]) != team:
                continue
            status = record.get("status", {})
            out[names[0]] = {
                "admitted": status.get("admission") is not None and any(
                    cond["type"] == "Admitted" and cond["status"] == "True"
                    for cond in status.get("conditions", [])),
                "reservation_denied": any(cond["type"] == "QuotaReserved" and cond["status"] == "False"
                                          and cond.get("reason") == "WaitingForQuota"
                                          and "insufficient unused quota" in cond.get("message", "")
                                          for cond in status.get("conditions", [])),
            }
    return out


def wait(lab, expected, description, *, pending=None):
    end = time.monotonic() + 85
    while True:
        states = observation(lab)
        if (all(name in states and states[name]["admitted"] == present for name, present in expected.items())
                and (pending is None or states.get(pending, {}).get("reservation_denied"))):
            return states
        if time.monotonic() >= end:
            lab.block(f"{description}. Controller status: {states}")
        time.sleep(0.75)


def observe_borrowing(lab):
    end = time.monotonic() + 45
    while True:
        status = objects(lab, "get clusterqueue team-a-cq").get("status", {})
        share = status.get("fairSharing", {}).get("weightedShare", 0)
        actual = next((entry for flavor in status.get("flavorsReservation", [])
                       for entry in flavor.get("resources", []) if entry.get("name") == RESOURCE), {})
        if status.get("reservingWorkloads") == 2 and actual.get("borrowed") == "1" and share > 0:
            return {"reservations": 2, "borrowed_units": actual["borrowed"], "weighted_share_positive": True}
        if time.monotonic() >= end:
            lab.block(f"ClusterQueue status did not account for the two reservations: {status}")
        time.sleep(0.5)


def run(lab):
    install(lab)
    configure_queues(lab)
    job(lab, "a-baseline")
    wait(lab, {"a-baseline": True}, "Team A could not reserve its nominal unit")
    job(lab, "a-borrowed")
    wait(lab, {"a-baseline": True, "a-borrowed": True}, "Team A could not borrow idle capacity")
    job(lab, "b-demand")
    red = wait(lab, {"a-baseline": True, "a-borrowed": True, "b-demand": False},
               "Team B did not reach the no-reclamation quota boundary", pending="b-demand")
    borrowed = observe_borrowing(lab)
    lab.check("red", "At full quota with reclamation disabled, team B remains pending while team A borrows",
              red["b-demand"]["reservation_denied"],
              {"team_a": borrowed, "team_b_quota_pending": red["b-demand"]["reservation_denied"]})

    lab.kubectl("patch", "clusterqueue", "team-b-cq", "--type=merge",
                "-p", '{"spec":{"preemption":{"reclaimWithinCohort":"Any"}}}')
    green = wait(lab, {"a-baseline": True, "a-borrowed": False, "b-demand": True},
                 "The waiting Job did not replace team A's borrowing under fair sharing")
    lab.check("green", "Enabling reclamation admits the same waiting Job and releases the borrowed unit",
              True, {name: state["admitted"] for name, state in green.items()})
    unrelated = [item for team in TEAMS for item in objects(lab, f"get pods -n {team}")["items"]
                 if item.get("spec", {}).get("nodeName")]
    lab.check("positive", "Both queues keep one admission while no synthetic Pod has a bound node",
              green["a-baseline"]["admitted"] and green["b-demand"]["admitted"] and not unrelated,
              {"team_a_retained_nominal": True, "team_b_reclaimed_nominal": True, "bound_pods": len(unrelated)})
