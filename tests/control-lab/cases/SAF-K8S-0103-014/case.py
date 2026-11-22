"""Verify default scheduler operational serving and native placement authorization."""
import json
from pathlib import Path
import subprocess
import time

from fixtures import container, pod


SCOPE = (
    "Stock kubeadm kind v1.36.1 IPv4: verify the scheduler operational loopback "
    "listener and a fixed HTTPS health status, exact Kubernetes pods/binding "
    "authorization for the scheduler and a synthetic workload submitter, and "
    "a fixture admission policy covering direct node assignment on Pod CREATE. "
    "A permitted Pod is placed by the real default scheduler. All mutations are "
    "case-owned, and direct placement requests are server-side dry-run only."
)
NS = "saf-test"
ACCOUNT = "saf-0103-014-submitter"
SUBJECT = f"system:serviceaccount:{NS}:{ACCOUNT}"
NAME = "saf-0103-014-scheduled"
DENIAL = "submit fixture Pods through the scheduler without choosing a direct node"


def can_bind(lab, subject):
    result = lab.kubectl("--as", subject, "auth", "can-i", "create",
                         f"pods/{NAME}", "--subresource=binding", allow_failure=True)
    answer = result.stdout.strip()
    if (result.returncode, answer) not in ((0, "yes"), (1, "no")):
        lab.block("Could not determine exact binding authorization")
    return answer == "yes"


def check_listener(lab):
    node = f"{lab.cluster}-control-plane"
    listeners = lab.command("docker", "exec", node, "ss", "-lntH", timeout=10).stdout
    endpoints = [line.split()[3] for line in listeners.splitlines() if len(line.split()) >= 4
                 and line.split()[3].rsplit(":", 1)[-1] == "10259"]
    lab.check("green", "Stock kind scheduler uses an IPv4 loopback operational listener",
              endpoints == ["127.0.0.1:10259"], {"secure_listeners": endpoints})
    raw = subprocess.run(
        ["docker", "exec", "--user=65534:65534", node, "/usr/bin/curl", "--silent",
         "--show-error", "--insecure", "--noproxy", "*", "--max-time", "6",
         "--output", "/dev/null", "--write-out", "%{http_code}",
         "https://127.0.0.1:10259/healthz"],
        env=lab.env, capture_output=True, text=True, timeout=10,
    )
    code = raw.stdout.strip()
    lab.check("positive", "The fixed operational health route remains available on loopback",
              raw.returncode == 0 and code == "200", {"http_status": code})


def submit(lab, fixture, *, dry_run):
    arguments = ["--dry-run=server"] if dry_run else []
    return lab.kubectl("--as", SUBJECT, "create", "-f", "-", "-o", "json", *arguments,
                       payload=json.dumps(fixture), allow_failure=True)


def setup_subject(lab):
    lab.kubectl("label", "namespace", NS, "saf-k8s.example/placement-policy=enabled")
    lab.kubectl("create", "serviceaccount", ACCOUNT)
    lab.kubectl("create", "role", ACCOUNT, "--verb=create", "--resource=pods")
    lab.kubectl("create", "rolebinding", ACCOUNT, f"--role={ACCOUNT}",
                f"--serviceaccount={NS}:{ACCOUNT}")


def run(lab):
    check_listener(lab)
    setup_subject(lab)
    authorized = can_bind(lab, "system:kube-scheduler")
    ordinary = can_bind(lab, SUBJECT)
    lab.check("green", "Only the scheduler of the two tested identities is authorized to bind the named Pod",
              authorized and not ordinary,
              {"scheduler_binding_authorized": authorized, "submitter_binding_authorized": ordinary})

    selected = f"{lab.cluster}-control-plane"
    direct = pod("saf-0103-014-direct", [container("probe")],
                 nodeName=selected, automountServiceAccountToken=False)
    baseline = submit(lab, direct, dry_run=True)
    lab.check("red", "A normal create grant alone permits an explicit nodeName in a server dry-run",
              baseline.returncode == 0, {"direct_request_dry_run_admitted": baseline.returncode == 0})

    lab.apply(Path(__file__).with_name("placement-policy.yaml"))
    deadline = time.monotonic() + 30
    while True:
        blocked = submit(lab, direct, dry_run=True)
        if blocked.returncode != 0 or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    exact = blocked.returncode != 0 and "(Forbidden)" in blocked.stderr and DENIAL in blocked.stderr
    lab.check("green", "Admission independently denies a direct nodeName on Pod CREATE",
              exact, {"exact_policy_denial": exact})

    fixture = pod(NAME, [container("probe")], automountServiceAccountToken=False)
    submitted = submit(lab, fixture, dry_run=False)
    if submitted.returncode:
        lab.block("The approved fixture Pod could not be submitted")
    lab.kubectl("wait", "--for=condition=PodScheduled", f"pod/{NAME}",
                "--timeout=60s", timeout=70)
    observed = json.loads(lab.kubectl("get", f"pod/{NAME}", "-o", "json").stdout)
    scheduled = observed["spec"].get("nodeName") == selected
    lab.check("positive", "A permitted workload without an explicit node is placed by the stock scheduler",
              scheduled, {"scheduled_on_owned_node": scheduled})
