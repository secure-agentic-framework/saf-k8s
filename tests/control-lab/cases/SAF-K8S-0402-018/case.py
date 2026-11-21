"""Reject application Pods using the shared default ServiceAccount."""
import json
from pathlib import Path
import time

from fixtures import container, pod

SCOPE = "Application Pod admission and default ServiceAccount automount, with a documented system fixture."
APP_NAMESPACE = "saf-test"
SYSTEM_NAMESPACE = "saf-platform-system"
TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
DENIAL = "default ServiceAccount is prohibited"


def workload(name, service_account):
    spec = {"serviceAccountName": service_account} if service_account else {}
    return pod(name, [container("probe")], **spec)


def token_state(lab, name, *, namespace=APP_NAMESPACE, service_account=None):
    resource = workload(name, service_account)
    lab.kubectl("-n", namespace, "create", "-f", "-", "-o", "name",
                payload=json.dumps(resource))
    lab.kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{name}",
                "--timeout=95s", timeout=105)
    result = lab.kubectl(
        "-n", namespace, "exec", name, "--", "sh", "-c",
        'if test -s "$1"; then printf present; else printf absent; fi', "probe", TOKEN,
    )
    return result.stdout.strip()


def probe(lab, name, service_account=None):
    return lab.create(workload(name, service_account), dry_run=True, allow_failure=True)


def denied(result):
    return result.returncode != 0 and "(Forbidden)" in result.stderr and DENIAL in result.stderr


def run(lab):
    for name, service_account in (("implicit-default", None), ("explicit-default", "default")):
        result = probe(lab, name, service_account)
        defaulted = result.returncode == 0 and json.loads(result.stdout)["spec"]["serviceAccountName"] == "default"
        lab.check("red", f"{name} is admitted as default before policy", defaulted,
                  "serviceAccountName=default" if defaulted else result.stderr.strip())

    observed = token_state(lab, "default-token-before")
    lab.check("red", "Default ServiceAccount automatically mounts a token", observed == "present", observed)

    case_dir = Path(__file__).parent
    lab.apply(case_dir / "fixture.yaml")
    observed = token_state(lab, "default-token-disabled")
    lab.check("green", "Hardened application default ServiceAccount automount is disabled",
              observed == "absent", observed)

    lab.kubectl("create", "namespace", SYSTEM_NAMESPACE)
    lab.kubectl("label", "namespace", SYSTEM_NAMESPACE, "saf-k8s.example/class=platform-managed-system")
    lab.kubectl("annotate", "namespace", SYSTEM_NAMESPACE,
                "saf-k8s.example/approval=lab fixture for a platform component requiring Kubernetes API access")
    lab.kubectl("-n", SYSTEM_NAMESPACE, "wait", "--for=create", "serviceaccount/default", "--timeout=20s")
    lab.kubectl("-n", SYSTEM_NAMESPACE, "apply", "-f",
                str(case_dir / "system-default-serviceaccount.yaml"))
    lab.apply(case_dir / "admission-policy.yaml")

    deadline = time.monotonic() + 15
    while True:
        implicit = probe(lab, "implicit-default-after")
        if denied(implicit) or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    explicit = probe(lab, "explicit-default-after", "default")
    for description, result in (("implicit", implicit), ("explicit", explicit)):
        lab.check("green", f"Policy denies {description} default ServiceAccount use",
                  denied(result), result.stderr.strip())

    dedicated = token_state(lab, "dedicated-identity", service_account="saf-app")
    lab.check("positive", "Dedicated application ServiceAccount is admitted and has its token",
              dedicated == "present", dedicated)
    system = token_state(lab, "platform-component", namespace=SYSTEM_NAMESPACE, service_account="default")
    lab.check("positive", "Documented system exception is admitted with default automount",
              system == "present", system)
