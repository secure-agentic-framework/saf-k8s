"""Review kubelet node-name inputs and synthetic identity policy fixtures."""
import json
from pathlib import Path


CASE_DIR = Path(__file__).resolve().parent
FIXTURES = CASE_DIR / "fixtures.json"

SCOPE = (
    "Versioned review of kubelet naming and credential binding, plus read-only observations "
    "of a case-owned kind v1.36.1 cluster's Node name, OS hostname, actual kubelet flags "
    "and configured Node authorization and NodeRestriction. Synthetic cases cover naming "
    "governance and documented enrollment requirements. Live credential binding and real "
    "provider naming or enrollment evidence remain separate."
)


def authorization_findings(document):
    """Check documented authorization posture, not runtime credentials."""
    findings = []
    modes = document.get("authorization_mode", [])
    config = document.get("authorization_configuration", {})
    configured = [item.get("type") for item in config.get("authorizers", [])
                  if isinstance(item, dict)]
    if "Node" not in modes and "Node" not in configured:
        findings.append("Node authorizer is absent from documented API-server authorization")
    if document.get("node_identity_username") != "system:node:<registered-node-name>":
        findings.append("documented kubelet username is not bound to the registered Node name")
    if "system:nodes" not in document.get("node_identity_groups", []):
        findings.append("documented kubelet identity omits system:nodes")
    return findings


def provisioning_findings(policy, observation):
    """Evaluate synthetic name governance against source observations."""
    findings = []
    names = observation.get("registered_node_names", [])
    if not names or any(not isinstance(name, str) or not name for name in names):
        findings.append("registered Node name set is empty or malformed")
    if len(names) != len(set(names)):
        findings.append("registered Node names are not unique")

    allowed = set(policy.get("approved_node_names", []))
    if any(name not in allowed for name in names):
        findings.append("registered Node name is absent from the provisioning approval")

    for item in observation.get("node_sources", []):
        name = item.get("registered_node_name")
        override = item.get("hostname_override")
        if override and override != name:
            findings.append(f"hostname override differs from registered Node name for {name}")
        approval = policy.get("approved_overrides", {}).get(name, {})
        if override and (override != approval.get("value") or not approval.get("reason")):
            findings.append(f"hostname override lacks a matching documented exception for {name}")
        if not override and item.get("hostname") != name:
            findings.append(f"default hostname differs from registered Node name for {name}")
    return findings


def check_fixtures(lab):
    data = json.loads(FIXTURES.read_text(encoding="utf-8"))
    bad_auth = authorization_findings(data["authorization_documents"]["red"])
    lab.check(
        "red", "Synthetic authorization document detects missing Node identity requirements",
        len(bad_auth) == 3, bad_auth,
    )
    good_auth = authorization_findings(data["authorization_documents"]["green"])
    lab.check(
        "green", "Synthetic authorization document records Node authorizer and identity binding",
        good_auth == [], good_auth,
    )

    bad_policy = data["provisioning_cases"]["red"]
    bad_findings = provisioning_findings(bad_policy["policy"], bad_policy["observation"])
    lab.check(
        "red", "Synthetic provisioning policy detects unapproved and duplicate names",
        len(bad_findings) >= 3 and any("unique" in item for item in bad_findings),
        bad_findings,
    )
    good_policy = data["provisioning_cases"]["green"]
    good_findings = provisioning_findings(good_policy["policy"], good_policy["observation"])
    lab.check(
        "green", "Synthetic approved names are consistent and unique",
        good_findings == [], good_findings,
    )


def kind_hostname_sources(lab):
    node = f"{lab.cluster}-control-plane"
    reported = json.loads(lab.kubectl("get", "nodes", "-o", "json").stdout)["items"]
    hostname = lab.command("docker", "exec", node, "hostname").stdout.strip()
    pid = lab.command("docker", "exec", node, "systemctl", "show", "kubelet.service",
                      "--property=MainPID", "--value").stdout.strip()
    if not pid.isdecimal() or pid == "0":
        lab.block("The selector did not identify the case-owned kubelet process")
    script = r"""tr '\000' '\n' < "/proc/$1/cmdline" | awk '
      previous { print; previous=0; next }
      /^--hostname-override$/ { previous=1; next }
      /^--hostname-override=/ { sub(/^--hostname-override=/, ""); print }
    '"""
    overrides = lab.command("docker", "exec", node, "sh", "-ec", script, "probe", pid).stdout.splitlines()
    exact = len(reported) == 1 and reported[0]["metadata"]["name"] == hostname == node
    lab.check("positive", "The registered Node matches the case hostname and has no override",
              exact and not overrides, {"node_hostname_matches": exact, "explicit_overrides": len(overrides)})

    apis = json.loads(lab.kubectl("-n", "kube-system", "get", "pods", "-l", "component=kube-apiserver",
                                 "-o", "json").stdout)["items"]
    if len(apis) != 1:
        lab.block("Expected one API server in the case cluster")
    args = apis[0]["spec"]["containers"][0]["command"]
    selected = {}
    for name in ("authorization-mode", "enable-admission-plugins"):
        prefix = f"--{name}="
        selected[name] = next((arg[len(prefix):].split(",") for arg in args
                               if arg.startswith(prefix)), [])
    lab.check("positive", "The API server is configured for Node authorization and NodeRestriction",
              "Node" in selected["authorization-mode"]
              and "NodeRestriction" in selected["enable-admission-plugins"], selected)


def run(lab):
    check_fixtures(lab)
    kind_hostname_sources(lab)


class StaticReporter:
    """Reporter for static synthetic fixture checks; it does not contact a cluster."""

    def __init__(self):
        self.failed = False

    def check(self, phase, claim, condition, observed):
        print(f"{'PASS' if condition else 'FAIL'} [{phase}] {claim}")
        if not condition:
            print(f"  observed: {observed!r}")
            self.failed = True


if __name__ == "__main__":
    reporter = StaticReporter()
    check_fixtures(reporter)
    raise SystemExit(1 if reporter.failed else 0)
