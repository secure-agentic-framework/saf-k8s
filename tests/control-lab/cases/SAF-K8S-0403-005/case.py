"""Verify that a deployment diff preserves Secret output masking."""
import base64
import json
import subprocess


SCOPE = (
    "AI deployment manifest diff subcase. A case-owned Kubernetes Secret object "
    "contains only two public synthetic marker strings. kubectl v1.36.1 is exercised "
    "against a disposable kind cluster; ordinary diff output keeps the data masked. "
    "No raw values or diff content are retained."
)
FIELD_MANAGER = "saf-lab-diff"
NAME = "synthetic-diff-record"
BEFORE = "public-fixture-record-A"
AFTER = "public-fixture-record-B"


def run(lab):
    env = dict(lab.env)
    for key in ("KUBECTL_EXTERNAL_DIFF", "KUBECTL_PLUGINS_CALLER", "KUBECTL_PLUGINS_CURRENT_NAMESPACE"):
        env.pop(key, None)
    env["KUBECTL_KUBERC"] = "false"
    prefix = ["kubectl", "--kubeconfig", str(lab.kubeconfig), "--context",
              f"kind-{lab.cluster}", "--namespace", "saf-test", "--request-timeout=20s"]

    def private(args, payload=None):
        return subprocess.run(prefix + args, input=payload, env=env, capture_output=True,
                              text=True, timeout=30)

    client = private(["version", "--client", "-o", "json"])
    if client.returncode:
        lab.block("Unable to determine kubectl version")
    version = json.loads(client.stdout)["clientVersion"]["gitVersion"]
    if version != "v1.36.1":
        lab.block(f"The exact client for this case is v1.36.1; found {version}")

    encoded = [base64.b64encode(value.encode()).decode() for value in (BEFORE, AFTER)]

    def manifest(value):
        return json.dumps({"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                           "metadata": {"name": NAME, "namespace": "saf-test"},
                           "data": {"marker": value}})

    options = ["--server-side", "--field-manager", FIELD_MANAGER, "-f", "-"]
    created = private(["apply", *options, "-o", "name"], manifest(encoded[0]))
    lab.check("positive", "The synthetic fixture object was accepted",
              created.returncode == 0 and created.stdout.strip() == f"secret/{NAME}",
              {"accepted": created.returncode == 0, "client": version})
    revision_args = ["get", f"secret/{NAME}", "-o", "jsonpath={.metadata.resourceVersion}"]
    before = private(revision_args)
    lab.check("positive", "The fixture has a persisted resource version",
              before.returncode == 0 and before.stdout.strip().isdigit(),
              {"resource_version_present": before.stdout.strip().isdigit()})

    for phase, extra, should_show in (("red", ["--show-secrets=true"], True),
                                      ("green", [], False),
                                      ("green", ["--show-secrets=false"], False)):
        result = private(["diff", *options, *extra], manifest(encoded[1]))
        visible = [value in result.stdout + result.stderr for value in encoded]
        plain_visible = any(value in result.stdout + result.stderr for value in (BEFORE, AFTER))
        actual_diff = result.returncode == 1
        masked_change = all(mask in result.stdout for mask in ("*** (before)", "*** (after)"))
        lab.check(phase, f"Client reports a diff with marker values {'visible' if should_show else 'masked'}",
                  actual_diff and visible == [should_show, should_show]
                  and not plain_visible and (should_show or masked_change),
                  {"diff_detected": actual_diff, "before_visible": visible[0],
                   "after_visible": visible[1], "plain_values_visible": plain_visible,
                   "masked_change": masked_change})
    after = private(revision_args)
    lab.check("positive", "Comparisons leave the fixture resource version unchanged",
              after.returncode == 0 and before.stdout == after.stdout,
              {"same_revision": before.stdout == after.stdout})
