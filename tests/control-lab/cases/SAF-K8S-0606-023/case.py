"""Exercise a digest-pinned Checkov Terraform gate and CloudFormation scan."""
from hashlib import sha256
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent

NAMESPACE = "saf-test"
PYTHON_IMAGE = ("docker.io/library/python:3.13-slim"
                "@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90")
CHECKOV_IMAGE = (
    "ghcr.io/bridgecrewio/checkov:3.3.16"
    "@sha256:7407699a91a556849ae66e05c3753f58cf0ce922aa6ddfac7839aad4f390c016"
)
SCOPE = (
    "A disposable Kubernetes v1.36.1 kind cluster runs the official Checkov 3.3.16 image "
    "against case-owned inert Terraform files and an added CloudFormation fail/pass pair with a matching local hash-bound marker gate. The test observes "
    "one configured Checkov rule, real Job and process exit statuses, and separate marker gates for each format. "
    "It never initializes or applies infrastructure and has no cloud credentials. CloudFormation coverage "
    "is scanner behavior only, not gate enforcement; Pulumi, production CI protection, policy completeness, "
    "and production deployment blocking for each format require separate evidence."
)


def configmap(name, data):
    return {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": name, "labels": {"saf-k8s.example/control": "0606-023"}},
        "immutable": True, "data": data,
    }


def job_manifest(name, fixture_configmap, *, framework="terraform", check_id="CKV_AWS_20"):
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "labels": {"saf-k8s.example/control": "0606-023"}},
        "spec": {
            "activeDeadlineSeconds": 150, "backoffLimit": 0,
            "ttlSecondsAfterFinished": 3600,
            "template": {"metadata": {"labels": {"saf-k8s.example/control": "0606-023"}},
                "spec": {
                    "restartPolicy": "Never", "automountServiceAccountToken": False,
                    "securityContext": {
                        "runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001, "fsGroup": 10001,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [{
                        "name": "checkov", "image": CHECKOV_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["checkov"],
                        "args": ["--directory", "/terraform", "--framework", framework,
                                 "--check", check_id, "--output", "json",
                                 "--skip-download"],
                        "env": [{"name": "HOME", "value": "/tmp"},
                                {"name": "TMPDIR", "value": "/tmp"}],
                        "securityContext": {
                            "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]},
                        },
                        "volumeMounts": [
                            {"name": "terraform", "mountPath": "/terraform", "readOnly": True},
                            {"name": "tmp", "mountPath": "/tmp"},
                        ],
                    }],
                    "volumes": [
                        {"name": "terraform", "configMap": {"name": fixture_configmap}},
                        {"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}},
                    ],
                },
            },
        },
    }


def parse_report(raw):
    """Extract Checkov JSON despite any non-JSON informational prefix in stdout."""
    decoder = json.JSONDecoder()
    for offset, char in enumerate(raw):
        if char != "{":
            continue
        try:
            report, _ = decoder.raw_decode(raw[offset:])
        except json.JSONDecodeError:
            continue
        if isinstance(report, dict) and isinstance(report.get("results"), dict):
            return report
    raise ValueError("Checkov stdout did not contain a JSON report with results")


def stable_result(job_state, exit_code, report):
    results = report["results"]
    failed = results.get("failed_checks", [])
    passed = results.get("passed_checks", [])
    violations = sorted(
        ({"check_id": row.get("check_id"), "resource": row.get("resource"),
          "file": Path(row.get("file_path", "")).name}
         for row in failed),
        key=lambda row: (str(row["check_id"]), str(row["resource"]), str(row["file"])),
    )
    return {
        "job_state": job_state, "exit_code": exit_code,
        "failed_count": len(failed), "passed_count": len(passed),
        "violations": violations,
        "report_parseable": True,
    }


def run_scan(lab, case_name, terraform_file, *, framework="terraform", input_file="main.tf"):
    cm_name = f"iac-{case_name}-input"
    job_name = f"iac-{case_name}-check"
    source = (HERE / "fixtures" / terraform_file).read_text()
    lab.create(configmap(cm_name, {input_file: source}))
    lab.create(job_manifest(job_name, cm_name, framework=framework))

    deadline = time.monotonic() + 180
    terminal_state = None
    while time.monotonic() < deadline:
        job = json.loads(lab.kubectl("get", f"job/{job_name}", "-o", "json").stdout)
        conditions = {condition["type"] for condition in job.get("status", {}).get("conditions", [])
                      if condition.get("status") == "True"}
        if "Complete" in conditions:
            terminal_state = "Complete"
            break
        if "Failed" in conditions:
            terminal_state = "Failed"
            break
        time.sleep(1)
    if terminal_state is None:
        lab.block(f"Checkov Job {job_name} did not reach a terminal condition")

    pod_list = json.loads(lab.kubectl(
        "get", "pods", "-l", f"job-name={job_name}", "-o", "json").stdout)
    pods = pod_list.get("items", [])
    if len(pods) != 1:
        lab.block(f"Expected one Pod owned by Checkov Job {job_name}; observed {len(pods)}")
    statuses = pods[0].get("status", {}).get("containerStatuses", [])
    terminated = [status.get("state", {}).get("terminated") for status in statuses
                  if status.get("name") == "checkov"]
    if len(terminated) != 1 or not terminated[0]:
        lab.block(f"Checkov container in {job_name} has no terminal exit status")
    exit_code = terminated[0].get("exitCode")
    stdout = lab.kubectl("logs", f"job/{job_name}").stdout
    # Preserve raw scanner bytes/text separately; these may include timestamps, temp paths,
    # and image/runtime details. Stable replay assertions use only stable_result below.
    (lab.evidence / f"{case_name}.checkov.stdout.raw").write_text(stdout)
    report = parse_report(stdout)
    stable = stable_result(terminal_state, exit_code, report)
    digest_field = "terraform_sha256" if framework == "terraform" else "cloudformation_sha256"
    stable[digest_field] = sha256(source.encode()).hexdigest()
    (lab.evidence / f"{case_name}.checkov.observation.json").write_text(
        json.dumps(stable, sort_keys=True, indent=2) + "\n")
    return stable


def run_cloudformation_scan_pair(lab):
    red = run_scan(lab, "cloudformation-noncompliant", "noncompliant.yaml",
                   framework="cloudformation", input_file="template.yaml")
    green = run_scan(lab, "cloudformation-compliant", "compliant.yaml",
                     framework="cloudformation", input_file="template.yaml")
    violation_shape = (len(red["violations"]) == 1
                       and red["violations"][0].get("check_id") == "CKV_AWS_20"
                       and red["violations"][0].get("file") == "template.yaml"
                       and bool(red["violations"][0].get("resource")))
    red_ok = (red["job_state"] == "Failed" and red["exit_code"] == 1
              and red["failed_count"] == 1 and red["passed_count"] == 0
              and violation_shape and red["report_parseable"])
    green_ok = (green["job_state"] == "Complete" and green["exit_code"] == 0
                and green["failed_count"] == 0 and green["violations"] == []
                and green["passed_count"] == 1 and green["report_parseable"])
    lab.check("positive", "The pinned Checkov image scans inert CloudFormation with the expected fail/pass results",
              red_ok and green_ok,
              {"framework": "cloudformation", "check_id": "CKV_AWS_20",
               "noncompliant": red, "compliant": green})
    marker_name = "iac-cloudformation-promotion-marker"
    marker_absent_before_gate = marker(lab, marker_name) is None
    blocked = promote(lab, "cloudformation-noncompliant", red, source_file="template.yaml",
                      digest_key="cloudformation_sha256", marker_name=marker_name,
                      framework="cloudformation")
    marker_absent_after_red = marker(lab, marker_name) is None
    red_withheld = (blocked == {"withheld": True, "created": False,
                                "artifact_matches": True, "job_matches": True}
                    and marker_absent_after_red)
    promoted = promote(lab, "cloudformation-compliant", green, source_file="template.yaml",
                       digest_key="cloudformation_sha256", marker_name=marker_name,
                       framework="cloudformation")
    observed = marker(lab, marker_name)
    green_promoted = (
        promoted == {"withheld": False, "created": True,
                     "artifact_matches": True, "job_matches": True}
        and observed is not None
        and observed.get("data") == {
            "decision": "promoted", "scanner_job": "iac-cloudformation-compliant-check",
            "cloudformation_sha256": green["cloudformation_sha256"],
        }
    )
    lab.check("green", "The hash-bound gate withholds failed CloudFormation and marks only the exact clean template",
              marker_absent_before_gate and red_withheld and green_promoted,
              {"marker_absent_before_gate": marker_absent_before_gate,
               "failed_scan_withheld": red_withheld,
               "failed_marker_absent": marker_absent_after_red,
               "clean_template_promoted": green_promoted,
               "marker_data_matches_cloudformation_sha256": bool(
                   observed and observed.get("data", {}).get("cloudformation_sha256")
                   == green["cloudformation_sha256"]),
               "marker_kind": observed.get("kind") if observed else None})


def marker(lab, name="iac-promotion-marker"):
    result = lab.kubectl("get", f"configmap/{name}", "-o", "json", "--ignore-not-found")
    return json.loads(result.stdout) if result.stdout.strip() else None


def prepare_promoter(lab):
    name = "iac-promotion"
    rbac_api = "rbac.authorization.k8s.io"
    lab.create({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": name}})
    lab.create({
        "apiVersion": f"{rbac_api}/v1", "kind": "Role", "metadata": {"name": name},
        "rules": [
            {"apiGroups": ["batch"], "resources": ["jobs"], "verbs": ["get"],
             "resourceNames": ["iac-noncompliant-check", "iac-compliant-check",
                               "iac-cloudformation-noncompliant-check",
                               "iac-cloudformation-compliant-check"]},
            {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["create"]},
        ],
    })
    lab.create({
        "apiVersion": f"{rbac_api}/v1", "kind": "RoleBinding", "metadata": {"name": name},
        "subjects": [{"kind": "ServiceAccount", "name": name, "namespace": NAMESPACE}],
        "roleRef": {"apiGroup": rbac_api, "kind": "Role", "name": name},
    })


def promote(lab, case_name, verdict, *, source_file="main.tf",
            digest_key="terraform_sha256", marker_name="iac-promotion-marker",
            framework="terraform", check_id="CKV_AWS_20"):
    name = f"iac-{case_name}-promotion"
    input_name = f"iac-{case_name}-input"
    scan = f"iac-{case_name}-check"
    lab.create(configmap(name, {"promote.py": (HERE / "promotion_gate.py").read_text(),
                                "scan.json": json.dumps(verdict)}))
    lab.create({
        "apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": name},
        "spec": {"backoffLimit": 0, "template": {"spec": {
            "serviceAccountName": "iac-promotion", "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 10001,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "promotion", "image": PYTHON_IMAGE,
                "command": ["python", "/decision/promote.py", NAMESPACE, scan, input_name, CHECKOV_IMAGE,
                            source_file, digest_key, marker_name, framework, check_id],
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [{"name": "decision", "mountPath": "/decision", "readOnly": True},
                                 {"name": "terraform", "mountPath": "/terraform", "readOnly": True}],
            }],
            "volumes": [{"name": "decision", "configMap": {"name": name}},
                        {"name": "terraform", "configMap": {"name": input_name}}],
        }}},
    })
    ready = lab.kubectl("wait", "--for=condition=complete", f"job/{name}", "--timeout=80s",
                        timeout=90, allow_failure=True)
    result = lab.kubectl("logs", f"job/{name}", allow_failure=True)
    if ready.returncode or result.returncode:
        lab.block(f"Promotion fixture {name} did not finish")
    return json.loads(result.stdout)


def run(lab):
    marker_before = marker(lab) is None
    lab.check("positive", "The case starts without a promotion marker", marker_before,
              {"marker_absent_before_scan": marker_before})

    prepare_promoter(lab)
    red = run_scan(lab, "noncompliant", "noncompliant.tf")
    expected_violation = [{"check_id": "CKV_AWS_20",
                           "resource": "aws_s3_bucket.saf_lab_public_acl",
                           "file": "main.tf"}]
    red_expected = (red["job_state"] == "Failed" and red["exit_code"] == 1
                    and red["failed_count"] == 1 and red["violations"] == expected_violation)
    lab.check("red", "The real Checkov Job exits 1 on the exact CKV_AWS_20 public ACL violation",
              red_expected, red)

    blocked = promote(lab, "noncompliant", red)
    still_absent = marker(lab) is None
    lab.check("red", "The independent promotion fixture withholds its marker after the failed scan",
              blocked == {"withheld": True, "created": False, "artifact_matches": True, "job_matches": True}
              and still_absent, blocked | {"marker_absent": still_absent})

    green = run_scan(lab, "compliant", "compliant.tf")
    clean = (green["job_state"] == "Complete" and green["exit_code"] == 0
             and green["failed_count"] == 0 and not green["violations"]
             and green["passed_count"] == 1)
    lab.check("green", "The same real scanner accepts the private ACL fixture with exit 0",
              clean, green)

    promoted = promote(lab, "compliant", green)
    observed = marker(lab)
    created = (
        promoted == {"withheld": False, "created": True, "artifact_matches": True, "job_matches": True}
        and observed is not None
        and observed.get("data") == {"decision": "promoted", "scanner_job": "iac-compliant-check",
                                    "terraform_sha256": green["terraform_sha256"]}
    )
    lab.check("green", "The independent promotion fixture creates its marker after a clean scan",
              created, promoted | {"marker_matches": created})

    lab.check("positive", "The promoted marker is a case-owned inert ConfigMap",
              created and observed.get("kind") == "ConfigMap",
              {"kind": observed.get("kind") if observed else None,
               "scanner_job": observed.get("data", {}).get("scanner_job") if observed else None})

    run_cloudformation_scan_pair(lab)
