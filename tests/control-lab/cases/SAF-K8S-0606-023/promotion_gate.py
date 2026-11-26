"""Run the fixture promotion decision inside a separate Kubernetes Job."""
from hashlib import sha256
import json
from pathlib import Path
import ssl
import sys
from urllib.request import Request, urlopen


def main():
    namespace, scan_job, input_name, image = sys.argv[1:5]
    source_file = sys.argv[5] if len(sys.argv) > 5 else "main.tf"
    digest_key = sys.argv[6] if len(sys.argv) > 6 else "terraform_sha256"
    marker_name = sys.argv[7] if len(sys.argv) > 7 else "iac-promotion-marker"
    framework = sys.argv[8] if len(sys.argv) > 8 else "terraform"
    check_id = sys.argv[9] if len(sys.argv) > 9 else "CKV_AWS_20"
    api = "https://kubernetes.default.svc"
    identity = Path("/var/run/secrets/kubernetes.io/serviceaccount")
    headers = {"Authorization": "Bearer " + (identity / "token").read_text().strip(),
               "Content-Type": "application/json"}
    tls = ssl.create_default_context(cafile=str(identity / "ca.crt"))

    def request(path, resource=None):
        payload = json.dumps(resource).encode() if resource else None
        with urlopen(Request(api + path, data=payload, headers=headers), context=tls, timeout=10) as response:
            return json.load(response)

    verdict = json.loads(Path("/decision/scan.json").read_text())
    subject = sha256((Path("/terraform") / source_file).read_bytes()).hexdigest()
    artifact_matches = subject == verdict[digest_key]
    job = request(f"/apis/batch/v1/namespaces/{namespace}/jobs/{scan_job}")
    pod = job["spec"]["template"]["spec"]
    condition = {row["type"] for row in job["status"].get("conditions", []) if row["status"] == "True"}
    containers = pod.get("containers", [])
    scan_args = ["--directory", "/terraform", "--framework", framework,
                 "--check", check_id, "--output", "json", "--skip-download"]
    input_volume = any(v.get("name") == "terraform"
                       and v.get("configMap", {}).get("name") == input_name
                       for v in pod.get("volumes", []))
    input_mount = (len(containers) == 1 and any(
        mount.get("name") == "terraform" and mount.get("mountPath") == "/terraform"
        and mount.get("readOnly") is True
        for mount in containers[0].get("volumeMounts", [])))
    job_matches = (
        len(containers) == 1 and containers[0].get("name") == "checkov"
        and containers[0].get("image") == image
        and containers[0].get("command") == ["checkov"]
        and containers[0].get("args") == scan_args
        and input_volume and input_mount
        and condition.intersection({"Complete", "Failed"}) == {verdict["job_state"]}
    )
    permitted = (
        artifact_matches and job_matches and "Complete" in condition
        and verdict["report_parseable"] and verdict["exit_code"] == 0
        and verdict["passed_count"] == 1 and verdict["failed_count"] == 0 and verdict["violations"] == []
    )
    created = False
    if permitted:
        marker = {
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": marker_name},
            "immutable": True,
            "data": {"decision": "promoted", "scanner_job": scan_job, digest_key: subject},
        }
        result = request(f"/api/v1/namespaces/{namespace}/configmaps", marker)
        created = result.get("data") == marker["data"]
    print(json.dumps({"withheld": not permitted, "created": created,
                      "artifact_matches": artifact_matches, "job_matches": job_matches}))


if __name__ == "__main__":
    main()
