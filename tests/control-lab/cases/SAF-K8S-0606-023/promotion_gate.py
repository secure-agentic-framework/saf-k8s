"""Run the fixture promotion decision inside a separate Kubernetes Job."""
from hashlib import sha256
import json
from pathlib import Path
import ssl
import sys
from urllib.request import Request, urlopen


def main():
    namespace, scan_job, input_name, image = sys.argv[1:]
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
    subject = sha256(Path("/terraform/main.tf").read_bytes()).hexdigest()
    artifact_matches = subject == verdict["terraform_sha256"]
    job = request(f"/apis/batch/v1/namespaces/{namespace}/jobs/{scan_job}")
    pod = job["spec"]["template"]["spec"]
    condition = {row["type"] for row in job["status"].get("conditions", []) if row["status"] == "True"}
    job_matches = (
        {row["image"] for row in pod["containers"]} == {image}
        and any(v.get("configMap", {}).get("name") == input_name for v in pod["volumes"])
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
            "metadata": {"name": "iac-promotion-marker"},
            "immutable": True,
            "data": {"decision": "promoted", "scanner_job": scan_job, "terraform_sha256": subject},
        }
        result = request(f"/api/v1/namespaces/{namespace}/configmaps", marker)
        created = result.get("data") == marker["data"]
    print(json.dumps({"withheld": not permitted, "created": created,
                      "artifact_matches": artifact_matches, "job_matches": job_matches}))


if __name__ == "__main__":
    main()
