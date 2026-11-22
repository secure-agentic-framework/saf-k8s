"""Run a SAF-K8S control case on a fresh local kind cluster."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent
NODE_IMAGE = "kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5"
NAMESPACE = "saf-test"


class CheckFailed(Exception):
    pass


class InfrastructureError(Exception):
    pass


class Lab:
    def __init__(self, evidence, context, kubeconfig):
        self.evidence = evidence
        self.cluster = f"saf-lab-{uuid.uuid4().hex[:12]}"
        self.kubeconfig = kubeconfig
        self.context = context
        self.env = dict(os.environ)
        for key in ("DOCKER_HOST", "KIND_CLUSTER_NAME", "KUBECONFIG", "KUBERNETES_MASTER"):
            self.env.pop(key, None)
        self.env.update(DOCKER_CONTEXT=context, KIND_EXPERIMENTAL_PROVIDER="docker")
        self.checks = []

    def command(self, *args, payload=None, timeout=45, allow_failure=False):
        with (self.evidence / "commands.log").open("a") as log:
            log.write(f"$ {shlex.join(args)}\n")
            if payload is not None:
                log.write(payload + "\n")
            try:
                result = subprocess.run(args, input=payload, text=True, capture_output=True,
                                        env=self.env, timeout=timeout)
            except (OSError, subprocess.TimeoutExpired) as error:
                log.write(f"{error}\n")
                raise InfrastructureError(str(error)) from error
            log.write(result.stdout + result.stderr + f"\n[exit {result.returncode}]\n\n")
        if result.returncode and not allow_failure:
            raise InfrastructureError(f"{args[0]} failed: {result.stderr.strip() or result.stdout.strip()}")
        return result

    def kubectl(self, *args, timeout=45, **kwargs):
        return self.command(
            "kubectl", "--kubeconfig", str(self.kubeconfig), "--context", f"kind-{self.cluster}",
            "--namespace", NAMESPACE, f"--request-timeout={timeout - 5}s", *args, timeout=timeout, **kwargs,
        )

    def create(self, resource, *, dry_run=False, allow_failure=False):
        flags = ["--dry-run=server"] if dry_run else []
        result = self.kubectl("create", "-f", "-", "-o", "json", *flags,
                              payload=json.dumps(resource), allow_failure=allow_failure)
        return result if allow_failure else json.loads(result.stdout)

    def apply(self, manifest):
        self.kubectl("apply", "-f", str(manifest))

    def block(self, reason):
        raise InfrastructureError(reason)

    def check(self, phase, claim, condition, observed):
        self.checks.append({"phase": phase, "claim": claim, "matched": bool(condition),
                            "observed": observed})
        print(f"{phase.upper()} {'OK' if condition else 'FAILED'}  {claim} ({observed})",
              flush=True)
        if not condition:
            raise CheckFailed(claim)


def load_case(control_id, control_hash):
    root = ROOT / "cases" / control_id
    versions = root / "catalog-cases.json"
    name = json.loads(versions.read_text()).get(control_hash, "case.py") if versions.is_file() else "case.py"
    if Path(name).name != name or Path(name).suffix != ".py":
        raise ValueError(f"Invalid case filename for {control_id}")
    path = root / name
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("control_case", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(control_id, control_case, index, docker_context):
    evidence = ROOT / "evidence" / control_id / (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    )
    prepare_kind = getattr(control_case, "prepare_kind", None)
    node_image = control_case.NODE_IMAGE if prepare_kind else NODE_IMAGE
    if not re.fullmatch(r"kindest/node:v\d+\.\d+\.\d+@sha256:[0-9a-f]{64}", node_image):
        raise ValueError(f"Invalid digest-pinned kind image for {control_id}")
    evidence.mkdir(parents=True, mode=0o700)
    report = {
        "control_id": control_id, "catalog_revision": index["revision"],
        "catalog_sha256": index["sha256"], "node_image": node_image,
        "control_sha256": index["controls"][control_id]["sha256"],
        "scope": control_case.SCOPE,
    }
    with tempfile.TemporaryDirectory(prefix="saf-lab-") as temp:
        temporary = Path(temp).resolve()
        lab = Lab(evidence, docker_context, temporary / "kubeconfig")
        owned = False
        report["cluster"] = lab.cluster
        try:
            endpoint = lab.command("docker", "context", "inspect", docker_context,
                                   "--format", "{{.Endpoints.docker.Host}}").stdout.strip()
            if not endpoint.startswith("unix://"):
                raise InfrastructureError(f"Select a local Docker Unix socket, got {endpoint!r}")
            lab.command("docker", "version", "--format", "{{.Server.Version}}")
            lab.command("kind", "version")
            clusters = lab.command("kind", "get", "clusters")
            if lab.cluster in clusters.stdout.splitlines():
                raise InfrastructureError(f"Cluster already exists: {lab.cluster}")
            config = Path(control_case.__file__).with_name("kind.yaml")
            if prepare_kind:
                config = Path(prepare_kind(lab, temporary)).resolve()
                if not config.is_relative_to(temporary) or not config.is_file():
                    raise InfrastructureError("Generated kind config must be inside the temporary workspace")
            config_args = ["--config", str(config)] if config.is_file() else []
            print(f"Starting {lab.cluster} on Docker context {docker_context}", flush=True)
            owned = True
            lab.command("kind", "create", "cluster", "--name", lab.cluster, "--image", node_image,
                        "--kubeconfig", str(lab.kubeconfig), "--wait", "90s",
                        *config_args, timeout=480)
            report["kubernetes"] = json.loads(lab.kubectl("version", "-o", "json").stdout)
            lab.kubectl("create", "namespace", NAMESPACE)
            lab.kubectl("wait", "--for=create", "serviceaccount/default", "--timeout=20s")
            control_case.run(lab)
            phases = {check["phase"] for check in lab.checks}
            if not {"red", "green", "positive"}.issubset(phases):
                raise InfrastructureError("A passing case must record red, green and positive observations")
            report["status"] = "passed"
        except CheckFailed as error:
            report.update(status="failed", error=str(error))
        except (InfrastructureError, json.JSONDecodeError) as error:
            report.update(status="blocked", error=str(error))
        except Exception as error:
            report.update(status="error", error=f"{type(error).__name__}: {error}")
        finally:
            if owned:
                try:
                    lab.command("kind", "delete", "cluster", "--name", lab.cluster,
                                "--kubeconfig", str(lab.kubeconfig), timeout=90)
                    report["cleanup"] = "deleted"
                except InfrastructureError as error:
                    report.update(cleanup="failed", cleanup_error=str(error))
            report["checks"] = lab.checks
            (evidence / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"{report['status'].upper()}  {control_id}")
    for key in ("error", "cleanup_error"):
        if key in report:
            print(report[key])
    print(f"Evidence: {evidence}")
    if report.get("cleanup") == "failed":
        return 3
    return {"passed": 0, "failed": 1, "blocked": 3, "error": 3}[report["status"]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list")
    test = commands.add_parser("test")
    test.add_argument("id", type=str.upper)
    test.add_argument("--catalog-index", type=Path, default=ROOT / "catalog/index.json")
    test.add_argument("--docker-context", default=os.getenv("DOCKER_CONTEXT") or "default")
    args = parser.parse_args()
    index_path = args.catalog_index if args.command == "test" else ROOT / "catalog/index.json"
    index = json.loads(index_path.read_text())
    if args.command == "list":
        for control_id, row in index["controls"].items():
            state = "case available" if (ROOT / "cases" / control_id / "case.py").is_file() else "queued"
            print(f"{control_id}\t{state}\t{row['title']}")
        return 0
    if args.id not in index["controls"]:
        print(f"Unknown catalog control: {args.id}")
        return 2
    control_case = load_case(args.id, index["controls"][args.id]["sha256"])
    if control_case is None:
        print(f"No executable case for {args.id}. See bd show saf-lab-{args.id[8:]}.")
        return 2
    return run(args.id, control_case, index, args.docker_context)


if __name__ == "__main__":
    raise SystemExit(main())
