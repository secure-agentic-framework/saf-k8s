"""Run a SAF-K8S control case on a fresh local kind cluster."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import tempfile
import time
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


def load_case(control_id, control_hash, *, directory=None):
    root = directory if directory is not None else ROOT / "cases" / control_id
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


def case_files(source):
    if not source.is_dir() or source.is_symlink():
        raise InfrastructureError("The reviewed case directory is missing or is a symlink")
    files = {}
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise InfrastructureError(f"A reviewed case cannot contain a symlink: {path.name}")
        if path.is_dir() or "__pycache__" in path.parts:
            continue
        if not path.is_file():
            raise InfrastructureError(f"A reviewed case may contain only regular files: {path.name}")
        files[path.relative_to(source)] = (path.stat().st_mode & 0o777, path.read_bytes())
    if Path("kind.yaml") in files:
        raise InfrastructureError("Early startup requires the default Kind layout")
    return files


def approval_record(control_id, index, files):
    entries = [(path.as_posix(), mode, hashlib.sha256(raw).hexdigest())
               for path, (mode, raw) in files.items()]
    return {
        "control_id": control_id,
        "catalog_revision": index["revision"],
        "catalog_sha256": index["sha256"],
        "control_sha256": index["controls"][control_id]["sha256"],
        "node_image": NODE_IMAGE,
        "case_sha256": hashlib.sha256(json.dumps(entries).encode()).hexdigest(),
    }


def approve(control_id, index, destination):
    files = case_files(ROOT / "cases" / control_id)
    record = approval_record(control_id, index, files)
    with tempfile.NamedTemporaryFile(mode="w", prefix=".approval-", dir=destination.parent,
                                     delete=False) as output:
        temporary = Path(output.name)
        json.dump(record, output)
    try:
        os.link(temporary, destination)
    finally:
        temporary.unlink()


def load_approved_case(control_id, index, marker, timeout, destination, report):
    pending = time.monotonic() + timeout
    while time.monotonic() < pending and not marker.is_file():
        time.sleep(0.2)
    if time.monotonic() >= pending:
        raise InfrastructureError("Case approval expired")

    if marker.is_symlink():
        raise InfrastructureError("Approval file cannot be a symlink")
    with marker.open() as record:
        approval = json.load(record)
        approved_at = os.fstat(record.fileno()).st_mtime
    files = case_files(ROOT / "cases" / control_id)
    if approval != approval_record(control_id, index, files):
        raise InfrastructureError("Approval does not match the exact case and catalog snapshot")
    for name, (mode, raw) in files.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(mode)
    case = load_case(control_id, approval["control_sha256"], directory=destination)
    if case is None or getattr(case, "prepare_kind", None):
        raise InfrastructureError("Early startup requires an executable case with the default Kind layout")
    report["review_timing"]["approval_at"] = datetime.fromtimestamp(approved_at, timezone.utc).isoformat()
    report["review_timing"]["case_loaded_at"] = datetime.now(timezone.utc).isoformat()
    report["approved_case_sha256"] = approval["case_sha256"]
    return case


def interrupt_approval_run(_signum, _frame):
    raise KeyboardInterrupt


def run(control_id, control_case, index, docker_context, *, approval_file=None, approval_timeout=180):
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
        "scope": control_case.SCOPE if control_case else None,
    }
    if approval_file is not None:
        report["review_timing"] = {"queued_at": datetime.now(timezone.utc).isoformat()}
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
            config = Path(control_case.__file__).with_name("kind.yaml") if control_case else None
            if prepare_kind:
                config = Path(prepare_kind(lab, temporary)).resolve()
                if not config.is_relative_to(temporary) or not config.is_file():
                    raise InfrastructureError("Generated kind config must be inside the temporary workspace")
            config_args = ["--config", str(config)] if config is not None and config.is_file() else []
            print(f"Starting {lab.cluster} on Docker context {docker_context}", flush=True)
            owned = True
            lab.command("kind", "create", "cluster", "--name", lab.cluster, "--image", node_image,
                        "--kubeconfig", str(lab.kubeconfig), "--wait", "90s",
                        *config_args, timeout=480)
            report["kubernetes"] = json.loads(lab.kubectl("version", "-o", "json").stdout)
            lab.kubectl("create", "namespace", NAMESPACE)
            lab.kubectl("wait", "--for=create", "serviceaccount/default", "--timeout=20s")
            if approval_file is not None:
                report["review_timing"]["cluster_ready_at"] = datetime.now(timezone.utc).isoformat()
                print("Cluster ready for reviewed case", flush=True)
                control_case = load_approved_case(control_id, index, approval_file, approval_timeout,
                                                  temporary / control_id, report)
                report["scope"] = control_case.SCOPE
            control_case.run(lab)
            phases = {check["phase"] for check in lab.checks}
            if not {"red", "green", "positive"}.issubset(phases):
                raise InfrastructureError("A passing case must record red, green and positive observations")
            report["status"] = "passed"
        except KeyboardInterrupt:
            if approval_file is None:
                raise
            report.update(status="blocked", error="Case run cancelled")
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
    test.add_argument("--await-approval", type=Path, metavar="FILE")
    test.add_argument("--approval-timeout", type=int, default=180, metavar="SECONDS",
                      help="Seconds to wait for approval after the fresh cluster is ready")
    approval = commands.add_parser("approve", help="Approve the reviewed case and catalog snapshot")
    approval.add_argument("id", type=str.upper)
    approval.add_argument("file", type=Path)
    approval.add_argument("--catalog-index", type=Path, default=ROOT / "catalog/index.json")
    args = parser.parse_args()
    index_path = args.catalog_index if args.command in {"test", "approve"} else ROOT / "catalog/index.json"
    index = json.loads(index_path.read_text())
    if args.command == "list":
        for control_id, row in index["controls"].items():
            state = "case available" if (ROOT / "cases" / control_id / "case.py").is_file() else "queued"
            print(f"{control_id}\t{state}\t{row['title']}")
        return 0
    if args.id not in index["controls"]:
        print(f"Unknown catalog control: {args.id}")
        return 2
    if args.command == "approve":
        try:
            approve(args.id, index, args.file)
        except (InfrastructureError, OSError) as error:
            parser.error(str(error))
        return 0
    if args.await_approval is not None:
        if args.await_approval.exists() or args.await_approval.is_symlink():
            parser.error("Use a new approval file for each run")
        if args.approval_timeout < 1:
            parser.error("Approval timeout must be at least one second")
        if (ROOT / "cases" / args.id / "kind.yaml").exists():
            parser.error("Early startup requires the default Kind layout")
        old_handler = signal.signal(signal.SIGTERM, interrupt_approval_run)
        try:
            return run(args.id, None, index, args.docker_context,
                       approval_file=args.await_approval, approval_timeout=args.approval_timeout)
        finally:
            signal.signal(signal.SIGTERM, old_handler)
    control_case = load_case(args.id, index["controls"][args.id]["sha256"])
    if control_case is None:
        print(f"No executable case for {args.id}. See bd show saf-lab-{args.id[8:]}.")
        return 2
    return run(args.id, control_case, index, args.docker_context)


if __name__ == "__main__":
    raise SystemExit(main())
