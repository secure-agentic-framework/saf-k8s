"""Dispatch approved hardware cases on the existing disposable A100 guest."""

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "manifest.json"
KUBECONFIG = "/etc/rancher/k3s/k3s.yaml"
EXPORTER_SELECTOR = "app.kubernetes.io/name=dcgm-exporter"
CASE_IDS = ("SAF-K8S-0802-008", "SAF-K8S-0805-001", "SAF-K8S-0805-003", "SAF-K8S-0805-004")


class Interrupted(RuntimeError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        return None


def utc():
    return datetime.now(timezone.utc).isoformat()


def checksum(path):
    digest = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_bundle(expected):
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or MANIFEST.is_symlink() or checksum(MANIFEST) != expected:
        raise SystemExit("The manifest differs from the staged operator checksum")
    doc = json.loads(MANIFEST.read_text())
    if doc.get("schema") != "saf-a100-hardware-bundle-v1":
        raise SystemExit("Unexpected guest bundle manifest")
    files = doc["files"]
    found = set()
    for item in ROOT.rglob("*"):
        if item.is_symlink():
            raise SystemExit("Symlink found in the guest bundle")
        if item.is_dir() or item == MANIFEST:
            continue
        key = item.relative_to(ROOT).as_posix()
        if not item.is_file() or key not in files or checksum(item) != files[key]:
            raise SystemExit(f"Unapproved or modified guest bundle member: {key}")
        found.add(key)
    if found != set(files):
        raise SystemExit("Guest bundle members are missing")
    return doc


def existing_guest():
    if os.geteuid() != 0 or not re.fullmatch(r"saf-a100-[0-9]{10}", socket.gethostname()):
        raise SystemExit("Run as root on the dedicated, already-authorized A100 guest")
    request = Request("http://169.254.169.254/computeMetadata/v1/instance/id",
                      headers={"Metadata-Flavor": "Google"})
    with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=4) as response:
        instance = response.read(32).decode("ascii").strip()
        if response.headers.get("Metadata-Flavor") != "Google" or not re.fullmatch(r"[1-9][0-9]{1,20}", instance):
            raise SystemExit("Could not confirm the exact Google Cloud guest identity")
    epoch = next(line.split()[1] for line in Path("/proc/stat").read_text().splitlines() if line.startswith("btime "))
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot):
        raise SystemExit("Could not confirm the current kernel boot identity")
    return instance, epoch, boot


def append_record(directory, row):
    with (directory / "journal.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"at_utc": utc(), **row}, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps(row, sort_keys=True), flush=True)


def run_step(directory, stage, argv, timeout, *, expect=None, prepared=False, shutdown_grace=4):
    append_record(directory, {"step": stage, "state": "started", "timeout_seconds": timeout})
    env = dict(os.environ)
    for name in ("PYTHONOPTIMIZE", "PYTHONPATH", "PYTHONHOME", "KUBECONFIG"):
        env.pop(name, None)
    with (directory / f"{stage}.private.log").open("xb") as log:
        proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env,
                                cwd=ROOT, start_new_session=True)
        try:
            code = proc.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, Interrupted, KeyboardInterrupt):
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=shutdown_grace)
            except ProcessLookupError:
                pass
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
            append_record(directory, {"step": stage, "state": "incomplete"})
            raise
    state = "completed" if code == 0 else ("pending-guest-reboot" if stage == "request-mig" and code == 4 else "incomplete")
    if code == 0 and expect:
        path, schema, values = expect
        try:
            receipt = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            receipt = {}
        if receipt.get("schema") != schema or any(receipt.get(key) != value for key, value in values.items()):
            state, code = "incomplete", 3
        else:
            append_record(directory, {"step": stage, "receipt": str(path.relative_to(directory)),
                                      "receipt_sha256": checksum(path)})
    if code == 0 and prepared:
        state = "prepared"
    append_record(directory, {"step": stage, "state": state, "exit_code": code})
    if code:
        raise SystemExit(code)


def py(script, *argv):
    return [sys.executable, "-B", str(ROOT / script), *map(str, argv)]


def receipt(path, schema, **values):
    return path, schema, values


def ready(directory, port, name="readiness.json"):
    output = directory / name
    helper = ROOT / "capture" / "podresources-list-linux-amd64"
    allocator = ROOT / "fixtures" / "framebuffer-witness-linux-amd64"
    run_step(directory, Path(name).stem, py("a100_readiness.py", "--kubeconfig", KUBECONFIG,
             "--exporter-selector", EXPORTER_SELECTOR, "--podresources-binary", helper,
             "--framebuffer-helper", allocator, "--exporter-port", port, "--prometheus-port", port + 2,
             "--output", output), 100, expect=receipt(
                 output, "saf-a100-live-readiness-v1", status="profile_observed_review_required"))
    return output


def test_case(args, directory):
    case = args.case
    if case == "SAF-K8S-0802-008":
        inputs = {"baseline_boot_review_sha256": args.first_boot_review,
                  "baseline_module_receipt_sha256": args.first_modules,
                  "boot_review_sha256": args.boot_review,
                  "loaded_module_receipt_sha256": args.modules}
        if not all(path and path.is_absolute() and path.is_file() for path in inputs.values()):
            raise SystemExit("Run capture-boot and the provider binder for each boot; pass all four absolute input paths")
        if len({path.resolve() for path in inputs.values()}) != len(inputs):
            raise SystemExit("Pass separate files for the first and current boot and loaded-module reviews")
        digests = {name: checksum(path) for name, path in inputs.items()}
        output = directory / "signed-admission.json"
        append_record(directory, digests)
        run_step(directory, "signed-admission", py("prove-signed-admission.py", *inputs.values(), output),
                 180, expect=receipt(output, "saf-a100-signed-admission-v2", status="passed",
                                     independent_boot_verified=True, same_provider_instance=True,
                                     submitter_evidence_write_forbidden=True, unreviewed_node_denied=True,
                                     **digests))
    elif case == "SAF-K8S-0805-003":
        profile = ready(directory, args.port_base)
        output = directory / "live-catch"
        run_step(directory, "live-catch", py(
            "live_catch_hold.py", "--kubeconfig", KUBECONFIG, "--profile", profile,
            "--support-review", ROOT / "support-review.json", "--exporter-selector", EXPORTER_SELECTOR,
            "--podresources-binary", ROOT / "capture" / "podresources-list-linux-amd64",
            "--framebuffer-helper", ROOT / "fixtures" / "framebuffer-witness-linux-amd64",
            "--exporter-port", args.port_base, "--prometheus-port", args.port_base + 2, "--evidence-dir", output),
            850, shutdown_grace=90, expect=receipt(
                output / "catch-hold.raw.json", "saf-a100-catch-hold-raw-v2",
                status="passed", escalation_denied_by_policy=True, escalation_not_persisted=True,
                allocator_release_verified=True, fixture_resources_removed=True,
                hold_preserved_after_cleanup=True, self_asserted_corroboration_denied=True,
                all_wrong_approval_bindings_denied=True))
    elif case == "SAF-K8S-0805-004":
        output = directory / "physical-placement"
        run_step(directory, "physical-placement", py("prove-mig.py", output), 560,
                 expect=receipt(output / "mig-placement.json", "saf-a100-mig-placement-v2", status="passed",
                                distinct_live_mig_assignments=2, whole_gpu_baseline_admitted_dry_run=True,
                                whole_gpu_request_denied_by_policy=True, whole_gpu_denied_request_absent=True,
                                fixture_resources_removed=True))
    else:
        profile = ready(directory, args.port_base)
        output = directory / "live-visibility"
        run_step(directory, "live-visibility", py(
            "a100_visibility.py", "--kubeconfig", KUBECONFIG, "--profile", profile,
            "--support-review", ROOT / "support-review.json", "--exporter-selector", EXPORTER_SELECTOR,
            "--podresources-binary", ROOT / "capture" / "podresources-list-linux-amd64",
            "--exporter-port", args.port_base, "--evidence-dir", output),
            950, expect=receipt(output / "visibility.json", "saf-a100-live-visibility-route-v2",
                                status="passed", source="live_a100_dcgm_exporter", case_namespace_deleted=True,
                                failed_target_http_404=True, vanished_target_absent=True,
                                direct_healthy_framebuffer_mib=0, scrape_configuration_only=True))


def interrupted(_signal, _frame):
    raise Interrupted("Hardware test interrupted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-sha256", required=True)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("verify-bundle")
    actions = ("bootstrap", "capture-boot", "request-mig", "configure-mig", "test")
    for action in actions:
        part = sub.add_parser(action)
        part.add_argument("--run-dir", type=Path, required=True, help="new directory under existing private storage")
        if action == "test":
            part.add_argument("case", choices=CASE_IDS)
            part.add_argument("--first-boot-review", type=Path)
            part.add_argument("--first-modules", type=Path)
            part.add_argument("--boot-review", type=Path)
            part.add_argument("--modules", type=Path)
            part.add_argument("--port-base", type=int, default=19440)
    args = parser.parse_args()
    verified = verify_bundle(args.manifest_sha256)
    if args.action == "verify-bundle":
        print(json.dumps({"bundle_verified": True, "files": len(verified["files"])}))
        return
    if args.action == "test" and not 1024 <= args.port_base <= 65532:
        parser.error("--port-base must leave room for three distinct nonprivileged loopback ports")
    instance, epoch, boot = existing_guest()
    directory = args.run_dir
    if not directory.is_absolute():
        raise SystemExit("--run-dir must be absolute")
    if directory.resolve() == ROOT or ROOT in directory.resolve().parents:
        raise SystemExit("Write the attempt outside the verified bundle")
    directory.mkdir(mode=0o700, exist_ok=False)
    append_record(directory, {"action": args.action, "case": getattr(args, "case", None),
                              "manifest_sha256": args.manifest_sha256,
                              "host_ref": sha256(instance.encode()).hexdigest(),
                              "boot_ref": sha256(boot.encode()).hexdigest()})
    if args.action == "bootstrap":
        run_step(directory, "bootstrap", ["bash", str(ROOT / "bootstrap.sh")], 850, prepared=True)
        run_step(directory, "baseline", ["bash", str(ROOT / "deploy-and-baseline.sh"), str(directory)],
                 550, prepared=True)
    elif args.action == "capture-boot":
        (directory / "boot-identity.private.tsv").write_text(f"instance_id={instance}\nboot_epoch_s={epoch}\n{boot}\n")
        run_step(directory, "load-signed-core", ["modprobe", "nvidia"], 20, prepared=True)
        run_step(directory, "load-signed-uvm", ["modprobe", "nvidia_uvm"], 20, prepared=True)
        output = directory / "signed-modules.json"
        run_step(directory, "signed-modules", py("verify-loaded-signed-modules.py", output), 95,
                 expect=receipt(output, "saf-a100-loaded-signed-modules-v1",
                                boot_ref_sha256=sha256(boot.encode()).hexdigest()), prepared=True)
    elif args.action == "request-mig":
        run_step(directory, args.action, ["bash", str(ROOT / "request-mig-mode.sh")], 250, prepared=True)
    elif args.action == "configure-mig":
        output = directory / "mig-setup.json"
        run_step(directory, args.action, py("mig_setup.py", output), 290,
                 expect=receipt(output, "saf-a100-mig-setup-v2", status="prepared", geometry_verified=True,
                                profile="1g.5gb", device_count=2), prepared=True)
    else:
        test_case(args, directory)


if __name__ == "__main__":
    os.umask(0o077)
    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except (Interrupted, KeyboardInterrupt, subprocess.TimeoutExpired) as error:
        sys.exit(str(error))
