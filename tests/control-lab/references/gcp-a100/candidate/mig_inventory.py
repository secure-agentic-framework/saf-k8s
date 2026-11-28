"""Strict inventory of the owned A100-SXM4-40GB MIG fixture."""

from dataclasses import dataclass
import re

MODEL = "NVIDIA A100-SXM4-40GB"
DRIVER = "580.178.04"
PROFILE = "1g.5gb"
RESOURCE = "nvidia.com/mig-" + PROFILE
UUID = r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}"
GPU = re.compile(rf"GPU 0: (?:NVIDIA )?A100-SXM4-40GB \(UUID: (GPU-{UUID})\)")
DEVICE = re.compile(rf"MIG\s+1g\.5gb\s+Device\s+(\d+):\s+\(UUID: (MIG-{UUID})\)")
GPU_INSTANCE = re.compile(r"0\s+MIG\s+1g\.5gb\s+19\s+(\d+)\s+(\d+)\s*:\s*1")
COMPUTE_INSTANCE = re.compile(r"0\s+(\d+)\s+MIG\s+(?:1c\.)?1g\.5gb\s+0\s+(\d+)")
PROFILE_CAPACITY = re.compile(r"0\s+MIG\s+1g\.5gb\s+19\s+(\d+)\s*/\s*7\s+.+")
EMPTY = ("No GPU instances found", "No GPU instances found: Not Found")


class MigPrecondition(RuntimeError):
    pass


def require(condition, description):
    if not condition:
        raise MigPrecondition(description)


@dataclass(frozen=True)
class Inventory:
    gpu: str
    devices: tuple
    instances: tuple

    @property
    def empty(self):
        return not self.devices and not self.instances


def table_rows(text, title):
    lines = [line.strip(" |") for line in text.splitlines() if line.strip()]
    require(title in lines, f"Missing {title} inventory header")
    return [line for line in lines if re.match(r"\d", line)]


def layout(text):
    lines = text.strip().splitlines()
    model = GPU.fullmatch(lines[0].strip()) if lines else None
    require(model, "Expected one NVIDIA A100-SXM4-40GB at index zero")
    devices = [DEVICE.fullmatch(line.strip()) for line in lines[1:]]
    require(all(devices), "Unexpected GPU or MIG device in nvidia-smi -L")
    require(len({m[1] for m in devices}) == len(devices)
            and len({m[2] for m in devices}) == len(devices), "Duplicate MIG device index or UUID")
    return model[1], tuple(sorted(m[2] for m in devices))


def read_inventory(command):
    profile = command("nvidia-smi", "--query-gpu=name,driver_version,mig.mode.current,mig.mode.pending",
                      "--format=csv,noheader").stdout.strip()
    require(profile == f"{MODEL}, {DRIVER}, Enabled, Enabled",
            "Expected the pinned signed driver and active/pending MIG mode on one A100")
    gpu, devices = layout(command("nvidia-smi", "-L").stdout)
    gi = command("nvidia-smi", "mig", "-lgi", "-i", "0", check=False)
    message = gi.stdout.strip() or gi.stderr.strip()
    if gi.returncode in (0, 6) and not (gi.stdout.strip() and gi.stderr.strip()) and message in EMPTY:
        require(not devices, "Driver views disagree about empty MIG geometry")
        # A no-object response is only accepted when the profile table independently
        # confirms that all seven placements are available.
        profiles = command("nvidia-smi", "mig", "-lgip", "-i", "0").stdout
        capacities = [m for row in table_rows(profiles, "GPU instance profiles:")
                      if (m := PROFILE_CAPACITY.fullmatch(row))]
        require(len(capacities) == 1 and capacities[0][1] == "7",
                "Empty GPU instance list lacks independent all-placements-free readback")
        return Inventory(gpu, (), ())
    require(gi.returncode == 0 and not gi.stderr.strip(), "GPU instance inventory query failed")
    gis = [GPU_INSTANCE.fullmatch(row) for row in table_rows(gi.stdout, "GPU instances:")]
    require(len(gis) == 2 and all(gis) and len({g[1] for g in gis}) == 2 and len({g[2] for g in gis}) == 2,
            "Unexpected or partial GPU instances; review the retained layout before retrying")
    ci = command("nvidia-smi", "mig", "-lci", "-i", "0").stdout
    cis = [COMPUTE_INSTANCE.fullmatch(row) for row in table_rows(ci, "Compute instances:")]
    require(len(cis) == 2 and all(cis) and {c[1] for c in cis} == {g[1] for g in gis},
            "Expected one full compute instance for each of the two approved GPU instances")
    require(len(devices) == 2, "Driver must enumerate two distinct approved MIG device UUIDs")
    return Inventory(gpu, devices, tuple(sorted((c[1], c[2]) for c in cis)))
