"""Observe a case-owned time source without adjusting the node clock."""
import hashlib
import json
from pathlib import Path
import re
import tempfile
from urllib.request import urlopen

PACKAGES = {
    "arm64": "efae2e04c60f675126b0251c391f7df23e87e8c776445516a282f5b7bba4769a",
    "amd64": "3b3fb6b13818c288ea0121038dc3220da869c6dc5d1e5c4d5f7b13647f3ff7e7",
}
VERSION = "4.6.1-3+deb13u2"
WORK = "/var/lib/saf-chrony-observation"
PORT = 11230
SCOPE = (
    "Pinned Chrony in one disposable Kind v1.36.1 node. Observes an isolated "
    "loopback fixture reference. Checks source loss, a test-only measurement "
    "offset and recovery, and retains an alert. Chrony clock adjustment is "
    "disabled and CAP_SYS_TIME is dropped. Production synchronization, authority "
    "and monitoring destinations remain unverified."
)


def exec_node(lab, *args, timeout=30, allow_failure=False, payload=None):
    return lab.command("docker", "exec", "-i", f"{lab.cluster}-control-plane",
                       *args, timeout=timeout, allow_failure=allow_failure, payload=payload)


def prepare_chrony(lab):
    arch = exec_node(lab, "dpkg", "--print-architecture").stdout.strip()
    if arch not in PACKAGES:
        lab.block(f"Unsupported fixture architecture {arch}")
    filename = f"chrony_{VERSION}_{arch}.deb"
    url = f"https://deb.debian.org/debian/pool/main/c/chrony/{filename}"
    with urlopen(url, timeout=20) as response:
        package = response.read(2_000_000)
    digest = hashlib.sha256(package).hexdigest()
    if digest != PACKAGES[arch]:
        lab.block("Chrony fixture package checksum did not match")
    exec_node(lab, "mkdir", "-m", "700", WORK)
    with tempfile.TemporaryDirectory(prefix="saf-chrony-") as tmp:
        path = Path(tmp) / filename
        path.write_bytes(package)
        lab.command("docker", "cp", str(path), f"{lab.cluster}-control-plane:{WORK}/chrony.deb")
    exec_node(lab, "dpkg-deb", "-x", f"{WORK}/chrony.deb", WORK)
    executable = f"{WORK}/usr/sbin/chronyd"
    release = exec_node(lab, executable, "-v").stdout.strip()
    if "version 4.6.1" not in release.lower():
        lab.block("Unexpected Chrony executable version")
    return executable, digest


def sample(lab, binary, offset=None):
    source = f"server 127.0.0.1 port {PORT} iburst minpoll 0 maxpoll 0"
    if offset is not None:
        source += f" offset {offset}"
    result = exec_node(lab, "setpriv", "--bounding-set=-sys_time", binary,
                       "-Q", "-u", "root", "-t", "8", source, "port 0", "cmdport 0",
                       f"pidfile {WORK}/client.pid", timeout=14, allow_failure=True)
    output = result.stderr + result.stdout
    match = re.search(r"System clock wrong by\s+([+-]?\d+(?:\.\d+)?)", output)
    return {"exit":result.returncode, "offset_seconds": float(match.group(1)) if match else None,
            "no_source": "No suitable source" in output,
            "output": output.strip()}


def run(lab):
    binary, digest = prepare_chrony(lab)
    missing = sample(lab, binary)
    lab.check("red", "Missing approved fixture source yields no usable Chrony measurement",
              missing["exit"] != 0 and missing["no_source"] and missing["offset_seconds"] is None,
              {"classified_source_unavailable": missing["no_source"], "measurement_present": missing["offset_seconds"] is not None})
    source_config = (f"port {PORT}\nbindaddress 127.0.0.1\ncmdport 0\n"
                     f"pidfile {WORK}/source.pid\nlocal stratum 8\nallow 127.0.0.1\n")
    exec_node(lab, "sh", "-c", f"umask 077; cat > {WORK}/source.conf", payload=source_config)
    # Keep the source local and launch it without clock-control capability.
    exec_node(lab, "sh", "-c",
              f"setpriv --bounding-set=-sys_time {binary} -x -u root -d -f {WORK}/source.conf >{WORK}/source.log 2>&1 </dev/null &")
    try:
        nominal = sample(lab, binary)
        drift = sample(lab, binary, "0.400")
        limit = 0.150
        nominal_ok = nominal["exit"] == 0 and nominal["offset_seconds"] is not None and abs(nominal["offset_seconds"]) < limit
        drift_detected = drift["exit"] == 0 and drift["offset_seconds"] is not None and abs(drift["offset_seconds"]) > limit
        lab.check("green", "The approved local source produces a nominal sample and the monitor detects the test offset",
                  nominal_ok and drift_detected, {"normal_measurement_accepted": nominal_ok,
                    "test_offset_flagged": drift_detected, "threshold_seconds": limit})
        alert = {"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"saf-time-drift"},
                 "immutable":True,
                 "data":{"source":"case-owned-loopback-reference","status":"drift-exceeded",
                         "threshold-seconds":str(limit)}}
        lab.create(alert)
        recovered = sample(lab, binary)
        recovered_ok = recovered["exit"] == 0 and recovered["offset_seconds"] is not None and abs(recovered["offset_seconds"]) < limit
        persisted = json.loads(lab.kubectl("get","configmap","saf-time-drift","-o","json").stdout)
        api = lab.kubectl("get","--raw=/readyz").stdout.strip()=="ok"
        lab.check("positive", "Restored nominal measurement and retained alert coexist with a Ready control plane",
                  recovered_ok and persisted["data"] == alert["data"] and persisted["immutable"] and api,
                  {"recovered":recovered_ok,"alert_retained":persisted["data"]==alert["data"],"api_ready":api})
        (lab.evidence/"chrony-observations.raw.json").write_text(json.dumps({"package_sha256":digest,
            "threshold":limit,"unavailable":missing,"normal":nominal,"measurement_offset":drift,
            "recovered":recovered,"clock_control":"disabled"},indent=2)+"\n")
    finally:
        exec_node(lab, "sh", "-c", f"if test -s {WORK}/source.pid; then kill -TERM \"$(cat {WORK}/source.pid)\"; fi",
                  allow_failure=True)
