"""Pinned cert-manager installation and public-certificate helpers."""
import base64
from hashlib import sha256
import json
import time

RELEASE = "v1.21.3"

MANIFEST = f"https://github.com/cert-manager/cert-manager/releases/download/{RELEASE}/cert-manager.yaml"

MANIFEST_SHA = "c04a51295adda2b1a775146751f973e787190778c7f35180861d9678876e5c74"

IMAGES = {
    "cainjector": "083d0e906f8eb44e255fe4ff817ae54e49f9ed82e22f1011bb4e9e4f4b8a641f",
    "controller": "9f4f96a33c7774cef24466fcd85031997531a03a8d117f151126baa8d1290dcc",
    "webhook": "055ac8e9de6a0ba6763794838fe38944acc650f68ebe1b01dd8be079e580f458",
}

API = "cert-manager.io/v1"

def managed(lab, kind, name, spec, dry_run=False):
    return lab.create({"apiVersion": API, "kind": kind, "metadata": {"name": name}, "spec": spec},
                      dry_run=dry_run, allow_failure=dry_run)


def document(lab, kind, name):
    out = lab.kubectl("get", kind, name, "-o", "json").stdout
    return json.loads(out)


def wait(lab, kind, name, condition="Ready"):
    lab.kubectl("wait", f"--for=condition={condition}", kind + "/" + name,
                "--timeout=95s", timeout=105)


def install(lab):
    local = lab.kubeconfig.parent / "cert-manager.yaml"
    lab.command("curl", "--fail", "--location", "--silent", "--show-error", "--proto", "=https",
                "--max-time", "45", MANIFEST, "-o", str(local), timeout=50)
    release = local.read_bytes()
    if sha256(release).hexdigest() != MANIFEST_SHA:
        lab.block("The official cert-manager artifact does not match the reviewed manifest")
    adjusted = release.decode()
    for part, digest in IMAGES.items():
        ref = f"quay.io/jetstack/cert-manager-{part}:{RELEASE}"
        if adjusted.count(ref) != 1:
            lab.block("The reviewed cert-manager manifest has a changed image set")
        adjusted = adjusted.replace(ref, f"{ref}@sha256:{digest}")
    local.write_text(adjusted)
    lab.command("kubectl", "--kubeconfig", str(lab.kubeconfig), "--context", f"kind-{lab.cluster}",
                "apply", "-f", str(local), timeout=120)
    for name in ("cert-manager", "cert-manager-cainjector", "cert-manager-webhook"):
        lab.kubectl("-n", "cert-manager", "rollout", "status", "deployment/" + name,
                    "--timeout=145s", timeout=155)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status = managed(lab, "Issuer", "fixture-startup-probe", {"selfSigned": {}}, dry_run=True)
        if status.returncode == 0:
            return
        time.sleep(.5)
    lab.block("The pinned certificate admission webhook did not become available")


def public_cert(lab, name, filename):
    selected = lab.kubectl("get", "secret", name, "-o", 'go-template={{index .data "tls.crt"}}').stdout.strip()
    local = lab.kubeconfig.parent / filename
    local.write_bytes(base64.b64decode(selected, validate=True))
    return local
