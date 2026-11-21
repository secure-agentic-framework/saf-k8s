"""Check the control's stated configuration surface against the installed API server."""
SCOPE = "The installed kube-apiserver's support for the catalog flag. Stream behavior is a separate claim."
FLAG = "--streaming-connection-idle-timeout"


def run(lab):
    # Keep the existing process running. The version command exits after parsing flags.
    args = ("exec", "-n", "kube-system", f"kube-apiserver-{lab.cluster}-control-plane",
            "--", "kube-apiserver", "--version")
    reference = lab.kubectl(*args).stdout.strip()
    lab.check("positive", "The installed API server binary reports its version",
              reference.startswith("Kubernetes v"), reference)
    result = lab.kubectl(*args, f"{FLAG}=15s", allow_failure=True)
    if result.returncode and f"unknown flag: {FLAG}" not in result.stderr:
        lab.block(result.stderr.strip())
    lab.check("claim", f"kube-apiserver accepts the catalog flag {FLAG}",
              result.returncode == 0, (result.stderr or result.stdout).strip())
