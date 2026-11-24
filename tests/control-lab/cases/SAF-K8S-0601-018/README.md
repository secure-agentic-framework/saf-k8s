# SAF-K8S-0601-018 registry rescans

Run `python3 lab.py test SAF-K8S-0601-018` from the control-lab directory.

The case fetches real manifest, configuration and layer bytes from the
disposable Distribution registry by digest. Pinned OSV-Scanner checks those
bytes using two generations of a synthetic offline advisory. A native
Kubernetes policy requires the current approved digest. The formerly clear
image becomes quarantined and remains denied after retagging. The separately
scanned clean digest remains allowed. No fixture image is started.

The run supplies the rescan trigger directly. Deployed webhook delivery,
feed freshness, signed decisions, startup and runtime coverage, rescan
cadence and exception lifecycle require separate evidence.
