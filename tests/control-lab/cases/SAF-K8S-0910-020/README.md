# SAF-K8S-0910-020 cross-cluster transport

Run `python3 lab.py test SAF-K8S-0910-020` in the control-lab directory.
Each arm owns a source cluster and a peer cluster. The only test path is
the owned peer node's dynamically assigned NodePort.

The ordinary test response starts on plaintext. After the Service changes
to the TLS-only port, plaintext and unrelated trust fail. The source Pod
reads the fixed marker with the approved trust root and verified TLS 1.3.
No production traffic or credentials are used.

Verify route inventory, intermediaries, other transports, key lifecycle,
performance and encryption of every required production hop separately.
