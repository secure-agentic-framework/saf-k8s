# SAF-K8S-0910-022 cross-cluster operation authorization

Run `python3 lab.py test SAF-K8S-0910-022` from the control-lab directory.
The setup reuses the supervised two-cluster bridge and the companion identity
fixture. A single dynamic NodePort initially routes both verified client
identities to an unscoped listener. The same NodePort then switches to the
listener that restricts each identity to its own operation. Each caller is
allowed its own operation and refused the other caller's operation. The
destination logs provide independent evidence of the four governed decisions.
