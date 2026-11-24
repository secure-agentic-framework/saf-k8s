# SAF-K8S-0601-021 registry network restriction

Run `python3 lab.py test SAF-K8S-0601-021` from the control-lab directory.

Two test clients make real OCI API requests to the owned registry through its
Service and directly to its Pod. Both succeed in the baseline. After kindnet
enforces the recorded NetworkPolicy, only the approved source can reach either
route. The isolated fixture does not use a public endpoint or a real credential.
Verify provider, mirror and private endpoint paths separately for each deployment.
