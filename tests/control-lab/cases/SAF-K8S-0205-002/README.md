# SAF-K8S-0205-002 NodePort and HostPort admission

The case compares Baseline Pod Security Admission with a separate Service ValidatingAdmissionPolicy on Kind. Inert server-side requests check regular and init HostPort, NodePort creation and update, LoadBalancer allocation defaults, allowed declarations and one isolated exception namespace. The requests make no listener, traffic, or cloud resource. Effective provider reachability and each production exception require separate evidence.

```sh
python3 lab.py test SAF-K8S-0205-002 --docker-context desktop-linux
```
