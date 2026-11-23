# SAF-K8S-0205-007 Node firewall and NetworkPolicy compatibility

Owned Pods exchange marker traffic across two Kind nodes. A dedicated IPv4 forward table on the owned receiver counts one denied source. A separate Kubernetes NetworkPolicy denies a second source. The case observes the approved path through both controls, then removes each rule and verifies the associated recovery.

The test covers the pinned Kind profile and cross-node Pod traffic. Deployed host, service, cloud, encapsulation and additional protocol paths require independent evidence.

```sh
python3 lab.py test SAF-K8S-0205-007 --docker-context desktop-linux
```
