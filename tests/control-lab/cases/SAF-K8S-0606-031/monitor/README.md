# SAF-K8S-0606-031 retained GitOps monitoring

Run from the SAF-K8S framework checkout with local Docker, Kind and kubectl.
The test also uses Git and curl through the original Argo CD fixture.

```sh
python3 tests/control-lab/cases/SAF-K8S-0606-031/monitor/run.py --docker-context desktop-linux
```

Prometheus scrapes repeated samples from the live Argo CD fixture. A missing
manifest path produces an `Unknown` reconciliation alert while the previous
workload remains healthy. The owned receiver observes delivery when the alert
fires and when it resolves. The case replaces the Prometheus Pod and checks
that the new Pod reads the same healthy, failed and recovered history from
the retained volume.

The test also temporarily detaches the metrics Service from its endpoints.
A separate alert must fire and resolve while the application itself remains
healthy. Detecting a stalled controller whose status remains exposed, and
verifying production monitoring policies, require further evidence.
