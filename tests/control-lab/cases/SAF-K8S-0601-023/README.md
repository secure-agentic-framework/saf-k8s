# SAF-K8S-0601-023 — Scheduled rotation and propagation

Two running Pods start with an inert version marker mounted from a ConfigMap.
A suspended CronJob crosses a schedule boundary while both readers retain the
original marker. Once enabled, the CronJob controller creates the Job. The Job
uses a ServiceAccount authorized to update that exact ConfigMap, and changes
the marker before the test deadline. Both original Pods receive the update
through their existing mounts.

This verifies scheduled execution and live propagation. The marker represents
a version only. Actual registry issuance, expiry, revocation, authorized pulls
and propagation through a production Secret manager require separate evidence.

```sh
python3 lab.py test SAF-K8S-0601-023 --docker-context desktop-linux
```

From the framework checkout use `python3 tests/control-lab/lab.py` with the
same arguments. Allow time for one schedule boundary and volume refresh.

- [Kubernetes v1.36 CronJobs](https://v1-36.docs.kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/)
- [Kubernetes v1.36 ConfigMap volume updates](https://v1-36.docs.kubernetes.io/docs/concepts/configuration/configmap/)
- [Kubernetes v1.36 image pull Secrets](https://v1-36.docs.kubernetes.io/docs/concepts/containers/images/#specifying-imagepullsecrets-on-a-pod)
