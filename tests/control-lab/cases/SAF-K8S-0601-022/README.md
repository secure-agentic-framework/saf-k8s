# SAF-K8S-0601-022 — Kubernetes image pull Secret delivery

In the disposable cluster a Pod targeting the fixture ServiceAccount initially
has no `imagePullSecrets` reference. The API admits a same-namespace Secret
whose Docker configuration has an empty authentication map. Once the
ServiceAccount names the Secret, Pod admission injects that name and the
public-image test container exits successfully.

The test also evaluates inert examples of embedded values and object references.
It establishes the supported reference mechanism. Credential verification by a
private registry, external Secret synchronization, and CI delivery need their
own evidence. Credential rotation has a separate catalog control.

```sh
python3 lab.py test SAF-K8S-0601-022 --docker-context desktop-linux
```

From the framework checkout use `python3 tests/control-lab/lab.py` with the
same arguments.

- [Kubernetes v1.36 image pull Secrets](https://v1-36.docs.kubernetes.io/docs/concepts/containers/images/#specifying-imagepullsecrets-on-a-pod)
- [Kubernetes v1.36 kubelet credential providers](https://v1-36.docs.kubernetes.io/docs/tasks/administer-cluster/kubelet-credential-provider/)
