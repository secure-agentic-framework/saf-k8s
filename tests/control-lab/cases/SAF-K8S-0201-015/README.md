# SAF-K8S-0201-015 Node-level kubelet file audit

Run on a Mac with Docker, kind, kubectl and Lima 2.0 or newer. Lima uses
Virtualization.framework and a digest-pinned Debian 13 guest image.

```sh
python3 lab.py test SAF-K8S-0201-015 --docker-context desktop-linux
```

The [catalog control](https://github.com/secure-agentic-framework/saf-k8s/blob/133a8698a45e2b335b51728bf4c62f7bda98d15f/markdown/controls/SAF-K8S-0201-015.md)
requires Linux Audit or equivalent endpoint telemetry for reads and writes
to kubelet configuration files, kubeconfig, and PKI paths, with recurring
checks that the rules remain loaded.

The case confirms the expected path types exist on the disposable kind node.
It then boots a separate Linux VM with an independent kernel and no host
mounts. The guest installs its signed Debian auditd package. Before adding
the rules, ordinary reads and writes of three inert fixture files produce no
matches while a separate canary proves the collector is live. After installing
the watches, auditd records successful reads and writes for each of the three
exact paths and the kernel reports no lost events. The case verifies the
watch rules were removed and deletes the VM and kind cluster.

The guest fixture uses the documented legacy file-watch syntax. On the tested
Debian arm64 build, auditctl 4.0.2 rejected the path and permission rule form
while expanding a syscall unavailable on that architecture. The real emitted
events are required for a pass. Deployment evidence needs the actual node
paths, active and persistent rules for the deployed kernel and userspace,
and recurring verification across all nodes.

- [Linux Audit rule reference](https://github.com/linux-audit/audit-userspace/blob/master/docs/audit.rules.7)
- [Linux Audit arm64 rule-loader compatibility issue](https://github.com/linux-audit/audit-userspace/issues/496)
- [Lima Virtualization.framework configuration](https://lima-vm.io/docs/config/vmtype/vz/)
