# SAF-K8S-0203-012 Kernel module loading policy

Exercise the post-boot module freeze in an isolated Linux guest launched by an unprivileged Job. The pinned ARM64 Linux guests run with QEMU software emulation and no virtual network. The enclosing Kubernetes Job is non-root, applies the default seccomp profile, drops all capabilities, and uses only its ephemeral volume and read-only fixture.

- **Red** The public stock module loads before the guest is frozen.
- **Green** The effective guest freeze denies loading the same stock module.
- **Positive** The approved boot module remains present after policy activation.

Run within the lab or from `tests/control-lab` after migration.

```sh
python3 lab.py test SAF-K8S-0203-012 --docker-context desktop-linux
```

An ARM64 Docker and Kind host is required by this fixture. The disconnected fixture tests the loading freeze. Module-signature trust management, provider assurance, and real device operation require their own evidence.
