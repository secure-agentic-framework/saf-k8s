# SAF-K8S-0203-013 Effective kernel lockdown mode

Compare effective Linux Security Module lockdown state on two disposable guests launched by an unprivileged Job. The pinned ARM64 Linux guests run with QEMU software emulation and no virtual network. The enclosing Kubernetes Job is non-root, applies the default seccomp profile, drops all capabilities, and uses only its ephemeral volume and read-only fixture.

- **Red** The running baseline kernel reports no lockdown.
- **Green** The running kernel reports the selected integrity lockdown mode.
- **Positive** The same kernel release retains ordinary procfs reads under the selected mode.

Run within the lab or from `tests/control-lab` after migration.

```sh
python3 lab.py test SAF-K8S-0203-013 --docker-context desktop-linux
```

An ARM64 Docker and Kind host is required by this fixture. The disconnected fixture verifies the reported effective setting and a harmless required read. Mode-specific interface enforcement, compatibility, provider attestation, and Secure Boot require separate evidence.
