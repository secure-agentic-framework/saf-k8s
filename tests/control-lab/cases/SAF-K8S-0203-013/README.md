# SAF-K8S-0203-013 — Effective kernel lockdown and scoped trace enforcement

```sh
python3 lab.py test SAF-K8S-0203-013 --docker-context desktop-linux
```

An unprivileged Kind Job boots the same pinned Debian ARM64 kernel in two
disconnected QEMU guests. The baseline reports no lockdown and observes an
owned TraceFS marker. The governed guest boots in integrity mode and executes
the same marker operation. After raising the running guest to confidentiality,
the same marker write is denied with the Linux lockdown reason. The kernel
rejects a request to lower the mode and still returns its ordinary uptime.
The guest uses only fixture resources.

## Verify deployment applicability and evidence

1. For each applicable Linux node role, record the exact image, kernel
   release and vendor support, owner, expected mode, boot mechanism and
   approved exceptions. Use provider-supported evidence for managed nodes.
2. For accessible nodes, retain read-only observations of
   `/sys/kernel/security/lockdown`, `/sys/kernel/security/lsm` if exposed,
   `uname -r`, and trusted image and kernel configuration identities. Compare
   the bracketed active mode with the approved one after provisioning,
   replacement and reboot. Boot arguments and separate Secure Boot evidence
   can help trace how the mode was selected.
3. In an isolated representative node, exercise required CNI, device drivers,
   storage, monitoring or support functions as applicable. Compare a harmless
   approved operation with a relevant restriction from the selected kernel
   version, retaining its native denial or allowed result. Treat missing
   securityfs, provider claims without a scoped result, and incompatible
   operations as explicit evidence gaps or documented exceptions.
4. Verify module signing, allowlists and Secure Boot policy independently
   when the selected profile requires them. This fixture observes one
   confidentiality hook and the running mode transition.

[Linux v6.12 lockdown implementation](https://github.com/torvalds/linux/blob/v6.12/security/lockdown/lockdown.c) ·
[Linux v6.12 TraceFS hook](https://github.com/torvalds/linux/blob/v6.12/kernel/trace/trace.c)
