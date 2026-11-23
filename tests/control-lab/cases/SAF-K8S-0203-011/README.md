# SAF-K8S-0203-011 Read-only root and approved writable state

An unprivileged Kind Job runs three small Linux boots in QEMU with attachment limited to case-owned files. The writable comparison root accepts a marker. A protected root denies the same write while a separate state disk accepts it. Selecting a second protected root version preserves the state marker and leaves both protected disk hashes unchanged. The result covers virtual Linux mount and disk policy. Production node lifecycle, image authentication, measured integrity and provider controls need separate evidence.
