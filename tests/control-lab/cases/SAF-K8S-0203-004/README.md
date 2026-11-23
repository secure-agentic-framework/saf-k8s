# SAF-K8S-0203-004 Verified boot policy

An unprivileged Kind Job runs QEMU with disposable ARM virtual UEFI firmware and an inert EFI marker. The case observes the unsigned marker running with enforcement disabled, firmware denial with enforcement enabled, and a successful signed boot under the enrolled key. The signing key, UEFI variables and VM content are confined to the disposable fixture. Production hardware, provider images, trust policy updates, kernel stage coverage and attestation require their own evidence.
