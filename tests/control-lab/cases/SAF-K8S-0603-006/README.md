# Verify trusted TUF updates

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0603-006 --docker-context desktop-linux
```

The pinned client uses a separately mounted immutable policy to verify the exact initial root fingerprint. It refuses a different self-signed version-one root before creating the updater. Two disposable Kubernetes Pods serve and consume an inert release note. The client checks role thresholds, signed metadata references, expiry, lengths, and exact target bytes. It rejects rollback using persisted metadata. Root rotation requires the configured thresholds of both the old and new root; the case tests successful rotation and refusal of a root signed only under the new authority.

For adoption, inventory the actual repositories, clients and release channels. Distribute the approved initial root through an independently authenticated channel and confirm both acceptance of that root and refusal of a different root. Document role owners, thresholds, expiry, custody, rotation and recovery, including offline or HSM requirements when applicable. Test real client download bounds, version and hash bindings, persistent state across restart, and safe behavior on failed updates. Retain the exact target and approved root fingerprints, tested decision, and expected installed artifact. Verify installed integrity and build provenance independently where required. The reference uses ephemeral fixture keys and a case-owned distribution path.

[TUF specification](https://theupdateframework.github.io/specification/latest/) · [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
