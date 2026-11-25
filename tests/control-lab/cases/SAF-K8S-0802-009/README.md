# SAF-K8S-0802-009 Fixture file-integrity detection

A Kubernetes Pod uses a writable fixture volume for inert bytes and a read-only monitor mount. The monitor compares those bytes against a separately mounted immutable digest and reports unchanged, replaced, and restored states. The same filename remains present throughout.

The case detects fixture drift with no host mount, driver file, kernel policy or pre-use enforcement.

## Adopter verification

1. Document the real monitor, approved driver and firmware files, expected package or signed version source, authorized modifiers and deployment scope.
2. Compare authoritative versions and hashes with actual files and effective read permissions. In an owned representative canary, verify detection, correct source attribution, alert delivery and restoration using an approved inert marker.
3. Record exclusions, baseline and update approval, false-positive handling and elapsed detection time. Recheck after installations, upgrades, repair and node replacement.
