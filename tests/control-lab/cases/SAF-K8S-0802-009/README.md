# SAF-K8S-0802-009 Fixture file-integrity detection

A Kubernetes Pod uses a writable fixture volume for inert bytes and a read-only monitor mount. The monitor compares those bytes against a separately mounted immutable digest and reports unchanged, replaced, and restored states. The same filename remains present throughout.

The case detects fixture drift with no host mount, driver file, kernel policy or pre-use enforcement.
