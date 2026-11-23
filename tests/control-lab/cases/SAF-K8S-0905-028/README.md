# SAF-K8S-0905-028 — Scan a Python dependency and gate fixture promotion

    python3 lab.py test SAF-K8S-0905-028 --docker-context desktop-linux

A restricted Job installs two tiny local wheels with pip. The wheels contain metadata only and the installer resolves a declared transitive dependency offline. The gate reads the installed distributions, matches a fabricated advisory, and compares the same installed inventory with enforcement disabled and enabled. The disabled gate writes a local promotion record. The enabled gate withholds it and retains the reason. A fresh installation of the patched wheel produces a promotion record and preserves the required dependency.

The test uses invented dependencies and advisory data. Production scanner coverage, advisory feeds, risk triage, approval and compensating controls, release enforcement, and framework-specific exposure still require separate evidence.

- [Python core metadata specification](https://packaging.python.org/en/latest/specifications/core-metadata/)
- [pip install](https://pip.pypa.io/en/stable/cli/pip_install/)
