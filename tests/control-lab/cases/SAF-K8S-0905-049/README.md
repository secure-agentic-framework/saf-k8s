# SAF-K8S-0905-049 Zot tag protection and administrator policy

Run `python3 tests/control-lab/lab.py test SAF-K8S-0905-049 --docker-context desktop-linux` from the framework checkout. The runner host needs `htpasswd`.

The disposable pinned Zot registry compares authorized tag mutation with an effective protected configuration. In the protected fixture the same publisher can create the original tag, cannot overwrite or delete it, and can still publish another allowed tag. Independent reads confirm the original digest and native logs attribute the decisions.

The administrator comparator uses one additional synthetic identity. The protected policy refuses the same request before the global grant is configured. An explicit global mutation grant authorizes the fixture comparison, and the resulting change appears in actor logs. This verifies product policy precedence for Zot v2.1.23.
