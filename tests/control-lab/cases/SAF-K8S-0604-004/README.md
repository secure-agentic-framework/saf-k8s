# Verify VEX assessments at intake

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0604-004 --docker-context desktop-linux
```

The pinned OpenVEX reference checks an approved source, exact release and component, revision and evidence. Missing, altered, mismatched or unsupported assessments leave fictional findings active. One authenticated and corroborated assessment changes the selected finding's priority while retaining the original record. The reference uses inert artifacts and fictional finding identifiers.

For adoption, inventory the actual formats, versions, intake clients, allowed issuers and trust configuration. Verify issuer identity and rotation, revision and freshness, exact release and component scope and applicable advisory. Bind assessments to actual scanner or product findings. Test an approved and corroborated status, invalid or conflicting evidence, and a resolved assertion against the actual release. Keep uncertain findings active and preserve the original results plus reviewed disposition. Record the exact document, evidence source, reviewer authority, policy version, priority decision and retention term.

[OpenVEX v0.2.0 specification](https://github.com/openvex/spec/blob/v0.2.0/OPENVEX-SPEC.md) · [NIST SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final)
