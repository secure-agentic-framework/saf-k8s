# SAF-K8S-1004-001 ML threat taxonomy worksheet

Run from the framework checkout.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-1004-001 --docker-context desktop-linux
```

A restricted Kubernetes Job validates a defensive worksheet against fixed
synthetic incident records. The case rejects missing links and mismatched
classifications, accepts the repaired worksheet, and confirms an independent
observation maps to an owned threat class.

The label check uses the ten reviewed entries in CTA-2114 (November 2025),
Section 9, printed pages 16–17. It rejects a worksheet that omits
`Poisoning Attacks` and uses the short label `Evasion`. The repaired
worksheet matches the reviewed list and preserves the previous `control.*`
IDs. Extraction, inversion, and membership inference are grouped under
`Oracle Attack`.

Section 9 is non-exhaustive. For adoption, record which categories apply to
the ML system and map them to the deployed surfaces, controls, and detection
mechanisms. Extend the threat model with any other relevant threats. Use
evidence from the deployed detection and response workflow to validate those
mappings.

Sources [CTA-2114](https://www.cta.tech/standards/mitigating-cybersecurity-threats-in-ml-based-systems/)
and [NIST AI 100-2e2025 comparator](https://doi.org/10.6028/NIST.AI.100-2e2025).
