# ID Migration Map: SAFE-K8S → SAF-K8S

As part of the rename to **Secure Agentic Framework (SAF)**, all control and crosswalk identifiers changed prefix from `SAFE-K8S` to `SAF-K8S`.

**Rule:** `SAFE-K8S-<block>-<seq>` → `SAF-K8S-<block>-<seq>`. The 4-digit block and 3-digit sequence are unchanged; only the prefix differs.

This is a pure prefix swap across all 593 controls. Generated markdown filenames under `markdown/controls/` changed correspondingly (e.g. `SAFE-K8S-0101-003.md` → `SAF-K8S-0101-003.md`).

To rewrite external references programmatically: `s/SAFE-K8S/SAF-K8S/g`.
