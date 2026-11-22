# SAF-K8S-1003-005 — Technique-aligned detection rules

```sh
python3 lab.py test SAF-K8S-1003-005 --docker-context desktop-linux
```

From the framework checkout, use `python3 tests/control-lab/lab.py` with the same arguments. Two native Kubernetes Jobs use the digest-pinned Prometheus rule evaluator on inert synthetic records. The rules match a privileged AI Pod request and an AI Pod administration request. They assign the versioned ATT&CK technique IDs during evaluation. Four near misses cover safe requests and equivalent signals outside the fixture namespace scope.

The first Job demonstrates the missing matches when the rules are absent. The second validates both exact alert labels and annotations, including a named runbook and a review action, with zero alerts on the comparison inputs. The change-review fixture records the rule digest and the MITRE v20.1 metadata digest. `runbooks.json` includes case-owned triage instructions.

Operational evidence requires actual event normalization, deployment and delivery, prioritization across the applicable techniques, and analyst response.

[Prometheus rule unit tests](https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/) · [MITRE ATT&CK v20.1 release](https://github.com/mitre-attack/attack-stix-data/releases/tag/v20.1)
