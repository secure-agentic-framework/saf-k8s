# Verify explicit cloud-to-Kubernetes event correlation on Kind

```sh
python3 lab.py test SAF-K8S-0704-008 --docker-context desktop-linux
```

The case generates two actual metadata-only Kubernetes audit events for a
public ConfigMap. It correlates those events with synthetic cloud rows using
an explicit fixture mapping. A time-only comparison offers false matches;
validated links preserve matched, ambiguous and unmatched outcomes.

No real cloud logs are used. Deployed source coverage, identity linkage,
audit retention and evidence of causation require separate verification.
