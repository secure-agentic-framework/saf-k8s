# Separate model retrieval from training-data access

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0501-009 --docker-context desktop-linux
```

A disposable Kubernetes cluster compares model and training paths before and after applying scoped NetworkPolicies. The transport policy restricts selected source, destination and port combinations. When two routes share an allowed listener, the routes need their own authorization. The separate fixture gateway permits each owned test identity only on its assigned route. The two backend counters confirm that denied requests never reached either backend. The route credentials are synthetic and local to the case.

For adoption, inventory every client and destination identity, including registries, mirrors, training stores, proxies and shared ports. Confirm that the selected CNI implements the required policy. Use owned approved and excluded comparisons at the network and route boundaries and confirm backend observations. Record the effective identity or token authority, route configuration and exception scope. Independently verify the exact retrieved model or image against approved provenance and expected immutable content before promotion or consumption. Retain the decision, authoritative signer or trust policy, and digest with the route evidence.

[Companion signed build and promotion chain](https://github.com/secure-agentic-framework/saf-k8s/blob/52c2abe5df25415ff10e4393f5b1a41a7bbcd9dc/tests/control-lab/verified/SAF-K8S-0603-013.json)
