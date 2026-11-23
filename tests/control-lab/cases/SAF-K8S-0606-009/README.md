# Verify one build tool integrity practice

```sh
python3 lab.py test SAF-K8S-0606-009 --docker-context desktop-linux
```

Three real Jobs in a Restricted namespace exercise an unchecked public tool,
a changed tool rejected before execution, and an approved digest that executes.
The tool is a fixture stored in an immutable ConfigMap. The Jobs have no default
service-account token and the approved run records its marker and terminal state.

The test illustrates one aspect of NIST SSDF v1.1 task PO.3.2. The selected
organization, toolchain governance, remaining practices and crosswalks require
separate review and evidence.
