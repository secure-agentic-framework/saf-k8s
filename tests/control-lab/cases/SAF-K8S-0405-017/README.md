# Verify a human password policy at its verifier

Run from the framework repository.

```sh
python3 tests/control-lab/lab.py test SAF-K8S-0405-017 --docker-context desktop-linux
```

The disposable Keycloak 26.8.2 verifier compares candidate password changes with and without minimum-length and blocklist rules, and accepts a compliant lowercase password. A separate case uses two fixed failed attempts in each policy state. With the setting disabled, the correct password still works. With temporary lockout enabled, the administrator observes the threshold and lock independently, the correct password is refused for the selected identity, and the separate comparison identity remains usable. Authorized reset restores access. The recorded outcomes contain no credentials or tokens.

For adoption, identify the actual human verifier, governing requirements and covered populations. Compare permitted and refused password changes against the applicable minimum length and blocklist. Use authorized test identities to evaluate the effective failed-attempt controls, availability and recovery at each governed sign-in path. Record the effective policy, version, observed control decisions and scope of any exceptions. Evaluate non-password credentials through their applicable lifecycle controls. The reference uses a disposable realm and local test client.

[Keycloak Server Administration Guide](https://www.keycloak.org/docs/26.8.0/server_admin/) · [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
