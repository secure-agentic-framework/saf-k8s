# Verify Helm merged values and dependency integrity

```sh
python3 lab.py test SAF-K8S-0606-020 --docker-context desktop-linux
```

Helm installs only local synthetic charts that create inert ConfigMaps. The
values schema refuses a disallowed marker from the normal CLI override path.
Rebuilding the fixture dependency at the same declared version preserves
`Chart.lock` while producing different package bytes. An independent archive
digest check refuses those bytes. The approved package installs with the
allowed CLI value and the original dependency marker.

The case illustrates a local release gate. Actual deployed dependency sources,
authentic package provenance, security-sensitive values and controller policy
require separate verification.
