# Verify routine webhook replacement and recovery

```sh
python3 lab.py test SAF-K8S-0605-010 --docker-context desktop-linux
```

The fixture installs a narrow HTTPS validating webhook for an inert custom
resource. It checks the live resource budget and admission settings. During
each ordinary pod replacement, one sequential dry-run request must reach the
observed Ready survivor. A final single request verifies fail-closed handling
with no Ready backends, followed by a probe after restoration.

The test measures routine fixture availability. Production rate limits, sizing,
operator-specific deployment and adversarial capacity remain separate evidence.

## Verify an adopting implementation

Inventory webhook matches, endpoint topology, resource
limits, timeout/failure policy, and version-specific operator settings.
Measure authorized representative serial and concurrency profiles against
approved latency/error objectives; test a controlled backend replacement and
unavailable endpoint, and verify alerts plus fail-closed/recovery behavior.
The fixture's sequential requests do not establish production capacity.
