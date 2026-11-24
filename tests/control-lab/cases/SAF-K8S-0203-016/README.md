# SAF-K8S-0203-016 — Node clock reference selection and measurement

```sh
python3 lab.py test SAF-K8S-0203-016 --docker-context desktop-linux
```

The restricted Kind Job starts two owned loopback NTP references and the
pinned Chrony client, all with clock adjustment disabled. Each source has a
deliberate 50 ms fixture offset. The case records the raw selected source,
sample age, offset, and Chrony tracking report under four conditions. It starts
with both sources available, stops the preferred source, stops both, then
restores the preferred source. A fresh measurement passes a 100 ms bound and
fails a 20 ms bound. Both bounds and the 5-second freshness threshold belong
to this fixture. During loss, check the selected-source report even if tracking
retains the previous estimate and reports a normal leap indicator.

## Verify deployment applicability and evidence

1. Inventory governed node pools by OS, node image, role, location, and control
   owner. Identify provider-managed time discipline and request the provider's
   scoped time-source, offset, freshness, and fallback evidence for those pools.
   An unseen provider configuration leaves that pool unverified.
2. Record the approved authoritative sources, source ownership, profile-defined
   comparison cadence, maximum absolute offset, maximum sample age, and
   required response. If the selected profile includes SC-45(2), record an
   approved secondary in a different geographic region and verify
   synchronization after primary loss. Confirm the actual time service, version,
   effective source directories, and source selection on each pool.
3. Collect timestamped `chronyc -n tracking`, `chronyc -n sources -v`, and
   `chronyc -n sourcestats -v` reports, or equivalent provider exports. Record
   the signed system clock offset, dispersion, measurement age, selected source
   and leap state, and evaluate each against its approved threshold. Use a
   trusted comparison reference independent of the reviewed failure domain.
4. Exercise stale, excessive-offset and unavailable-source handling with
   synthetic samples or an isolated reference-failure fixture. Observe a fresh
   in-bound sample after recovery. Trace the test alert from evaluation through
   delivery and acknowledgement to the named responder. Retain the alert rule
   version, sample class, delivery and recovery times, and the scope of the
   tested profile. Clock adjustment remains disabled in this example.
5. For AU-8 evidence, check whether audit producers use the monitored clock and
   verify the actual timestamp granularity and UTC or fixed-offset formatting
   independently.

[Chrony 4.6 chronyc](https://chrony-project.org/doc/4.6/chronyc.html) ·
[Chrony 4.6 chronyd](https://chrony-project.org/doc/4.6/chronyd.html) ·
[Chrony 4.6 source configuration](https://chrony-project.org/doc/4.6/chrony.conf.html) ·
[NIST SP 800-53 Rev. 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)
