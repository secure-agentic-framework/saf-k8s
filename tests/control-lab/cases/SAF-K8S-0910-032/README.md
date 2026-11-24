# SAF-K8S-0910-032 cross-cluster telemetry monitoring

Run `python3 lab.py test SAF-K8S-0910-032` from the lab directory.

The same private mTLS route carries four benign synthetic records before
and after alerting is enabled. The collector measures their actual bytes
and unique record IDs. It alerts only with monitoring enabled, and a
separately authenticated read-only observer verifies the source, record
digests, counts and alert. The enabled listener also accepts a normal
two-record sample without an alert.

The fixture measures one count-based threshold on one owned route.
Production exporter coverage, volume baselines, timing, alert delivery,
and additional anomaly types require deployment evidence.
