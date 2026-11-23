# SAF-K8S-0203-016 node time monitoring

Run `python3 tests/control-lab/lab.py test SAF-K8S-0203-016 --docker-context desktop-linux`
from the framework root. The case downloads a checksum-pinned Debian Chrony
package for the disposable Kind node. No package service is installed.

Chrony observes a case-owned loopback reference. The case starts with the
source unavailable and then takes a valid measurement. A client-only test
offset exercises the alert threshold. The final measurement returns to the
normal range, while an immutable ConfigMap retains the alert. Both
Chrony processes run without clock-control capability. The fixture does
not contact external time servers.

The result covers local observation and threshold behavior. Deployed node
clock synchronization, trusted sources, alert integration and managed
node evidence remain separate.

- [Chrony clock measurement and -Q option](https://chrony-project.org/doc/4.6/chronyd.html)
- [Chrony source offset directive](https://chrony-project.org/doc/4.6/chrony.conf.html)
- [Debian chrony package](https://packages.debian.org/trixie/chrony)
