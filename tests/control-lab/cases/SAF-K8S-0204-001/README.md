# SAF-K8S-0204-001 Runtime signal coverage

The restricted Job voluntarily traces only an owned child workload. It compares collection disabled and enabled, and verifies actual process, file and loopback connection events. Its measured scope is that child process in this fixture. A deployed node sensor, event forwarding, compatibility, fleet health, and drop behavior require additional evidence.

```sh
python3 lab.py test SAF-K8S-0204-001 --docker-context desktop-linux
```
