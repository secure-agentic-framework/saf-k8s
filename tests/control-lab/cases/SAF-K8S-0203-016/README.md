# SAF-K8S-0203-016 Node clock reference selection

A restricted Job uses the pinned Chrony client and two lab-owned loopback-only NTP sources. It verifies preferred-source selection, actual alternate selection after the preferred source stops, and the absence of a selected reference when both are unavailable. Chrony runs with clock adjustment disabled and the enclosing Job drops all capabilities. The client uses a deliberately short fixture stale-distance budget so source loss is observable within the test window. The fixture observes source selection. Deployed source authority, regional separation, measured node time and alert routing need their own evidence.

```sh
python3 lab.py test SAF-K8S-0203-016 --docker-context desktop-linux
```
