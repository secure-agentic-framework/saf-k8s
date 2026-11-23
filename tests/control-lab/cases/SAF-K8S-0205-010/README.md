# SAF-K8S-0205-010 Node firewall paths

Three harmless listeners use dynamically assigned IPv4 ports in the owned Kind receiver. The lab records baseline reachability, then installs a narrow input restriction on the receiver and output restriction on the sender. Independent counters attribute their drops. The allowed marker and API stay available, and verified rollback restores the fixture paths.

No rule is installed outside the owned Kind nodes. Production ports, protocols, node roles and provider boundaries need their own evidence.

```sh
python3 lab.py test SAF-K8S-0205-010 --docker-context desktop-linux
```
