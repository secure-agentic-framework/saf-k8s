# SAF-K8S-0203-015 Metadata endpoint and path restrictions

Two disposable Kubernetes Services expose the same harmless fixture marker. Changing one Service selector removes its usable EndpointSlice backends and new connections stop reaching it. The separately approved Service remains available. The case exercises scoped route retirement on real Kubernetes. Provider instance settings, metadata hop limits, host paths, and node functionality require their own evidence.

```sh
python3 lab.py test SAF-K8S-0203-015 --docker-context desktop-linux
```
