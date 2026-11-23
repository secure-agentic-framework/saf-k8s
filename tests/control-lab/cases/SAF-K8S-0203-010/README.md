# SAF-K8S-0203-010 Reduced node image and observed platform functions

Build a disposable Kind node variant that removes APT from the pinned upstream image. Verify the active node runs that variant, compare installed package inventories, and start a fresh workload through kubelet and containerd. This establishes one supported lab image change. Production package, account, service, management and update requirements remain specific to the chosen node OS.

Build the exact local image and pass the returned ID to the lab entry point from the control lab directory.

```sh
image_id=$(DOCKER_CONTEXT=desktop-linux sh cases/SAF-K8S-0203-010/build-node.sh)
python3 lab.py test SAF-K8S-0203-010 --docker-context desktop-linux --local-node-image "$image_id"
```
