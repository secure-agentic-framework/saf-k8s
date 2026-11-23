# SAF-K8S-0803-002 Ordinary IP segmentation example

Two harmless peers initially reach an owned HTTP listener. An actual Kubernetes ingress policy restricts the selected TCP port to the approved peer while the same listener remains healthy. This is an IP-network observation on the installed Kind CNI. It does not demonstrate Ethernet ACL, InfiniBand partition, RoCE device, or hardware fabric enforcement.
