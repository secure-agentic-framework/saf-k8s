# SAF-K8S-0601-017 — Multi-stage runtime image minimization

```sh
python3 lab.py test SAF-K8S-0601-017 --docker-context desktop-linux
```

Use Go to compile a case-owned static probe for the kind node architecture,
then build three local scratch images from the same probe and payload.
A single-stage baseline retains the build-only fixture marker. The explicit
intermediate target proves the marker is present in the build stage. The final
target copies only the payload and executable.

Inspect the saved image layers, including the final filesystem inventory and
whether the build marker appears in any final layer. Run the minimized
image with a read-only root filesystem and networking disabled. The executed
probe reads the payload and returns its hash. The case deletes its temporary
archives and local image tags. It publishes no images.

The build-stage marker is deliberately synthetic. Production package
selection, image contents, build platforms, and promotion enforcement still
need their own evidence.

- [Docker multi-stage builds](https://docs.docker.com/build/building/multi-stage/)
- [OCI layer filesystem changes](https://github.com/opencontainers/image-spec/blob/v1.1.1/layer.md)
