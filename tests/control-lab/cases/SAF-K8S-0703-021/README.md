# Verify a governed accelerator request and quota on Kind

```sh
python3 lab.py test SAF-K8S-0703-021 --docker-context desktop-linux
```

Two fixture identities can submit Pods. The protected namespace requires its
approved identity and explicit synthetic resource declaration, and its quota
allows one slot. A valid inert Pod schedules under quota. A second request
receives the quota denial even though the node advertises two slots.

The fixture uses a synthetic resource. Verify the actual device plugin or DRA
driver, resource inventory, boundary controls and controller entry points in
the deployed accelerator environment.
