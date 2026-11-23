# Verify a synthetic metadata session and inventory evidence gate

```sh
python3 lab.py test SAF-K8S-0704-004 --docker-context desktop-linux
```

Two owned services return a public marker. The session-required service rejects
missing and expired fixture sessions. A separate synthetic inventory exercises
classification of effective, declared, pending and disabled endpoint settings.

The services use synthetic routes and session data. Effective cloud node
settings, launch mechanisms, runtime reachability and provider support require
separate evidence.
