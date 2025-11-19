# Nix Forge container registry

* Run container with podman

```bash
podman run -it --tls-verify=false --pull=always localhost:5000/<PACKAGE>:latest

```

* Run container with K8s

```bash
kubectl run test-api --insecure-skip-tls-verify --image=<IP-ADDRESS>:5000/<PACKAGE>:latest --port=5000
```
