# Nix Forge container registry

An OCI-compliant container registry that builds images on-demand using Nix.

Implements the [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec)
with backward compatibility for Docker Registry v2 clients.


## Quick start

* Launch registry service

```bash
nix develop

python app.py
```

* Run container

```bash
# With Podman
podman run --rm -it --tls-verify=false --pull=always \
  localhost:6443/packages/python-web:latest

# With Docker
docker run --rm -it --pull=always \
  localhost:6443/packages/python-web:latest

# With K8s
kubectl run myapp --insecure-skip-tls-verify \
  --image=<IP-ADDRESS>:6443/applications/myapp/web:latest --port=8080
```


## Configuration

Configure the registry using environment variables. See `.env.example` for all
available options:

```bash
# Logging
LOG_LEVEL=INFO              # DEBUG, INFO, WARNING, ERROR

# Server
FLASK_HOST=0.0.0.0         # Bind address
FLASK_PORT=6443            # Bind port

# Nix Build
GITHUB_REPO=github:imincik/flake-forge  # Nix flake repository
NIX_BUILD_TIMEOUT=600      # Build timeout in seconds

# Cache
CACHE_SIZE=50              # Number of manifests to cache

# Validation
MAX_IMAGE_NAME_LENGTH=255  # Max characters in image name
MAX_TAG_LENGTH=128         # Max characters in tag
```


## Image naming

The registry supports two image formats:

### 1. Nix Forge packages

Format: `packages/<package-name>`

```bash
# Pull a package image
podman pull localhost:6443/packages/python-web:latest

# Runs: nix build github:imincik/flake-forge#python-web.image
```

### 2. Nix Forge applications

Format: `applications/<package-name>/<image-name>`

```bash
# Pull specific image from an application (without .tar.gz extension)
podman pull localhost:6443/applications/myapp/web:latest
podman pull localhost:6443/applications/myapp/worker:latest

# Runs: nix build github:imincik/flake-forge#myapp.containers
# Serves: /nix/store/.../web.tar.gz
#         /nix/store/.../worker.tar.gz
# Note: Image name in URL doesn't include .tar.gz extension
```


## Features

- **OCI-compliant**: Implements OCI Distribution Specification v1.0
- **Docker compatible**: Supports Docker Registry v2 format via Accept headers
- **On-demand building**: Images are built using Nix when requested
- **Memory efficient**: Streams blobs without loading entire images into memory
- **Configurable**: All settings via environment variables
- **Input validation**: Prevents injection attacks
- **Real-time logging**: Debug mode streams nix build output line-by-line


## Manifest formats

The registry supports both OCI and Docker manifest formats:

- **OCI format** (default): `application/vnd.oci.image.manifest.v1+json`
- **Docker format**: `application/vnd.docker.distribution.manifest.v2+json`

The format is automatically selected based on the client's `Accept` header.
